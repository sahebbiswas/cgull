"""
Helpers for Memory Management Rules.
"""

import re
import logging
from typing import Dict, List, Optional, Set, Tuple

from ..base import BaseRule
from ..banned_functions import BannedFunctionsRule
from ...models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ...ast_analyzer import CASTContext, CFunction, get_type_byte_size, is_unsigned_type
from ...utils import extract_call_args, split_call_args, extract_balanced_parens
from ...cfg import StructuredCFG, CFGEvent, build_cfg, find_function_def, Nullness, Initialization, Allocation, analyze_function_summaries, FunctionSummary

logger = logging.getLogger(__name__)
def _brace_depths(body_lines: List[str]) -> List[int]:
    """
    Returns, for each line in `body_lines`, the net brace depth *after*
    that line relative to the start of the function body (depth 0). Used
    to bound forward-lookahead dataflow checks (use-after-free, unchecked
    allocation) to the enclosing block, instead of scanning arbitrarily
    far into unrelated code later in the same function.
    """
    depths = []
    depth = 0
    for line in body_lines:
        depth += line.count("{") - line.count("}")
        depths.append(depth)
    return depths



def _source_snippet(ast_ctx: CASTContext, line_no: int, fallback: str) -> str:
    if 1 <= line_no <= len(ast_ctx.source_lines):
        return ast_ctx.source_lines[line_no - 1].strip()
    return fallback


def _ast_cfg_for_function(
    ast_ctx: CASTContext,
    fn: CFunction,
    alloc_funcs: Optional[Set[str]] = None,
    dealloc_funcs: Optional[Set[str]] = None,
    realloc_funcs: Optional[Set[str]] = None,
    summaries: Optional[Dict[str, FunctionSummary]] = None,
):
    if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
        return None
    funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
    if funcdef is None:
        return None
    if summaries is None:
        summaries = analyze_function_summaries(ast_ctx, alloc_funcs=alloc_funcs, dealloc_funcs=dealloc_funcs, realloc_funcs=realloc_funcs)
    cfg = build_cfg(funcdef, alloc_funcs=alloc_funcs, dealloc_funcs=dealloc_funcs, realloc_funcs=realloc_funcs, summaries=summaries, line_map=getattr(ast_ctx, "line_map", None))
    initial_initialized = set(p.name for p in fn.parameters if p.name) | set(ast_ctx.global_variables.keys()) | {var.name for var in fn.variables.values() if getattr(var, "has_initializer", False) and var.name}
    cfg.analyze_dataflow(initial_nonnull=set(), initial_initialized=initial_initialized)
    return cfg


def _find_unsafe_allocation_use(cfg: StructuredCFG, alloc_node_id: int, ptr_name: str):
    """Return the first reachable unsafe use of ptr_name allocated at alloc_node_id, or None."""
    work = list(cfg.nodes[alloc_node_id].successors)
    visited = set()
    while work:
        nid = work.pop(0)
        if nid in visited:
            continue
        visited.add(nid)
        node = cfg.nodes[nid]

        if not node.kind.endswith('_cond'):
            if ptr_name in node.derefs or (ptr_name in node.reads and ptr_name not in node.freed and ptr_name not in node.asserted):
                if cfg.query_allocation(ptr_name, nid) in (Allocation.ALLOCATED, Allocation.MAYBE_ALLOCATED):
                    if cfg.query_nullness(ptr_name, nid) != Nullness.NON_NULL:
                        return node

        if ptr_name in node.writes:
            # Variable reassigned; ends scope of this allocation
            continue

        for succ in node.successors:
            if succ not in visited:
                work.append(succ)
    return None


def _find_unsafe_param_deref(cfg: StructuredCFG, param: str):
    """Return the first reachable unsafe dereference of parameter `param`, or None."""
    work = [cfg.entry] if cfg.entry is not None else []
    visited = set()
    while work:
        nid = work.pop(0)
        if nid in visited:
            continue
        visited.add(nid)
        node = cfg.nodes[nid]

        if param in node.derefs and cfg.query_nullness(param, nid) != Nullness.NON_NULL:
            return node

        if param in node.writes:
            # Parameter reassigned
            continue

        for succ in node.successors:
            if succ not in visited:
                work.append(succ)
    return None


def _find_uaf_uses(cfg: StructuredCFG, freed_node_id: int, ptr_name: str):
    """Yield (node, accessed_var) for reachable nodes where any pointer aliasing freed_node_id's freed object is accessed after free."""
    freed_locs = cfg.get_loc_map_at_node(freed_node_id).get(ptr_name, set())
    if not freed_locs:
        freed_locs = {f"var_{ptr_name}"}

    work = list(cfg.nodes[freed_node_id].successors)
    visited = set()
    while work:
        nid = work.pop(0)
        if nid in visited:
            continue
        visited.add(nid)
        node = cfg.nodes[nid]

        node_loc_map = cfg.get_loc_map_at_node(nid)
        accessed_vars = node.derefs | (node.reads - node.writes)
        for var in sorted(accessed_vars):
            var_locs = node_loc_map.get(var, {f"var_{var}"})
            if freed_locs & var_locs:
                alloc_state = cfg.query_allocation(var, nid)
                if alloc_state in (Allocation.FREED, Allocation.MAYBE_FREED):
                    if not node.kind.endswith('_cond'):
                        yield node, var

        for succ in node.successors:
            if succ not in visited:
                work.append(succ)




def _find_memory_leak_exits(
    ast_ctx: CASTContext,
    fn: CFunction,
    cfg: StructuredCFG,
    alloc_node_id: int,
    ptr_name: str,
    dealloc_funcs: Set[str],
) -> List[CFGEvent]:
    import collections
    alloc_node = cfg.nodes[alloc_node_id]
    queue = collections.deque([(succ, {alloc_node_id, succ}, {ptr_name}) for succ in alloc_node.successors])
    visited_states: Set[Tuple[int, Tuple[str, ...]]] = set()
    leak_nodes: List[CFGEvent] = []
    reported_node_ids: Set[int] = set()

    exit_call_names = {"exit", "_exit", "_Exit", "abort", "quick_exit", "fatal", "panic", "err", "errx"}

    while queue:
        curr_id, path_visited, aliases = queue.popleft()
        state_key = (curr_id, tuple(sorted(aliases)))
        if state_key in visited_states:
            continue
        visited_states.add(state_key)

        node = cfg.nodes[curr_id]

        # 1. Deallocation check
        if node.freed & aliases:
            continue
        if any(cfg.query_allocation(a, curr_id) == Allocation.FREED for a in aliases):
            continue

        # 2. Exit call check (program exit)
        if node.kind == "funccall":
            expr_lower = node.expr_str.lower()
            if any(re.search(rf'\b{re.escape(ef)}\b', expr_lower) for ef in exit_call_names):
                continue

        # 3. Ownership transfer check
        if node.kind in ("assignment", "decl"):
            if node.reads & aliases:
                is_direct_alias = False
                if node.expr_str:
                    m_alias = re.match(r'^\s*([a-zA-Z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?([a-zA-Z_]\w*)\s*;?$', node.expr_str)
                    if m_alias and m_alias.group(2) in aliases:
                        is_direct_alias = True
                    elif node.alias_writes:
                        for lhs_v, rhs_v in node.alias_writes.items():
                            if rhs_v in aliases:
                                is_direct_alias = True
                                break
                if is_direct_alias and node.writes:
                    written_var = next(iter(node.writes))
                    if written_var in fn.variables:
                        aliases = aliases | {written_var}

        # 4. Return statement check
        if node.kind == "return":
            if node.reads & aliases:
                continue
            is_null = any(cfg.query_nullness(a, curr_id) == Nullness.NULL or cfg.query_allocation(a, curr_id) == Allocation.NOT_ALLOCATED for a in aliases)
            if not is_null:
                if curr_id not in reported_node_ids:
                    reported_node_ids.add(curr_id)
                    leak_nodes.append(node)
            continue

        # 5. Overwrite check
        if curr_id == alloc_node_id:
            overwritten = []
        else:
            overwritten = [w for w in node.writes if w in aliases and not (node.reads & aliases)]
        if overwritten:
            remaining_aliases = aliases - set(overwritten)
            if not remaining_aliases:
                is_null = any(cfg.query_nullness(w, curr_id) == Nullness.NULL or cfg.query_allocation(w, curr_id) == Allocation.NOT_ALLOCATED for w in overwritten)
                if not is_null:
                    if curr_id not in reported_node_ids:
                        reported_node_ids.add(curr_id)
                        leak_nodes.append(node)
                continue
            else:
                aliases = remaining_aliases

        # 6. End of CFG check
        if not node.successors:
            is_null = any(cfg.query_nullness(a, curr_id) == Nullness.NULL or cfg.query_allocation(a, curr_id) == Allocation.NOT_ALLOCATED for a in aliases)
            if not is_null:
                if curr_id not in reported_node_ids:
                    reported_node_ids.add(curr_id)
                    leak_nodes.append(node)
            continue

        # 7. Propagate to successors
        for succ in node.successors:
            if succ not in path_visited:
                queue.append((succ, path_visited | {succ}, set(aliases)))

    return leak_nodes
