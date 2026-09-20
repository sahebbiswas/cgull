"""Structured CFG construction.

AST inspection and event-fact extraction live in :mod:`cgull.cfg.ast_events`;
this module owns only structured statement-to-graph construction and the
historic ``build_cfg`` entry point.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from ..ast_analyzer import _format_pycparser_expr
from .ast_events import (
    _call_events,
    _deref_vars,
    _deref_vars_with_lines,
    _event_payload,
    _find_ternary_op,
    _find_value_producing_call,
    _function_pointer_names,
    _guarded_expression_uses,
    _is_nullish,
    _replace_ast_node,
    _null_edge_facts,
)
from .dataflow import StructuredCFG
from .diagnostics import CFGDiagnostic
from .expression_effects import expression_read_write_sets
from .model import FunctionSummary


def build_cfg(
    funcdef,
    alloc_funcs: Optional[Set[str]] = None,
    dealloc_funcs: Optional[Set[str]] = None,
    realloc_funcs: Optional[Set[str]] = None,
    summaries: Optional[Dict[str, FunctionSummary]] = None,
    line_map: Optional[Dict[int, Any]] = None,
) -> StructuredCFG:
    """Build a structured CFG rooted at a pycparser FuncDef body."""
    from pycparser import c_ast

    cfg = StructuredCFG()
    function_pointers = _function_pointer_names(funcdef)
    labels_map: Dict[str, int] = {}
    pending_gotos: List[Tuple[int, str, Optional[int]]] = []

    def make_event(stmt) -> int:
        (
            kind,
            reads,
            writes,
            null_writes,
            maybe_null_writes,
            freed,
            allocated,
            derefs,
            deref_lines,
            asserted,
            alias_writes,
            realloc_inputs,
            realloc_bindings,
        ) = _event_payload(
            stmt,
            alloc_funcs=alloc_funcs,
            dealloc_funcs=dealloc_funcs,
            realloc_funcs=realloc_funcs,
            summaries=summaries,
            line_map=line_map,
        )
        # Read/write semantics are derived once from the AST expression shape.
        # Keep top-level call-event facts from _event_payload because that layer
        # intentionally handles deallocator and call-summary contracts specially;
        # nested calls remain part of the surrounding expression-effect walk.
        if kind != "FuncCall":
            reads, writes = expression_read_write_sets(stmt)
        node_kind = "allocation" if allocated else "free" if freed else kind.lower()
        if kind == "Return":
            expr_str = (
                _format_pycparser_expr(stmt.expr)
                if getattr(stmt, "expr", None) is not None
                else ""
            )
        else:
            expr_str = _format_pycparser_expr(stmt)
        return cfg.new_node(
            node_kind,
            stmt,
            line_map=line_map,
            expr_str=expr_str,
            reads=reads,
            writes=writes,
            null_writes=null_writes,
            maybe_null_writes=maybe_null_writes,
            freed=freed,
            allocated=allocated,
            derefs=derefs,
            deref_lines=deref_lines,
            asserted=asserted,
            alias_writes=alias_writes,
            realloc_inputs=realloc_inputs,
            realloc_bindings=realloc_bindings,
            calls=_call_events(stmt, line_map, function_pointers),
        )

    def build_compound(items, next_entry, break_target, continue_target):
        current = next_entry
        for item in reversed(items or []):
            current = build_stmt(item, current, break_target, continue_target)
        return current

    def build_case(case_node, next_entry, break_target, continue_target):
        return build_compound(
            case_node.stmts, next_entry, break_target, continue_target
        )

    def build_stmt(stmt, next_entry, break_target, continue_target):
        if stmt is None:
            return next_entry
        kind = type(stmt).__name__

        if kind == "If":
            ternary = _find_ternary_op(stmt.cond)
            if ternary is not None:
                coord = getattr(stmt, "coord", None)
                cond_t = _replace_ast_node(stmt.cond, ternary, ternary.iftrue)
                cond_f = _replace_ast_node(stmt.cond, ternary, ternary.iffalse)
                if_t = c_ast.If(
                    cond=cond_t,
                    iftrue=stmt.iftrue,
                    iffalse=stmt.iffalse,
                    coord=coord,
                )
                if_f = c_ast.If(
                    cond=cond_f,
                    iftrue=stmt.iftrue,
                    iffalse=stmt.iffalse,
                    coord=coord,
                )
                outer_if = c_ast.If(
                    cond=ternary.cond,
                    iftrue=if_t,
                    iffalse=if_f,
                    coord=coord,
                )
                return build_stmt(
                    outer_if, next_entry, break_target, continue_target
                )
        elif kind not in {
            "Compound",
            "While",
            "DoWhile",
            "For",
            "Switch",
            "Label",
            "Goto",
            "Break",
            "Continue",
        }:
            ternary = _find_ternary_op(stmt)
            if ternary is not None:
                coord = getattr(stmt, "coord", None)
                stmt_t = _replace_ast_node(stmt, ternary, ternary.iftrue)
                stmt_f = _replace_ast_node(stmt, ternary, ternary.iffalse)
                if_stmt = c_ast.If(
                    cond=ternary.cond,
                    iftrue=stmt_t,
                    iffalse=stmt_f,
                    coord=coord,
                )
                return build_stmt(if_stmt, next_entry, break_target, continue_target)

        if kind == "Compound":
            return build_compound(
                stmt.block_items, next_entry, break_target, continue_target
            )

        if kind in {
            "Decl",
            "Assignment",
            "FuncCall",
            "Return",
            "UnaryOp",
            "BinaryOp",
            "ExprList",
            "Cast",
            "ArrayRef",
            "StructRef",
        }:
            node = make_event(stmt)
            is_exit_call = False
            if kind == "FuncCall":
                callee_name = _format_pycparser_expr(getattr(stmt, "name", None))
                if callee_name in {
                    "exit",
                    "_exit",
                    "_Exit",
                    "abort",
                    "quick_exit",
                    "fatal",
                    "panic",
                    "err",
                    "errx",
                }:
                    is_exit_call = True
            if kind != "Return" and not is_exit_call:
                cfg.connect(node, next_entry)
            return node

        if kind == "If":
            cond_reads, cond_writes = expression_read_write_sets(stmt.cond)
            cond = cfg.new_node(
                "if_cond",
                stmt,
                line_map=line_map,
                expr_str=_format_pycparser_expr(stmt.cond),
                reads=cond_reads,
                writes=cond_writes,
                calls=_call_events(stmt.cond, line_map, function_pointers),
            )
            true_nn, true_null, false_nn, false_null = _null_edge_facts(
                stmt.cond, summaries
            )
            cfg.connect(
                cond,
                build_stmt(
                    stmt.iftrue, next_entry, break_target, continue_target
                ),
                truth=True,
                add=true_nn,
                remove={*true_null},
            )
            if stmt.iffalse is not None:
                cfg.connect(
                    cond,
                    build_stmt(
                        stmt.iffalse,
                        next_entry,
                        break_target,
                        continue_target,
                    ),
                    truth=False,
                    add=false_nn,
                    remove={*false_null},
                )
            else:
                cfg.connect(
                    cond,
                    next_entry,
                    truth=False,
                    add=false_nn,
                    remove={*false_null},
                )
            return cond

        if kind in {"While", "DoWhile"}:
            cond_reads, cond_writes = expression_read_write_sets(stmt.cond)
            if kind == "While":
                cond = cfg.new_node(
                    "while_cond",
                    stmt,
                    line_map=line_map,
                    expr_str=_format_pycparser_expr(stmt.cond),
                    reads=cond_reads,
                    writes=cond_writes,
                    calls=_call_events(stmt.cond, line_map, function_pointers),
                )
                body = build_stmt(stmt.stmt, cond, next_entry, cond)
                true_nn, true_null, false_nn, false_null = _null_edge_facts(
                    stmt.cond, summaries
                )
                cfg.connect(cond, body, add=true_nn, remove=true_null, truth=True)
                cfg.connect(
                    cond, next_entry, add=false_nn, remove=false_null, truth=False
                )
                return cond
            cond = cfg.new_node(
                "do_cond",
                stmt,
                line_map=line_map,
                expr_str=_format_pycparser_expr(stmt.cond),
                reads=cond_reads,
                writes=cond_writes,
                calls=_call_events(stmt.cond, line_map, function_pointers),
            )
            body = build_stmt(stmt.stmt, cond, next_entry, cond)
            true_nn, true_null, false_nn, false_null = _null_edge_facts(
                stmt.cond, summaries
            )
            cfg.connect(cond, body, add=true_nn, remove=true_null, truth=True)
            cfg.connect(cond, next_entry, add=false_nn, remove=false_null, truth=False)
            return body

        if kind == "For":
            cond_expr = stmt.cond
            cond_reads, cond_writes = expression_read_write_sets(cond_expr)
            cond = cfg.new_node(
                "for_cond",
                stmt,
                line_map=line_map,
                expr_str=(
                    _format_pycparser_expr(cond_expr) if cond_expr else "1"
                ),
                reads=cond_reads,
                writes=cond_writes,
                calls=_call_events(cond_expr, line_map, function_pointers),
            )
            iter_node = None
            if stmt.next is not None:
                iter_node = make_event(stmt.next)
                cfg.connect(iter_node, cond)
            body = build_stmt(
                stmt.stmt, iter_node or cond, next_entry, iter_node or cond
            )
            true_nn, true_null, false_nn, false_null = _null_edge_facts(
                cond_expr, summaries
            )
            cfg.connect(cond, body, add=true_nn, remove=true_null, truth=True)
            cfg.connect(cond, next_entry, add=false_nn, remove=false_null, truth=False)
            if stmt.init is not None:
                init_node = make_event(stmt.init)
                cfg.connect(init_node, cond)
                return init_node
            return cond

        if kind == "Switch":
            cond_reads, cond_writes = expression_read_write_sets(stmt.cond)
            switch_node = cfg.new_node(
                "switch_cond",
                stmt,
                line_map=line_map,
                expr_str=_format_pycparser_expr(stmt.cond),
                reads=cond_reads,
                writes=cond_writes,
                calls=_call_events(stmt.cond, line_map, function_pointers),
            )
            body = stmt.stmt
            cases = (
                list(getattr(body, "block_items", []) or [])
                if type(body).__name__ == "Compound"
                else []
            )
            case_entries = [None] * len(cases)
            fallthrough = next_entry
            for i in range(len(cases) - 1, -1, -1):
                case = cases[i]
                if type(case).__name__ not in {"Case", "Default"}:
                    continue
                case_entries[i] = build_case(
                    case, fallthrough, next_entry, continue_target
                )
                fallthrough = case_entries[i]
            for entry in case_entries:
                if entry is not None:
                    cfg.connect(switch_node, entry)
            if not any(type(c).__name__ == "Default" for c in cases):
                cfg.connect(switch_node, next_entry)
            return switch_node

        if kind == "Break":
            node = make_event(stmt)
            cfg.connect(node, break_target)
            return node

        if kind == "Continue":
            node = make_event(stmt)
            cfg.connect(node, continue_target)
            return node

        if kind == "Label":
            label_node = cfg.new_node(
                "label", stmt, line_map=line_map, expr_str=stmt.name
            )
            labels_map[stmt.name] = label_node
            inner_entry = build_stmt(
                stmt.stmt, next_entry, break_target, continue_target
            )
            cfg.connect(label_node, inner_entry)
            return label_node

        if kind == "Goto":
            goto_node = cfg.new_node(
                "goto",
                stmt,
                line_map=line_map,
                expr_str=f"goto {stmt.name}",
            )
            pending_gotos.append((goto_node, stmt.name, next_entry))
            return goto_node

        node = make_event(stmt)
        cfg.connect(node, next_entry)
        return node

    cfg.entry = build_stmt(funcdef.body, None, None, None)

    for goto_node, label_name, resume_entry in pending_gotos:
        if label_name in labels_map:
            cfg.connect(goto_node, labels_map[label_name])
            continue

        goto_event = cfg.nodes[goto_node]
        unknown_node = cfg.new_node(
            "unknown_control_flow",
            getattr(goto_event, "_ast_node", None),
            line_map=line_map,
            expr_str=f"unresolved goto {label_name}",
        )
        unknown_event = cfg.nodes[unknown_node]
        setattr(unknown_event, "is_unknown_control_flow", True)
        setattr(unknown_event, "unresolved_target", label_name)
        cfg.connect(goto_node, unknown_node)
        cfg.diagnostics.append(
            CFGDiagnostic(
                code="CFG_UNRESOLVED_GOTO",
                message=f"Unresolved goto target '{label_name}'; control flow is conservative",
                source_location=goto_event.source_location,
                target=label_name,
            )
        )

        # The actual label target is unknown, but analysis must not terminate at
        # the unresolved jump. Route through the explicit unknown-control-flow
        # event to the structured continuation boundary captured at construction
        # time. This keeps the uncertainty forward-scoped without inventing a
        # concrete label target or creating an O(N) wildcard fan-out.
        cfg.connect(unknown_node, resume_entry)

    cfg.build_basic_blocks()
    return cfg


def find_function_def(ast, name: str):
    for ext in getattr(ast, "ext", []) or []:
        if (
            type(ext).__name__ == "FuncDef"
            and getattr(ext.decl, "name", None) == name
        ):
            return ext
    return None


# Preserve the original constructors as explicit uncached escape hatches. The
# public names below are rebound to session/cache-aware wrappers so existing
# callers automatically reuse topology without inheriting mutable data-flow state.
build_cfg_uncached = build_cfg
find_function_def_uncached = find_function_def

from copy import copy
from threading import RLock
from weakref import WeakKeyDictionary


_CACHE_LOCK = RLock()
_FUNCTION_DEF_INDEX_CACHE = WeakKeyDictionary()
_STRUCTURAL_CFG_CACHE = WeakKeyDictionary()


def build_function_def_index(ast) -> Dict[str, Any]:
    """Return a one-pass function-definition index for a pycparser AST."""
    if ast is None:
        return {}
    with _CACHE_LOCK:
        try:
            cached = _FUNCTION_DEF_INDEX_CACHE.get(ast)
        except TypeError:
            cached = None
        if cached is not None:
            return cached
        index: Dict[str, Any] = {}
        for ext in getattr(ast, "ext", []) or []:
            if type(ext).__name__ != "FuncDef":
                continue
            name = getattr(getattr(ext, "decl", None), "name", None)
            if name and name not in index:
                index[name] = ext
        try:
            _FUNCTION_DEF_INDEX_CACHE[ast] = index
        except TypeError:
            pass
        return index


def find_function_def(ast, name: str):
    """Look up a function definition in O(1) after one AST indexing pass."""
    return build_function_def_index(ast).get(name)


def clone_structural_cfg(cfg: StructuredCFG) -> StructuredCFG:
    """Clone graph/event topology while discarding mutable analysis results."""
    clone = type(cfg)()
    clone.entry = cfg.entry
    clone._next_id = cfg._next_id
    clone.edge_truth = dict(cfg.edge_truth)
    clone.edge_facts = {
        edge: (set(add), set(remove))
        for edge, (add, remove) in cfg.edge_facts.items()
    }
    clone.diagnostics = list(cfg.diagnostics)

    for node_id, node in cfg.nodes.items():
        event = copy(node)
        event.reads = set(node.reads)
        event.writes = set(node.writes)
        event.null_writes = set(node.null_writes)
        event.maybe_null_writes = set(node.maybe_null_writes)
        event.freed = set(node.freed)
        event.allocated = set(node.allocated)
        event.derefs = set(node.derefs)
        event.deref_lines = dict(node.deref_lines)
        event.asserted = set(node.asserted)
        event.alias_writes = dict(node.alias_writes)
        event.realloc_inputs = set(node.realloc_inputs)
        event.realloc_bindings = dict(node.realloc_bindings)
        event.calls = tuple(node.calls)
        event.successors = list(node.successors)
        clone.nodes[node_id] = event

    clone.build_basic_blocks()
    return clone


def _cached_structural_cfg(funcdef, line_map=None) -> StructuredCFG:
    """Return the private immutable-by-convention structural base for a FuncDef."""
    with _CACHE_LOCK:
        try:
            by_line_map = _STRUCTURAL_CFG_CACHE.get(funcdef)
        except TypeError:
            by_line_map = None
        key = id(line_map)
        if by_line_map is not None:
            cached = by_line_map.get(key)
            if cached is not None and cached[0] is line_map:
                return cached[1]

        cfg = build_cfg_uncached(funcdef, line_map=line_map)
        if by_line_map is None:
            by_line_map = {}
        by_line_map[key] = (line_map, cfg)
        try:
            _STRUCTURAL_CFG_CACHE[funcdef] = by_line_map
        except TypeError:
            pass
        return cfg


def clone_cached_structural_cfg(funcdef, line_map=None) -> StructuredCFG:
    """Return a fresh mutable view of the cached AST-to-CFG topology."""
    return clone_structural_cfg(_cached_structural_cfg(funcdef, line_map=line_map))


_CONDITION_OR_STRUCTURAL_KINDS = {
    "if_cond",
    "while_cond",
    "do_cond",
    "for_cond",
    "switch_cond",
    "label",
    "goto",
    "unknown_control_flow",
}


def _refresh_condition_null_edge_facts(
    cfg: StructuredCFG,
    summaries: Optional[Dict[str, FunctionSummary]],
) -> None:
    """Recompute condition-edge null facts once callee summaries are known.

    Structural CFG caching builds topology without summaries, so Is*-style
    ``truthy_implies_nonnull`` proofs are applied here rather than at first
    construction. Compound ``&&`` / ``||`` / ``!`` facts are refreshed too so a
    later summary-aware pass cannot leave stale empty edges.
    """
    if not summaries:
        return
    for event in cfg.nodes.values():
        if event.kind not in {"if_cond", "while_cond", "do_cond", "for_cond"}:
            continue
        ast_node = getattr(event, "_ast_node", None)
        if ast_node is None:
            continue
        cond = getattr(ast_node, "cond", None)
        true_nn, true_null, false_nn, false_null = _null_edge_facts(cond, summaries)
        for succ in event.successors:
            edge = (event.node_id, succ)
            truth = cfg.edge_truth.get(edge)
            if truth is True:
                cfg.edge_facts[edge] = (set(true_nn), set(true_null))
            elif truth is False:
                cfg.edge_facts[edge] = (set(false_nn), set(false_null))
            else:
                # Coalesced true/false edges do not establish either predicate.
                cfg.edge_facts[edge] = (set(), set())

    for block in cfg.blocks.values():
        if not block.nodes:
            continue
        last = block.nodes[-1]
        refreshed: Dict[int, Tuple[Set[str], Set[str]]] = {}
        for succ_block_id in block.successors:
            succ_block = cfg.blocks.get(succ_block_id)
            if succ_block is None or not succ_block.nodes:
                continue
            edge_fact = cfg.edge_facts.get((last.node_id, succ_block.nodes[0].node_id))
            if edge_fact:
                refreshed[succ_block_id] = (set(edge_fact[0]), set(edge_fact[1]))
        block.edge_facts = refreshed


def apply_cfg_event_semantics(
    cfg: StructuredCFG,
    *,
    alloc_funcs: Optional[Set[str]] = None,
    dealloc_funcs: Optional[Set[str]] = None,
    realloc_funcs: Optional[Set[str]] = None,
    summaries: Optional[Dict[str, FunctionSummary]] = None,
    line_map: Optional[Dict[int, Any]] = None,
) -> StructuredCFG:
    """Recompute analysis-specific event facts without rebuilding graph topology."""
    _refresh_condition_null_edge_facts(cfg, summaries)
    for event in cfg.nodes.values():
        if event.kind in _CONDITION_OR_STRUCTURAL_KINDS:
            continue
        ast_node = getattr(event, "_ast_node", None)
        if ast_node is None:
            continue
        (
            kind,
            reads,
            writes,
            null_writes,
            maybe_null_writes,
            freed,
            allocated,
            derefs,
            deref_lines,
            asserted,
            alias_writes,
            realloc_inputs,
            realloc_bindings,
        ) = _event_payload(
            ast_node,
            alloc_funcs=alloc_funcs,
            dealloc_funcs=dealloc_funcs,
            realloc_funcs=realloc_funcs,
            summaries=summaries,
            line_map=line_map,
        )
        if kind != "FuncCall":
            reads, writes = expression_read_write_sets(ast_node)
        event.kind = "allocation" if allocated else "free" if freed else kind.lower()
        event.reads = set(reads)
        event.writes = set(writes)
        event.null_writes = set(null_writes)
        event.maybe_null_writes = set(maybe_null_writes)
        event.freed = set(freed)
        event.allocated = set(allocated)
        event.derefs = set(derefs)
        event.deref_lines = dict(deref_lines)
        event.asserted = set(asserted)
        event.alias_writes = dict(alias_writes)
        event.realloc_inputs = set(realloc_inputs)
        event.realloc_bindings = dict(realloc_bindings)
    return cfg


def build_cfg(
    funcdef,
    alloc_funcs: Optional[Set[str]] = None,
    dealloc_funcs: Optional[Set[str]] = None,
    realloc_funcs: Optional[Set[str]] = None,
    summaries: Optional[Dict[str, FunctionSummary]] = None,
    line_map: Optional[Dict[int, Any]] = None,
) -> StructuredCFG:
    """Return an isolated CFG view backed by cached structural topology."""
    try:
        from ..analysis_session import _analysis_session_for_funcdef

        session = _analysis_session_for_funcdef(funcdef)
    except ImportError:
        session = None

    if session is not None and line_map is getattr(session.ast_context, "line_map", None):
        cfg = session._analysis_cfg_for_funcdef(
            funcdef,
            alloc_funcs=alloc_funcs,
            dealloc_funcs=dealloc_funcs,
            realloc_funcs=realloc_funcs,
            summaries=summaries,
        )
        if cfg is not None:
            return cfg

    cfg = clone_cached_structural_cfg(funcdef, line_map=line_map)
    if any(
        value is not None
        for value in (alloc_funcs, dealloc_funcs, realloc_funcs, summaries)
    ):
        apply_cfg_event_semantics(
            cfg,
            alloc_funcs=alloc_funcs,
            dealloc_funcs=dealloc_funcs,
            realloc_funcs=realloc_funcs,
            summaries=summaries,
            line_map=line_map,
        )
    return cfg


__all__ = [
    "apply_cfg_event_semantics",
    "build_cfg",
    "build_cfg_uncached",
    "build_function_def_index",
    "clone_cached_structural_cfg",
    "clone_structural_cfg",
    "find_function_def",
    "find_function_def_uncached",
]
