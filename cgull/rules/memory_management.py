"""
Rules for Memory Allocation, Null-checks, Lifecycles, and Pointer Safety.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from .base import BaseRule
from .banned_functions import BannedFunctionsRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ..ast_analyzer import CASTContext, CFunction, get_type_byte_size
import logging
from ..cfg import StructuredCFG, CFGEvent, build_cfg, find_function_def, Nullness, Initialization, Allocation, analyze_function_summaries, FunctionSummary

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


class UncheckedDynamicAllocationsRule(BaseRule):
    rule_id = "CGULL-003"
    name = "Unchecked Dynamic Allocations"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Ensure return value of memory allocation (malloc, calloc, realloc, aligned_alloc) is checked for NULL before use."
    implementation_method = "AST parsing / CFG dataflow to verify conditional NULL checks"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-476 / CWE-252"
    remediation_suggestion = "Immediately check allocated pointer against NULL before dereference: if (ptr == NULL) { /* error handling / return */ }"
    sample_vulnerable_code = "char *buf = (char *)malloc(1024);\nbuf[0] = 'A'; // Potential NULL pointer dereference"
    sample_remediated_code = "char *buf = (char *)malloc(1024);\nif (buf == NULL) {\n    return -ENOMEM;\n}\nbuf[0] = 'A';"
    analysis_engine = AnalysisEngine.HYBRID

    DEFAULT_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "aligned_alloc"}
    DEFAULT_REALLOC_FUNCS = {"realloc"}
    DEFAULT_DEALLOC_FUNCS = {"free", "cfree", "vfree"}

    def __init__(
        self,
        extra_alloc_funcs: Optional[List[str]] = None,
        extra_realloc_funcs: Optional[List[str]] = None,
        extra_dealloc_funcs: Optional[List[str]] = None,
    ):
        super().__init__()
        self.alloc_funcs: Set[str] = set(self.DEFAULT_ALLOC_FUNCS)
        self.realloc_funcs: Set[str] = set(self.DEFAULT_REALLOC_FUNCS)
        self.dealloc_funcs: Set[str] = set(self.DEFAULT_DEALLOC_FUNCS)
        if extra_alloc_funcs:
            self.add_extra_alloc_funcs(extra_alloc_funcs)
        if extra_realloc_funcs:
            self.add_extra_realloc_funcs(extra_realloc_funcs)
        if extra_dealloc_funcs:
            self.add_extra_dealloc_funcs(extra_dealloc_funcs)

    def add_extra_alloc_funcs(self, extra_allocs: List[str]) -> None:
        self.alloc_funcs.update(extra_allocs)

    def add_extra_realloc_funcs(self, extra_reallocs: List[str]) -> None:
        self.realloc_funcs.update(extra_reallocs)
        self.alloc_funcs.update(extra_reallocs)

    def add_extra_dealloc_funcs(self, extra_deallocs: List[str]) -> None:
        self.dealloc_funcs.update(extra_deallocs)

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        alloc_pattern = "|".join(re.escape(f) for f in sorted(self.alloc_funcs, key=len, reverse=True))
        summaries = analyze_function_summaries(ast_ctx, alloc_funcs=self.alloc_funcs, dealloc_funcs=self.dealloc_funcs)
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, alloc_funcs=self.alloc_funcs, dealloc_funcs=self.dealloc_funcs, summaries=summaries)
            if cfg is not None:
                for node in cfg.nodes.values():
                    if not node.allocated:
                        continue
                    for ptr_name in node.allocated:
                        unsafe = _find_unsafe_allocation_use(cfg, node.node_id, ptr_name)
                        if unsafe is None:
                            continue
                        line_no = node.line_number
                        snippet = _source_snippet(ast_ctx, line_no, node.expr_str)
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Return value of dynamic memory allocation for '{ptr_name}' is not checked for NULL before use.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({ptr_name} == NULL) {{\n    return -1; // Handle out-of-memory\n}}"
                        ))
                continue

            # Parser unavailable: retain the existing lexical fallback.
            body_lines = fn.body.splitlines()
            depths = _brace_depths(body_lines)
            alloc_regex = re.compile(rf'\b(\w+)\s*=\s*(?:\([^\)]+\)\s*)?(?:{alloc_pattern})\s*\(')
            for i, line in enumerate(body_lines):
                line_no = fn.start_line + 1 + i
                m = alloc_regex.search(line)
                if not m:
                    continue
                ptr_name = m.group(1)
                base_depth = depths[i]
                has_check = False
                for j in range(i + 1, min(i + 8, len(body_lines))):
                    if depths[j] < base_depth:
                        break
                    sub_line = body_lines[j]
                    if re.search(rf'\bif\s*\([^)]*?\b{re.escape(ptr_name)}\s*(?:==\s*NULL|!=\s*NULL|==\s*0|!=\s*0)\b', sub_line) or \
                       re.search(rf'\bif\s*\(\s*!{re.escape(ptr_name)}\b', sub_line) or \
                       re.search(rf'\bassert\s*\([^)]*?\b{re.escape(ptr_name)}\b', sub_line):
                        has_check = True
                        break
                if not has_check:
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=line,
                        message=f"Return value of dynamic memory allocation for '{ptr_name}' is not checked for NULL before use.",
                        column_number=m.start() + 1,
                        engine="AST",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=f"if ({ptr_name} == NULL) {{\n    return -1; // Handle out-of-memory\n}}"
                    ))
        return issues


class MissingNullCheckOnFunctionParametersRule(BaseRule):
    rule_id = "CGULL-004"
    name = "Missing Null Check on Function Parameters"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Ensure pointer arguments and local pointers are checked against NULL before being dereferenced inside function body."
    implementation_method = "AST parsing & CFG dataflow to track NULL pointer dereferences and unchecked parameters"
    implementation_complexity = "Medium"
    chances_of_false_positives = "High"
    cwe_id = "CWE-476"
    remediation_suggestion = "Add a guard clause before pointer dereference: if (param == NULL) { return ERROR_CODE; }"
    sample_vulnerable_code = "int process_data(int *data, char *tag) {\n    *data = 100; // Dereferenced without NULL check\n    return 0;\n}"
    sample_remediated_code = "int process_data(int *data, char *tag) {\n    if (data == NULL || tag == NULL) return -EINVAL;\n    *data = 100;\n    return 0;\n}"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        summaries = analyze_function_summaries(ast_ctx)
        for fn in ast_ctx.functions:
            ptr_params = [p for p in fn.parameters if p.is_pointer and p.name]
            cfg = _ast_cfg_for_function(ast_ctx, fn, summaries=summaries)

            if cfg is not None:
                reported_nodes = set()
                # 1. Direct NULL pointer dereferences (known to be NULL)
                sorted_nodes = sorted(cfg.nodes.values(), key=lambda n: n.node_id)
                for node in sorted_nodes:
                    if not node.derefs:
                        continue
                    for deref_var in sorted(node.derefs):
                        null_status = cfg.query_nullness(deref_var, node.node_id)
                        if null_status == Nullness.NULL:
                            deref_line = node.get_deref_line(deref_var)
                            key = (deref_line, deref_var, "null_deref")
                            if key not in reported_nodes:
                                reported_nodes.add(key)
                                snippet = _source_snippet(ast_ctx, deref_line, node.expr_str)
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=deref_line,
                                    code_snippet=snippet,
                                    message=f"Null pointer dereference: pointer '{deref_var}' is known to be NULL when dereferenced.",
                                    column_number=1,
                                    engine="AST",
                                    fix_type=FixType.SUGGESTED_FIX,
                                    suggested_fix_replacement=f"if ({deref_var} == NULL) return -1;"
                                ))

                # 2. Pointer parameters dereferenced without a preceding NULL check
                for param in ptr_params:
                    unsafe = _find_unsafe_param_deref(cfg, param.name)
                    if unsafe is None:
                        continue
                    null_status = cfg.query_nullness(param.name, unsafe.node_id)
                    if null_status == Nullness.NULL:
                        continue  # Already reported above under direct NULL dereference
                    deref_line = unsafe.get_deref_line(param.name)
                    key = (deref_line, param.name, "param_missing_check")
                    if key not in reported_nodes:
                        reported_nodes.add(key)
                        snippet = _source_snippet(ast_ctx, deref_line, unsafe.expr_str)
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=deref_line,
                            code_snippet=snippet,
                            message=f"Pointer parameter '{param.name}' in function '{fn.name}' is dereferenced without a preceding NULL check.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({param.name} == NULL) return -EINVAL;"
                        ))
                continue

            # Parser unavailable: preserve and extend lexical fallback.
            body_lines = fn.body.splitlines()
            body_start = getattr(fn, "body_start_line", fn.start_line + 1)
            depths = _brace_depths(body_lines)

            # 1. Parameter missing check fallback
            for param in ptr_params:
                p_name = param.name
                checked = any(
                    re.search(rf'\bif\s*\([^)]*?\b{re.escape(p_name)}\s*(?:==\s*NULL|!=\s*NULL|==\s*0|!=\s*0)\b', line) or
                    re.search(rf'\bif\s*\(\s*!{re.escape(p_name)}\b', line) or
                    re.search(rf'\bassert\s*\([^)]*?\b{re.escape(p_name)}\b', line)
                    for line in body_lines[:min(6, len(body_lines))]
                )
                if checked:
                    continue
                for i, line in enumerate(body_lines):
                    line_no = body_start + i
                    deref_match = re.search(rf'(?:\*\s*{re.escape(p_name)}\b|{re.escape(p_name)}\s*->|{re.escape(p_name)}\s*\[)', line)
                    if deref_match:
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=line,
                            message=f"Pointer parameter '{p_name}' in function '{fn.name}' is dereferenced without a preceding NULL check.",
                            column_number=deref_match.start() + 1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({p_name} == NULL) return -EINVAL;"
                        ))
                        break

            # 2. Local NULL assignment dereference fallback
            null_assign_regex = re.compile(r'(?<![\*->\.\w])\b([a-zA-Z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?(?:NULL|nullptr|0|0x0)\b')
            for i, line in enumerate(body_lines):
                m = null_assign_regex.search(line)
                if not m:
                    continue
                v_name = m.group(1)
                base_depth = depths[i]
                for j in range(i + 1, len(body_lines)):
                    if depths[j] < base_depth:
                        break
                    sub_line = body_lines[j]
                    sub_line_no = body_start + j
                    if re.search(rf'(?<![\*->\.\w])\b{re.escape(v_name)}\s*=', sub_line):
                        break
                    deref_match = re.search(rf'(?:\*\s*{re.escape(v_name)}\b|{re.escape(v_name)}\s*->|{re.escape(v_name)}\s*\[)', sub_line)
                    if deref_match:
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=sub_line_no,
                            code_snippet=sub_line,
                            message=f"Null pointer dereference: pointer '{v_name}' is known to be NULL when dereferenced.",
                            column_number=deref_match.start() + 1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({v_name} == NULL) return -1;"
                        ))
                        break

            # 3. Inverted condition `if (v == NULL)` or `if (!v)` dereference fallback
            inverted_check_regex = re.compile(r'\bif\s*\(\s*(?:([a-zA-Z_]\w*)\s*==\s*(?:NULL|nullptr|0|0x0)|!([a-zA-Z_]\w*))\s*\)')
            for i, line in enumerate(body_lines):
                m = inverted_check_regex.search(line)
                if not m:
                    continue
                v_name = m.group(1) or m.group(2)
                target_depth = depths[i] - 1 if '{' in line else depths[i]
                for j in range(i + 1, len(body_lines)):
                    if j > i + 1 and depths[j] <= target_depth:
                        break
                    sub_line = body_lines[j]
                    sub_line_no = body_start + j
                    if re.search(rf'(?<![\*->\.\w])\b{re.escape(v_name)}\s*=', sub_line):
                        break
                    deref_match = re.search(rf'(?:\*\s*{re.escape(v_name)}\b|{re.escape(v_name)}\s*->|{re.escape(v_name)}\s*\[)', sub_line)
                    if deref_match:
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=sub_line_no,
                            code_snippet=sub_line,
                            message=f"Null pointer dereference: pointer '{v_name}' is known to be NULL when dereferenced.",
                            column_number=deref_match.start() + 1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({v_name} == NULL) return -1;"
                        ))
                        break

        return issues


class UninitializedPointersRule(BaseRule):
    rule_id = "CGULL-021"
    name = "Uninitialized Pointers"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Ensure pointer variables are explicitly initialized to NULL or a valid address upon declaration."
    implementation_method = "AST parsing to check pointer initialization"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-457"
    remediation_suggestion = "Initialize all pointer variables explicitly at declaration: type *ptr = NULL;"
    sample_vulnerable_code = "char *secret_key;\nif (condition) {\n    secret_key = fetch_key();\n}\nuse_key(secret_key); // May hold wild stack garbage"
    sample_remediated_code = "char *secret_key = NULL;\nif (condition) {\n    secret_key = fetch_key();\n}\nif (secret_key) use_key(secret_key);"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        summaries = analyze_function_summaries(ast_ctx)
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, summaries=summaries)
            if cfg is not None:
                uninit_ptrs = [v_name for v_name, var in fn.variables.items() if var.is_pointer and not var.has_initializer]
                if not uninit_ptrs:
                    continue
                reported = set()
                for node in cfg.nodes.values():
                    for ptr in uninit_ptrs:
                        if ptr in reported:
                            continue
                        if ptr in node.writes:
                            continue
                        if ptr in node.reads or ptr in node.derefs:
                            if cfg.query_initialization(ptr, node.node_id) in (Initialization.UNINITIALIZED, Initialization.MAYBE_INITIALIZED):
                                decl_line = fn.variables[ptr].declaration_line
                                snippet = _source_snippet(ast_ctx, decl_line, f"char *{ptr};")
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=decl_line,
                                    code_snippet=snippet,
                                    message=f"Pointer variable '{ptr}' is declared uninitialized (wild pointer risk). Initialize to NULL.",
                                    column_number=1,
                                    engine="AST",
                                    fix_type=FixType.SAFE_FIX,
                                    auto_fix_replacement=snippet.replace(f"{ptr};", f"{ptr} = NULL;")
                                ))
                                reported.add(ptr)
                continue
        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Match pointer declaration without = : e.g. int *p; or char* ptr, *buf;
        m = re.search(r'^[ \t]*(?:static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*+\s*|\w+\s*\*+)(\w+)\s*;', line_content)
        if m:
            v_name = m.group(1)
            if v_name not in ('return', 'break', 'continue'):
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Pointer variable '{v_name}' is declared uninitialized (wild pointer risk). Initialize to NULL.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SAFE_FIX,
                    auto_fix_replacement=line_content.replace(f"{v_name};", f"{v_name} = NULL;")
                ))
        return issues


class DoubleFreeRule(BaseRule):
    rule_id = "CGULL-027"
    name = "Double Free"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect calling free() on a pointer that has already been freed."
    implementation_method = "AST dataflow analysis tracking allocation lifecycle across control flow joins (ALLOCATED, MAYBE_ALLOCATED, FREED, MAYBE_FREED)"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-415"
    remediation_suggestion = "Ensure a pointer is freed only once. Set freed pointers to NULL immediately after free()."
    sample_vulnerable_code = "free(ptr);\nfree(ptr); // Double-Free"
    sample_remediated_code = "free(ptr);\nptr = NULL;\nfree(ptr); // Safe: free(NULL) is a no-op"
    analysis_engine = AnalysisEngine.AST

    DEFAULT_DEALLOC_FUNCS = {"free", "cfree", "vfree"}
    MAX_LOOKAHEAD_LINES = 200

    def __init__(self, extra_dealloc_funcs: Optional[List[str]] = None):
        super().__init__()
        self.dealloc_funcs: Set[str] = set(self.DEFAULT_DEALLOC_FUNCS)
        if extra_dealloc_funcs:
            self.add_extra_dealloc_funcs(extra_dealloc_funcs)

    def add_extra_dealloc_funcs(self, extra_deallocs: List[str]) -> None:
        self.dealloc_funcs.update(extra_deallocs)

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        dealloc_pattern = "|".join(re.escape(f) for f in sorted(self.dealloc_funcs, key=len, reverse=True))
        summaries = analyze_function_summaries(ast_ctx, dealloc_funcs=self.dealloc_funcs)
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, dealloc_funcs=self.dealloc_funcs, summaries=summaries)
            if cfg is not None:
                for node in cfg.nodes.values():
                    for freed_ptr in node.freed:
                        # Check if ptr was already freed prior to this node
                        alloc_status = cfg.query_allocation(freed_ptr, node.node_id)
                        if alloc_status in (Allocation.FREED, Allocation.MAYBE_FREED):
                            snippet = _source_snippet(ast_ctx, node.line_number, node.expr_str)
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=node.line_number,
                                code_snippet=snippet,
                                message=f"Potential Double Free: pointer '{freed_ptr}' is freed here but was already freed.",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.MANUAL_REVIEW,
                            ))
                continue

            body_lines = fn.body.splitlines()
            depths = _brace_depths(body_lines)
            for i, line in enumerate(body_lines):
                line_no = fn.start_line + 1 + i
                free_match = re.search(rf'\b(?:{dealloc_pattern})\s*\(\s*(\w+)\s*\)', line)
                if not free_match:
                    continue
                freed_ptr = free_match.group(1)
                base_depth = depths[i]
                limit = min(i + 1 + self.MAX_LOOKAHEAD_LINES, len(body_lines))
                for j in range(i + 1, limit):
                    if depths[j] < base_depth:
                        break
                    next_line = body_lines[j]
                    next_line_no = fn.start_line + 1 + j
                    # If reassigned to NULL or another value, break
                    if re.search(rf'\b{re.escape(freed_ptr)}\s*=', next_line):
                        break
                    if re.search(rf'\b(?:free|cfree|vfree)\s*\(\s*{re.escape(freed_ptr)}\s*\)', next_line):
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=next_line_no,
                            code_snippet=next_line,
                            message=f"Potential Double Free: pointer '{freed_ptr}' was already freed at line {line_no}.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.MANUAL_REVIEW,
                        ))
                        break
        return issues


class UseAfterFreeRule(BaseRule):
    rule_id = "CGULL-022"
    name = "Use-After-Free"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect dereferencing or reusing a pointer after the memory it points to has been released with free()."
    implementation_method = "AST dataflow analysis tracking allocation lifecycle across control flow joins (ALLOCATED, MAYBE_ALLOCATED, FREED, MAYBE_FREED)"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-416"
    remediation_suggestion = "Immediately set freed pointer to NULL (free(ptr); ptr = NULL;) and do not access freed memory."
    sample_vulnerable_code = "free(session);\nprintf(\"Session ID: %d\", session->id); // Use-After-Free"
    sample_remediated_code = "free(session);\nsession = NULL;"
    analysis_engine = AnalysisEngine.AST

    DEFAULT_DEALLOC_FUNCS = {"free", "cfree", "vfree"}
    MAX_LOOKAHEAD_LINES = 200

    def __init__(self, extra_dealloc_funcs: Optional[List[str]] = None):
        super().__init__()
        self.dealloc_funcs: Set[str] = set(self.DEFAULT_DEALLOC_FUNCS)
        if extra_dealloc_funcs:
            self.add_extra_dealloc_funcs(extra_dealloc_funcs)

    def add_extra_dealloc_funcs(self, extra_deallocs: List[str]) -> None:
        self.dealloc_funcs.update(extra_deallocs)

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        dealloc_pattern = "|".join(re.escape(f) for f in sorted(self.dealloc_funcs, key=len, reverse=True))
        summaries = analyze_function_summaries(ast_ctx, dealloc_funcs=self.dealloc_funcs)
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, dealloc_funcs=self.dealloc_funcs, summaries=summaries)
            if cfg is not None:
                reported_uafs = set()
                for node in cfg.nodes.values():
                    freed_ptrs = node.freed | node.realloc_inputs
                    for freed_ptr in freed_ptrs:
                        for use_node, accessed_var in _find_uaf_uses(cfg, node.node_id, freed_ptr):
                            key = (use_node.line_number, accessed_var)
                            if key in reported_uafs:
                                continue
                            reported_uafs.add(key)
                            use_line = use_node.line_number
                            snippet = _source_snippet(ast_ctx, use_line, use_node.expr_str)
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=use_line,
                                code_snippet=snippet,
                                message=f"Potential Use-After-Free: pointer '{accessed_var}' was freed at line {node.line_number} and accessed here.",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.MANUAL_REVIEW,
                            ))
                continue

            body_lines = fn.body.splitlines()
            depths = _brace_depths(body_lines)
            for i, line in enumerate(body_lines):
                line_no = fn.start_line + 1 + i
                free_match = re.search(rf'\b(?:{dealloc_pattern})\s*\(\s*(\w+)\s*\)', line)
                if not free_match:
                    continue
                freed_ptr = free_match.group(1)
                base_depth = depths[i]
                limit = min(i + 1 + self.MAX_LOOKAHEAD_LINES, len(body_lines))
                for j in range(i + 1, limit):
                    if depths[j] < base_depth:
                        break
                    next_line = body_lines[j]
                    next_line_no = fn.start_line + 1 + j
                    if re.search(rf'\b{re.escape(freed_ptr)}\s*=', next_line):
                        break
                    if re.search(rf'(?:\*\s*{re.escape(freed_ptr)}\b|{re.escape(freed_ptr)}\s*->|{re.escape(freed_ptr)}\s*\[|\b\w+\s*\([^)]*?\b{re.escape(freed_ptr)}\b)', next_line):
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=next_line_no,
                            code_snippet=next_line,
                            message=f"Potential Use-After-Free: pointer '{freed_ptr}' was freed at line {line_no} and accessed here.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.MANUAL_REVIEW,
                        ))
                        break
        return issues


class UninitializedMemoryUseRule(BaseRule):
    rule_id = "CGULL-023"
    name = "Uninitialized Memory Use"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Prevent reading from local memory locations / variables before they are explicitly initialized."
    implementation_method = "AST parsing to track variable assignment before read"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-457 / CWE-908"
    remediation_suggestion = "Always initialize scalar variables (e.g. int x = 0;) and buffers (char buf[128] = {0};) at declaration."
    sample_vulnerable_code = "int status;\nif (flag) status = 1;\nreturn status; // status uninitialized if flag is false"
    sample_remediated_code = "int status = 0;\nif (flag) status = 1;\nreturn status;"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        summaries = analyze_function_summaries(ast_ctx)
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, summaries=summaries)
            if cfg is not None:
                uninit_vars = [v_name for v_name, var in fn.variables.items() if not var.has_initializer and not var.is_volatile]
                if not uninit_vars:
                    continue
                reported = set()
                for node in cfg.nodes.values():
                    for v_name in uninit_vars:
                        if v_name in reported:
                            continue
                        if v_name in node.writes:
                            continue
                        if v_name in node.reads:
                            if cfg.query_initialization(v_name, node.node_id) in (Initialization.UNINITIALIZED, Initialization.MAYBE_INITIALIZED):
                                decl_line = fn.variables[v_name].declaration_line
                                snippet = _source_snippet(ast_ctx, decl_line, f"int {v_name};")
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=decl_line,
                                    code_snippet=snippet,
                                    message=f"Local variable '{v_name}' is declared without initialization. Initialize at declaration to prevent reading stack garbage.",
                                    column_number=1,
                                    engine="AST",
                                    fix_type=FixType.SAFE_FIX,
                                    auto_fix_replacement=snippet.replace(f"{v_name};", f"{v_name} = 0;")
                                ))
                                reported.add(v_name)
                continue

            for v_name, var in fn.variables.items():
                if not var.has_initializer and not var.is_pointer and not var.is_volatile:
                    decl_line_content = ast_ctx.source_lines[var.declaration_line - 1] if var.declaration_line <= len(ast_ctx.source_lines) else ""
                    if "=" not in decl_line_content and "{" not in decl_line_content:
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=var.declaration_line,
                            code_snippet=decl_line_content,
                            message=f"Local variable '{v_name}' is declared without initialization. Initialize at declaration to prevent reading stack garbage.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SAFE_FIX,
                            auto_fix_replacement=decl_line_content.replace(f"{v_name};", f"{v_name} = 0;")
                        ))
        return issues


class UnsafeSensitiveMemoryClearingRule(BaseRule):
    rule_id = "CGULL-008"
    name = "Unsafe Sensitive Memory Clearing"
    impact = Severity.HIGH
    category = RuleCategory.CRYPTO
    description = "Flag memset() used on sensitive local buffers just before scope exit/return, which optimizing compilers can silently eliminate (Dead Store Elimination)."
    implementation_method = "AST parsing & CFG dataflow to track buffer scope exit and dead store risks"
    implementation_complexity = "High"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-14"
    remediation_suggestion = "Use non-optimizable memory wipe functions such as explicit_bzero(), memset_s(), or SecureZeroMemory() instead of memset()."
    sample_vulnerable_code = "char password[64];\n// ... cryptographic operations ...\nmemset(password, 0, sizeof(password));\nreturn 0; // Compiler dead-store optimizer may erase memset!"
    sample_remediated_code = "explicit_bzero(password, sizeof(password)); // Or memset_s(password, sizeof(password), 0, sizeof(password));"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        sensitive_name_keywords = {'key', 'secret', 'pass', 'passwd', 'password', 'token', 'auth', 'hash', 'iv', 'pin', 'cred', 'credential', 'priv', 'cert', 'seed', 'session'}

        for fn in ast_ctx.functions:
            fn_is_sec = any(k in fn.name.lower() for k in ['auth', 'crypto', 'sec', 'key', 'pass', 'hash', 'token', 'sign', 'login', 'verify'])
            body_lines = fn.body.splitlines()

            # Map memset calls in function
            for call in fn.calls:
                callee, line_no, raw_args = call[0], call[1], call[2]
                if callee == "memset":
                    # Parse args: memset(buf, 0, len)
                    arg_parts = [a.strip() for a in raw_args.split(',')]
                    if len(arg_parts) >= 2 and arg_parts[1] in ('0', '0U', '0x0'):
                        buf_expr = arg_parts[0]
                        buf_name = re.findall(r'\b[a-zA-Z_]\w*\b', buf_expr)[0] if re.findall(r'\b[a-zA-Z_]\w*\b', buf_expr) else buf_expr

                        # Check if buf_name is sensitive by name or type or function context
                        is_sensitive_name = any(k in buf_name.lower() for k in sensitive_name_keywords)
                        var_obj = fn.variables.get(buf_name)
                        is_sensitive_type = False
                        if var_obj:
                            t_lower = var_obj.type_name.lower()
                            if any(k in t_lower for k in sensitive_name_keywords):
                                is_sensitive_type = True

                        is_near_exit = False
                        # Check CFG if available
                        if fn.cfg_nodes:
                            memset_nodes = [n for n in fn.cfg_nodes if n.line_number == line_no and 'memset' in n.expr_str]
                            for mn in memset_nodes:
                                idx = fn.cfg_nodes.index(mn)
                                is_read_after = False
                                for next_n in fn.cfg_nodes[idx + 1:]:
                                    if next_n.kind == "return":
                                        is_near_exit = True
                                    if buf_name in next_n.read_vars:
                                        is_read_after = True
                                        break
                                if not is_read_after:
                                    is_near_exit = True
                        else:
                            line_idx = line_no - fn.start_line
                            for offset in range(1, 4):
                                if line_idx + offset < len(body_lines):
                                    l_str = body_lines[line_idx + offset]
                                    if "return" in l_str or l_str.strip() == "}":
                                        is_near_exit = True
                                        break
                            if line_idx >= len(body_lines) - 3:
                                is_near_exit = True

                        if (is_sensitive_name or is_sensitive_type or fn_is_sec) and is_near_exit:
                            len_arg = arg_parts[2] if len(arg_parts) >= 3 else f"sizeof({buf_name})"
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else f"memset({raw_args})"
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Potentially unsafe memory wipe using memset('{buf_name}', 0, ...). Compilers frequently optimize out memset prior to return (Dead Store Elimination / CWE-14).",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.SAFE_FIX,
                                auto_fix_replacement=f"explicit_bzero({buf_name}, {len_arg});"
                            ))
        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # memset(key, 0, len) followed within 3 lines by return or }
        m = re.search(r'\bmemset\s*\(\s*(\w+)\s*,\s*0\s*,\s*([^)]+)\)', line_content)
        if m:
            buf_name = m.group(1)
            is_sensitive_name = any(k in buf_name.lower() for k in ['key', 'secret', 'pass', 'token', 'auth', 'hash', 'iv', 'pin', 'cred', 'session'])
            is_near_return = False
            for offset in range(1, 4):
                if line_number - 1 + offset < len(source_lines):
                    next_l = source_lines[line_number - 1 + offset]
                    if "return" in next_l or next_l.strip() == "}":
                        is_near_return = True
                        break

            if is_sensitive_name and is_near_return:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Potentially unsafe memory wipe using memset('{buf_name}', 0, ...). Compilers frequently optimize out memset prior to return (Dead Store Elimination / CWE-14).",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SAFE_FIX,
                    auto_fix_replacement=f"explicit_bzero({buf_name}, {m.group(2).strip()});"
                ))
        return issues


class ReallocOverwriteRule(BaseRule):
    rule_id = "CGULL-032"
    name = "Realloc-Overwrite Memory Leak"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect assigning realloc() return value directly to the pointer variable passed as its argument, which leaks memory if realloc() fails and returns NULL."
    implementation_method = "AST / Regex analysis to detect assignment of realloc return value to the same pointer identifier"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-401"
    remediation_suggestion = "Assign realloc() result to a temporary pointer, check for NULL, and update original pointer only on success: tmp = realloc(ptr, new_size); if (!tmp) { /* handle error, ptr remains valid */ } else { ptr = tmp; }"
    sample_vulnerable_code = "ptr = realloc(ptr, new_size);\nif (!ptr) {\n    return -1; // Leaked original memory block!\n}"
    sample_remediated_code = "void *tmp = realloc(ptr, new_size);\nif (!tmp) {\n    return -1; // ptr still valid\n}\nptr = tmp;"
    analysis_engine = AnalysisEngine.HYBRID

    DEFAULT_REALLOC_FUNCS = {"realloc"}

    def __init__(self, extra_realloc_funcs: Optional[List[str]] = None):
        super().__init__()
        self.realloc_funcs: Set[str] = set(self.DEFAULT_REALLOC_FUNCS)
        if extra_realloc_funcs:
            self.add_extra_realloc_funcs(extra_realloc_funcs)

    def add_extra_realloc_funcs(self, extra_reallocs: List[str]) -> None:
        self.realloc_funcs.update(extra_reallocs)

    @staticmethod
    def _extract_first_arg(raw_args: str) -> str:
        s = raw_args.strip()
        paren_depth = 0
        in_quote = False
        quote_char = None
        for i, c in enumerate(s):
            if in_quote:
                if c == quote_char and (i == 0 or s[i-1] != '\\'):
                    in_quote = False
            elif c in ('"', "'"):
                in_quote = True
                quote_char = c
            elif c in ('(', '[', '{'):
                paren_depth += 1
            elif c in (')', ']', '}'):
                paren_depth -= 1
                if paren_depth < 0:
                    return s[:i].strip()
            elif c == ',' and paren_depth == 0:
                return s[:i].strip()
        return s.strip()

    @staticmethod
    def _clean_expr(expr: str) -> str:
        s = expr.strip()
        s = re.sub(r'^\s*\(\s*(?:[a-zA-Z_]\w*\s*\*+|\w+)\s*\)\s*', '', s)
        s = s.strip().lstrip('(').rstrip(')')
        return re.sub(r'\s+', '', s)

    @staticmethod
    def _reconstruct_statement(source_lines: List[str], line_no: int) -> Tuple[str, int]:
        if not source_lines or line_no < 1 or line_no > len(source_lines):
            return "", line_no

        idx = line_no - 1
        start_idx = idx
        while start_idx > 0:
            prev_line = source_lines[start_idx - 1]
            if ';' in prev_line or '{' in prev_line or '}' in prev_line:
                break
            start_idx -= 1

        end_idx = idx
        while end_idx < len(source_lines):
            curr_line = source_lines[end_idx]
            if ';' in curr_line:
                break
            end_idx += 1

        if end_idx >= len(source_lines):
            end_idx = len(source_lines) - 1

        stmt_lines = source_lines[start_idx:end_idx + 1]
        return " ".join(l.strip() for l in stmt_lines), start_idx + 1

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        realloc_pattern = "|".join(re.escape(f) for f in sorted(self.realloc_funcs, key=len, reverse=True))
        assign_regex = re.compile(
            rf'\b([a-zA-Z_]\w*(?:\s*->\s*\w+|\s*\.\s*\w+|\[[^\]]+\])*)\s*=\s*'
            rf'(?:\([^)]+\)\s*)?'
            rf'({realloc_pattern})\s*\('
        )

        for fn in ast_ctx.functions:
            reported_lines_in_fn = set()

            if ast_ctx.has_pycparser and ast_ctx.pycparser_ast is not None:
                for call in fn.calls:
                    callee = call[0]
                    line_no = call[1]
                    raw_args = call[2]
                    target_var = call[3] if len(call) > 3 else None

                    if callee in self.realloc_funcs:
                        arg1_expr = self._extract_first_arg(raw_args)
                        if not arg1_expr:
                            continue

                        lhs_expr = target_var
                        if not lhs_expr:
                            stmt, _ = self._reconstruct_statement(ast_ctx.source_lines, line_no)
                            m = assign_regex.search(stmt)
                            if m:
                                lhs_expr = m.group(1).strip()

                        if lhs_expr and self._clean_expr(lhs_expr) == self._clean_expr(arg1_expr):
                            snippet = _source_snippet(ast_ctx, line_no, f"{callee}({raw_args})")
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Realloc-overwrite memory leak: return value of {callee}() is directly assigned to '{lhs_expr}'. If {callee}() fails and returns NULL, the original buffer at '{lhs_expr}' is leaked.",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.SUGGESTED_FIX,
                                suggested_fix_replacement=f"void *tmp = {callee}({lhs_expr}, ...);\nif (!tmp) {{\n    /* handle allocation failure, {lhs_expr} remains valid */\n}} else {{\n    {lhs_expr} = tmp;\n}}"
                            ))
                            reported_lines_in_fn.add(line_no)
            else:
                body_lines = fn.body.splitlines()
                body_start = getattr(fn, "body_start_line", fn.start_line + 1)
                for i, line in enumerate(body_lines):
                    line_no = body_start + i
                    if line_no in reported_lines_in_fn:
                        continue

                    stmt, _ = self._reconstruct_statement(ast_ctx.source_lines, line_no)
                    for m in assign_regex.finditer(stmt):
                        lhs_expr = m.group(1).strip()
                        callee_fn = m.group(2).strip()
                        arg1_expr = self._extract_first_arg(stmt[m.end():])

                        if self._clean_expr(lhs_expr) == self._clean_expr(arg1_expr):
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=line.strip() if 0 < line_no <= len(ast_ctx.source_lines) else stmt,
                                message=f"Realloc-overwrite memory leak: return value of {callee_fn}() is directly assigned to '{lhs_expr}'. If {callee_fn}() fails and returns NULL, the original buffer at '{lhs_expr}' is leaked.",
                                column_number=m.start() + 1,
                                engine="AST",
                                fix_type=FixType.SUGGESTED_FIX,
                                suggested_fix_replacement=f"void *tmp = {callee_fn}({lhs_expr}, ...);\nif (!tmp) {{\n    /* handle allocation failure, {lhs_expr} remains valid */\n}} else {{\n    {lhs_expr} = tmp;\n}}"
                            ))
                            reported_lines_in_fn.add(line_no)

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        if line_content.lstrip().startswith('#'):
            return issues

        realloc_pattern = "|".join(re.escape(f) for f in sorted(self.realloc_funcs, key=len, reverse=True))
        pattern = re.compile(
            rf'\b([a-zA-Z_]\w*(?:\s*->\s*\w+|\s*\.\s*\w+|\[[^\]]+\])*)\s*=\s*'
            rf'(?:\([^)]+\)\s*)?'
            rf'({realloc_pattern})\s*\('
        )

        match_target = masked_line_content or line_content
        m = pattern.search(match_target)
        if not m:
            return issues

        lhs_expr = m.group(1).strip()
        callee_fn = m.group(2).strip()
        rest_str = line_content[m.end():]
        arg1_expr = self._extract_first_arg(rest_str)

        if not arg1_expr or ';' not in line_content:
            stmt, _ = self._reconstruct_statement(source_lines, line_number)
            m_stmt = pattern.search(stmt)
            if m_stmt:
                lhs_expr = m_stmt.group(1).strip()
                callee_fn = m_stmt.group(2).strip()
                arg1_expr = self._extract_first_arg(stmt[m_stmt.end():])

        if self._clean_expr(lhs_expr) == self._clean_expr(arg1_expr):
            col_no = m.start() + 1
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Realloc-overwrite memory leak: return value of {callee_fn}() is directly assigned to '{lhs_expr}'. If {callee_fn}() fails and returns NULL, the original buffer at '{lhs_expr}' is leaked.",
                column_number=col_no,
                engine="Regex",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement=f"void *tmp = {callee_fn}({lhs_expr}, ...);\nif (!tmp) {{\n    /* handle allocation failure, {lhs_expr} remains valid */\n}} else {{\n    {lhs_expr} = tmp;\n}}"
            ))
        return issues


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


class MemoryLeakRule(BaseRule):
    rule_id = "CGULL-036"
    name = "Memory Leak"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect dynamically allocated memory (malloc, calloc, realloc, strdup, aligned_alloc) assigned to local pointers that is not freed or transferred before function exit paths."
    implementation_method = "AST parsing & CFG dataflow analysis tracking allocation lifecycles across exit paths"
    implementation_complexity = "High"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-401"
    remediation_suggestion = "Ensure all allocated memory blocks are freed with free() before scope exit, or transferred to the caller via return value or output parameter."
    sample_vulnerable_code = "void bad() {\n    char *data = (char *)malloc(100);\n    if (!data) return;\n    strcpy(data, \"hello\");\n    // POTENTIAL FLAW: data is never freed\n}"
    sample_remediated_code = "void good() {\n    char *data = (char *)malloc(100);\n    if (!data) return;\n    strcpy(data, \"hello\");\n    free(data);\n}"
    analysis_engine = AnalysisEngine.HYBRID

    DEFAULT_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "strdup", "strndup", "aligned_alloc", "valloc", "pvalloc", "memalign", "posix_memalign"}
    DEFAULT_REALLOC_FUNCS = {"realloc"}
    DEFAULT_DEALLOC_FUNCS = {"free", "cfree", "vfree"}

    def __init__(
        self,
        extra_alloc_funcs: Optional[List[str]] = None,
        extra_realloc_funcs: Optional[List[str]] = None,
        extra_dealloc_funcs: Optional[List[str]] = None,
    ):
        super().__init__()
        self.alloc_funcs: Set[str] = set(self.DEFAULT_ALLOC_FUNCS)
        self.realloc_funcs: Set[str] = set(self.DEFAULT_REALLOC_FUNCS)
        self.dealloc_funcs: Set[str] = set(self.DEFAULT_DEALLOC_FUNCS)
        if extra_alloc_funcs:
            self.add_extra_alloc_funcs(extra_alloc_funcs)
        if extra_realloc_funcs:
            self.add_extra_realloc_funcs(extra_realloc_funcs)
        if extra_dealloc_funcs:
            self.add_extra_dealloc_funcs(extra_dealloc_funcs)

    def add_extra_alloc_funcs(self, extra_allocs: List[str]) -> None:
        self.alloc_funcs.update(extra_allocs)

    def add_extra_realloc_funcs(self, extra_reallocs: List[str]) -> None:
        self.realloc_funcs.update(extra_reallocs)
        self.alloc_funcs.update(extra_reallocs)

    def add_extra_dealloc_funcs(self, extra_deallocs: List[str]) -> None:
        self.dealloc_funcs.update(extra_deallocs)

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        alloc_pattern = "|".join(re.escape(f) for f in sorted(self.alloc_funcs, key=len, reverse=True))
        dealloc_pattern = "|".join(re.escape(f) for f in sorted(self.dealloc_funcs, key=len, reverse=True))
        summaries = analyze_function_summaries(ast_ctx, alloc_funcs=self.alloc_funcs, dealloc_funcs=self.dealloc_funcs)

        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, alloc_funcs=self.alloc_funcs, dealloc_funcs=self.dealloc_funcs, summaries=summaries)
            if cfg is not None:
                reported_allocs = set()
                for node in cfg.nodes.values():
                    if not node.allocated:
                        continue
                    for ptr_name in node.allocated:
                        key = (node.line_number, ptr_name)
                        if key in reported_allocs:
                            continue
                        leak_nodes = _find_memory_leak_exits(ast_ctx, fn, cfg, node.node_id, ptr_name, self.dealloc_funcs)
                        if leak_nodes:
                            reported_allocs.add(key)
                            line_no = node.line_number
                            snippet = _source_snippet(ast_ctx, line_no, node.expr_str)
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Memory leak: memory allocated for '{ptr_name}' at line {line_no} is never freed or transferred before scope exit.",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.SUGGESTED_FIX,
                                suggested_fix_replacement=f"free({ptr_name});"
                            ))
                continue

            # Parser unavailable: fallback to lexical scope analysis
            body_lines = fn.body.splitlines()
            depths = _brace_depths(body_lines)
            alloc_regex = re.compile(rf'\b(\w+)\s*=\s*(?:\([^\)]+\)\s*)?(?:{alloc_pattern})\s*\(')
            body_start = getattr(fn, "body_start_line", fn.start_line + 1)

            for i, line in enumerate(body_lines):
                line_no = body_start + i
                m = alloc_regex.search(line)
                if not m:
                    continue
                ptr_name = m.group(1)
                base_depth = depths[i]

                has_dealloc_or_transfer = False
                for j in range(i + 1, len(body_lines)):
                    if depths[j] < base_depth:
                        break
                    sub_line = body_lines[j]
                    if re.search(rf'\b(?:{dealloc_pattern})\s*\(\s*{re.escape(ptr_name)}\s*\)', sub_line) or \
                       re.search(rf'\breturn\b.*?\b{re.escape(ptr_name)}\b', sub_line) or \
                       re.search(rf'\*\s*\w+\s*=\s*{re.escape(ptr_name)}\b', sub_line) or \
                       re.search(rf'{re.escape(ptr_name)}\s*->', sub_line):
                        has_dealloc_or_transfer = True
                        break
                if not has_dealloc_or_transfer:
                    snippet = _source_snippet(ast_ctx, line_no, line)
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        message=f"Memory leak: memory allocated for '{ptr_name}' at line {line_no} is never freed or transferred before scope exit.",
                        column_number=m.start() + 1,
                        engine="Regex",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=f"free({ptr_name});"
                    ))

        return issues


class ReturnStackVariableRule(BaseRule):
    rule_id = "CGULL-038"
    name = "Return Stack Variable"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect return statements that expose the address of an automatic-storage local variable or function parameter after the function returns."
    implementation_method = "AST traversal of return expressions and lexical local-variable scopes"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-562"
    remediation_suggestion = "Do not return the address of an automatic-storage local variable or parameter; return caller-owned storage, a static object when appropriate, or dynamically allocated storage instead."
    sample_vulnerable_code = "int *get_value(void) {\n    int value = 42;\n    return &value;\n}"
    sample_remediated_code = "int *get_value(void) {\n    int *value = malloc(sizeof(*value));\n    if (!value) return NULL;\n    *value = 42;\n    return value;\n}"
    analysis_engine = AnalysisEngine.AST

    @staticmethod
    def _returned_local_names(expr, automatic_names: Set[str], array_names: Set[str]) -> Set[str]:
        """Return automatic locals whose storage can escape through `expr`.

        A direct ID is unsafe when it names an automatic array because array-to-
        pointer decay returns its first element's address. An explicit address-of
        expression is unsafe for any automatic object. Casts and pointer arithmetic
        around an address expression are also handled by recursively inspecting
        their operands. Plain uses of local scalar/pointer variables are ignored.
        """
        from pycparser import c_ast

        found: Set[str] = set()

        def root_lvalue(node):
            while isinstance(node, (c_ast.ArrayRef, c_ast.StructRef)):
                node = node.name
            return node

        def visit(node, address_context: bool = False):
            if node is None:
                return
            if isinstance(node, c_ast.ID):
                if node.name in automatic_names and (address_context or node.name in array_names):
                    found.add(node.name)
                return
            if isinstance(node, c_ast.UnaryOp):
                if node.op == '&':
                    operand = node.expr
                    is_safe = False
                    needs_array = False
                    
                    curr = operand
                    while isinstance(curr, (c_ast.ArrayRef, c_ast.StructRef)):
                        if isinstance(curr, c_ast.StructRef):
                            if curr.type == '->':
                                is_safe = True
                                break
                        elif isinstance(curr, c_ast.ArrayRef):
                            needs_array = True
                        curr = curr.name
                    
                    if not is_safe and isinstance(curr, c_ast.ID):
                        if needs_array:
                            if curr.name in array_names:
                                found.add(curr.name)
                        else:
                            if curr.name in automatic_names:
                                found.add(curr.name)
                    elif not is_safe:
                        visit(operand, True)
                    return
                visit(node.expr, address_context)
                return
            if isinstance(node, c_ast.Cast):
                visit(node.expr, address_context)
                return
            if isinstance(node, c_ast.FuncCall):
                visit(node.name, False)
                return
            if isinstance(node, c_ast.ArrayRef):
                # Array-to-pointer decay only applies when the array itself is the
                # returned expression; an indexed scalar is not an escaped address.
                visit(node.name, address_context and False)
                visit(node.subscript, False)
                return
            if isinstance(node, c_ast.StructRef):
                visit(node.name, address_context)
                visit(node.field, False)
                return
            for _, child in node.children():
                visit(child, address_context)

        visit(expr)
        return found

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
            return []

        from pycparser import c_ast

        issues: List[Issue] = []
        for fn in ast_ctx.functions:
            funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
            if funcdef is None or funcdef.body is None:
                continue

            class ReturnVisitor(c_ast.NodeVisitor):
                def __init__(self, outer: "ReturnStackVariableRule"):
                    self.outer = outer
                    self.scope_stack = [
                        {p.name: {'is_static': False, 'is_array': False} for p in fn.parameters if p.name}
                    ]
                    self.returns: List[Tuple[c_ast.Return, Set[str]]] = []

                def _get_active_names(self):
                    active_automatic = set()
                    active_arrays = set()
                    for scope in self.scope_stack:
                        for name, info in scope.items():
                            if info['is_static']:
                                active_automatic.discard(name)
                                active_arrays.discard(name)
                            else:
                                active_automatic.add(name)
                                if info['is_array']:
                                    active_arrays.add(name)
                                else:
                                    active_arrays.discard(name)
                    return active_automatic, active_arrays

                def visit_Compound(self, node):
                    self.scope_stack.append({})
                    for item in node.block_items or []:
                        self.visit(item)
                    self.scope_stack.pop()

                def visit_Decl(self, node):
                    if node.name and type(node.type).__name__ != "FuncDecl":
                        is_static = "static" in (node.storage or [])
                        is_array = isinstance(node.type, c_ast.ArrayDecl)
                        self.scope_stack[-1][node.name] = {'is_static': is_static, 'is_array': is_array}
                    # Initializers can contain nested expressions, but declarations
                    # themselves cannot contain return statements in standard C.
                    if node.init is not None:
                        self.visit(node.init)

                def visit_Return(self, node):
                    active_automatic, active_arrays = self._get_active_names()
                    names = self.outer._returned_local_names(
                        node.expr, active_automatic, active_arrays
                    )
                    if names:
                        self.returns.append((node, names))
                    # Do not descend into the return expression a second time.

            visitor = ReturnVisitor(self)
            visitor.visit(funcdef.body)
            line_offset = (
                funcdef.decl.coord.line - fn.start_line
                if funcdef.decl.coord is not None
                else 0
            )

            for node, names in visitor.returns:
                line_no = (node.coord.line - line_offset) if node.coord else fn.start_line
                snippet = _source_snippet(ast_ctx, line_no, "return;")
                names_text = ", ".join(sorted(names))
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    message=(
                        f"Return statement exposes the address of automatic-storage "
                        f"variable(s) '{names_text}', which become invalid when function "
                        "'{0}' returns.".format(fn.name)
                    ),
                    column_number=getattr(node.coord, "column", 1) if node.coord else 1,
                    engine="AST",
                    fix_type=FixType.MANUAL_REVIEW,
                ))

        return issues


class MemcpyStructMemberOverflowRule(BaseRule):
    rule_id = "CGULL-044"
    name = "Size-Aware Struct-Member / Array Buffer Overflow in Memory Copy Functions"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect memcpy(), memmove(), or memset() calls where the specified byte count provably exceeds the destination buffer's capacity (struct member or plain array) or is ungated by a preceding bounds check."
    implementation_method = "AST / CFG dataflow and bounds check analysis with regex fallback"
    implementation_complexity = "High"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-787 / CWE-120"
    remediation_suggestion = "Ensure memory copy/fill operations do not write past destination buffer capacity, and gate variable size arguments with explicit bounds checks: if (n <= capacity) memcpy(dest, src, n);"
    sample_vulnerable_code = "struct A { char array_a[100]; };\nvoid fun_c(struct A *a, const char *src, int n) {\n    memcpy(a->array_a, src, n); // n exceeds 100 or ungated!\n}"
    sample_remediated_code = "struct A { char array_a[100]; };\nvoid fun_c(struct A *a, const char *src, int n) {\n    if (n <= 100) {\n        memcpy(a->array_a, src, n);\n    }\n}"
    analysis_engine = AnalysisEngine.HYBRID

    TARGET_FUNCS = {"memcpy", "memmove", "memset"}

    def _resolve_dest_capacity(
        self,
        dest_expr: str,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Optional[int]:
        dest_clean = dest_expr.strip()
        dest_clean = re.sub(
            r'^\s*\(\s*(?:const\s+)?(?:char|int8_t|uint8_t|void|unsigned\s+char|signed\s+char|int)\s*\*+\s*\)\s*',
            '',
            dest_clean,
        ).strip()
        while dest_clean.startswith('(') and dest_clean.endswith(')'):
            dest_clean = dest_clean[1:-1].strip()

        is_address_of = dest_expr.strip().startswith('&')
        if dest_clean.startswith('&'):
            dest_clean = dest_clean[1:].strip()

        # 1. Struct member access chain resolution (V1-V7)
        if '->' in dest_clean or '.' in dest_clean:
            parts = re.split(r'->|\.', dest_clean)
            base_expr_str = parts[0].strip()
            fields = [p.strip() for p in parts[1:] if p.strip()]

            if base_expr_str and fields and ast_ctx:
                sdef = ast_ctx.resolve_struct_def(fn, base_expr_str)
                curr_sdef = sdef
                target_field = None
                for field_expr in fields:
                    if not curr_sdef:
                        target_field = None
                        break
                    f_name = re.sub(r'\[[^\]]*\]', '', field_expr).strip()
                    target_field = curr_sdef.get(f_name)
                    if not target_field:
                        break
                    if target_field.is_struct_or_union:
                        nested_tag = target_field.nested_tag or target_field.type_name
                        curr_sdef = ast_ctx.get_struct_def(nested_tag)
                    else:
                        curr_sdef = None

                if target_field and target_field.is_array:
                    elem_byte_size = get_type_byte_size(target_field.type_name, ast_ctx)
                    if elem_byte_size is None:
                        return None

                    dims = getattr(target_field, 'array_dims', None) or (
                        [target_field.array_size] if target_field.array_size is not None else []
                    )
                    last_field_expr = fields[-1]
                    subscripts = re.findall(r'\[\s*([^\]]+)\s*\]', last_field_expr)

                    if is_address_of and subscripts:
                        dim_subscripts = subscripts[:-1]
                        offset_str = subscripts[-1].strip()
                        try:
                            offset_val = int(offset_str)
                        except ValueError:
                            offset_val = 0
                    else:
                        dim_subscripts = subscripts
                        offset_val = 0

                    dim_idx = len(dim_subscripts)
                    if dims and dim_idx < len(dims):
                        selected_dim = dims[dim_idx]
                    elif target_field.array_size is not None and dim_idx == 0:
                        selected_dim = target_field.array_size
                    else:
                        selected_dim = None

                    if selected_dim is not None and isinstance(selected_dim, int):
                        remaining_elems = max(0, selected_dim - offset_val)
                        return remaining_elems * elem_byte_size

        # 2. Plain local or global array (with optional offset)
        elem_offset = 0
        m_idx = re.match(r'^(.*?)\s*\[\s*(\d+)\s*\]$', dest_clean)
        if m_idx:
            dest_clean_base = m_idx.group(1).strip()
            elem_offset = int(m_idx.group(2))
        else:
            dest_clean_base = dest_clean

        if re.match(r'^[a-zA-Z_]\w*$', dest_clean_base):
            var_name = dest_clean_base
            var_obj = fn.variables.get(var_name) or (ast_ctx.global_variables.get(var_name) if ast_ctx else None)
            if var_obj and var_obj.array_size_expr:
                elem_byte_size = get_type_byte_size(var_obj.type_name, ast_ctx)
                if elem_byte_size is None:
                    return None
                expr = var_obj.array_size_expr.strip()
                if expr.isdigit():
                    remaining_elems = max(0, int(expr) - elem_offset)
                    return remaining_elems * elem_byte_size
                m = re.search(r'\b(\d+)\b', expr)
                if m:
                    remaining_elems = max(0, int(m.group(1)) - elem_offset)
                    return remaining_elems * elem_byte_size

            # Check pointer aliasing or local array decl in source lines
            body_lines = fn.body.splitlines() if fn else []
            fn_start = getattr(fn, "body_start_line", fn.start_line) if fn else 1
            max_idx = min(len(body_lines), line_no - fn_start) if line_no >= fn_start else len(body_lines)

            assign_stmt_pattern = re.compile(
                rf'(?:^|[;{{}}\s])(?:(?:\w+\s+)*\*+\s*)?{re.escape(var_name)}\s*=(?!=)\s*(.+?)(?:;|$)'
            )
            for idx in range(max_idx - 1, -1, -1):
                line = body_lines[idx]
                m = assign_stmt_pattern.search(line)
                if m:
                    rhs = m.group(1).strip()
                    rhs_clean = re.sub(r'^(?:\([^\)]+\)\s*)+', '', rhs).strip()
                    alias_target = None
                    offset = 0
                    m_idx_rhs = re.match(r'^&\s*([a-zA-Z_]\w*)\s*\[\s*(\d+)\s*\]$', rhs_clean)
                    m_add1 = re.match(r'^([a-zA-Z_]\w*)\s*\+\s*(\d+)$', rhs_clean)
                    m_add2 = re.match(r'^(\d+)\s*\+\s*([a-zA-Z_]\w*)$', rhs_clean)
                    m_simple = re.match(r'^(?:&\s*)?([a-zA-Z_]\w*)(?:\s*\[\s*0\s*\])?$', rhs_clean)
                    if m_idx_rhs:
                        alias_target = m_idx_rhs.group(1)
                        offset = int(m_idx_rhs.group(2))
                    elif m_add1:
                        alias_target = m_add1.group(1)
                        offset = int(m_add1.group(2))
                    elif m_add2:
                        alias_target = m_add2.group(2)
                        offset = int(m_add2.group(1))
                    elif m_simple:
                        alias_target = m_simple.group(1)
                        offset = 0

                    if alias_target and alias_target != var_name:
                        t_var = fn.variables.get(alias_target) or (ast_ctx.global_variables.get(alias_target) if ast_ctx else None)
                        if t_var and t_var.array_size_expr and t_var.array_size_expr.isdigit():
                            elem_byte_size = get_type_byte_size(t_var.type_name, ast_ctx)
                            if elem_byte_size is None:
                                return None
                            remaining_elems = max(0, int(t_var.array_size_expr) - offset - elem_offset)
                            return remaining_elems * elem_byte_size

        return None

    @staticmethod
    def _eval_const_arithmetic(expr_str: str) -> Optional[int]:
        import ast
        try:
            tree = ast.parse(expr_str, mode='eval')
        except Exception:
            return None

        def _eval_node(node):
            if isinstance(node, ast.Expression):
                return _eval_node(node.body)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return int(node.value)
            if isinstance(node, ast.UnaryOp):
                val = _eval_node(node.operand)
                if val is None:
                    return None
                if isinstance(node.op, ast.USub):
                    return -val
                if isinstance(node.op, ast.UAdd):
                    return +val
            if isinstance(node, ast.BinOp):
                left = _eval_node(node.left)
                right = _eval_node(node.right)
                if left is None or right is None:
                    return None
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if isinstance(node.op, (ast.FloorDiv, ast.Div)):
                    return left // right if right != 0 else None
                if isinstance(node.op, ast.LShift):
                    return left << right if 0 <= right <= 63 else None
                if isinstance(node.op, ast.RShift):
                    return left >> right if 0 <= right <= 63 else None
            return None

        return _eval_node(tree)

    def _resolve_size_arg(
        self,
        size_expr: str,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Tuple[Optional[int], Optional[str]]:
        """
        Returns (const_value, var_name).
        If const_value is not None, size is a static constant.
        If var_name is not None, size is a dynamic variable identifier or expression.
        """
        expr = size_expr.strip()
        s_sub = expr

        # 1. Substitute all sizeof(...) occurrences with resolved integer sizes
        sizeof_matches = list(re.finditer(r'sizeof\s*\(\s*(.+?)\s*\)', expr)) or list(re.finditer(r'sizeof\s*([a-zA-Z_]\w*)', expr))
        if sizeof_matches:
            offset_shift = 0
            for m in sizeof_matches:
                so_arg = m.group(1).strip()
                so_val = get_type_byte_size(so_arg, ast_ctx)
                if so_val is None and fn and ast_ctx:
                    var_obj = fn.variables.get(so_arg) or ast_ctx.global_variables.get(so_arg)
                    if var_obj:
                        so_val = self._resolve_dest_capacity(so_arg, fn, line_no, ast_ctx) or get_type_byte_size(var_obj.type_name, ast_ctx)
                if so_val is None and ast_ctx:
                    sdef = ast_ctx.get_struct_def(so_arg)
                    if sdef and sdef.fields:
                        fb = 0
                        for f in sdef.fields.values():
                            fe = get_type_byte_size(f.type_name, ast_ctx)
                            if fe is None:
                                fb = None
                                break
                            fc = f.array_size if (f.is_array and f.array_size is not None) else 1
                            fb += fc * fe
                        if fb is not None and fb > 0:
                            so_val = fb

                if so_val is None:
                    # An unresolvable sizeof term makes the full expression unresolved
                    return None, expr

                start = m.start() + offset_shift
                end = m.end() + offset_shift
                rep = str(so_val)
                s_sub = s_sub[:start] + rep + s_sub[end:]
                offset_shift += len(rep) - (m.end() - m.start())

        # 2. Substitute macro constants
        if ast_ctx and ast_ctx.clean_source:
            for macro_m in re.finditer(r'\b([a-zA-Z_]\w*)\b', s_sub):
                m_name = macro_m.group(1)
                if m_name.isdigit():
                    continue
                def_m = re.search(rf'#\s*define\s+{re.escape(m_name)}\s+(\d+|0x[0-9a-fA-F]+)\b', ast_ctx.clean_source)
                if def_m:
                    v_str = def_m.group(1)
                    val = int(v_str, 16) if v_str.startswith(('0x', '0X')) else int(v_str)
                    s_sub = re.sub(rf'\b{re.escape(m_name)}\b', str(val), s_sub)

        # 3. Try evaluating complete constant arithmetic expression
        const_val = self._eval_const_arithmetic(s_sub)
        if const_val is not None:
            return const_val, None

        # 4. Expression is dynamic / variable
        return None, expr

    def _resolve_upper_bound(
        self,
        limit_expr: str,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Optional[int]:
        s = limit_expr.strip()
        s = re.sub(r'^\s*\(\s*(?:[a-zA-Z_]\w*\s*\*+|\w+)\s*\)\s*', '', s).strip()
        while s.startswith('(') and s.endswith(')'):
            s = s[1:-1].strip()

        const_v = self._eval_const_arithmetic(s)
        if const_v is not None:
            return const_v

        m_op = re.match(r'^([a-zA-Z_]\w*(?:\s*->\s*\w+|\s*\.\s*\w+)?)\s*([\+\-])\s*(\d+)$', s)
        if m_op:
            base_str = m_op.group(1)
            op = m_op.group(2)
            val = int(m_op.group(3))
            base_bound = self._resolve_upper_bound(base_str, fn, line_no, ast_ctx)
            if base_bound is not None:
                return base_bound + val if op == '+' else base_bound - val

        if 'sizeof' in s:
            const_val, _ = self._resolve_size_arg(s, fn, line_no, ast_ctx)
            if const_val is not None:
                return const_val

        if ast_ctx and ast_ctx.clean_source:
            def_m = re.search(rf'#\s*define\s+{re.escape(s)}\s+(\d+|0x[0-9a-fA-F]+)\b', ast_ctx.clean_source)
            if def_m:
                val_str = def_m.group(1)
                return int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)

        cap = self._resolve_dest_capacity(s, fn, line_no, ast_ctx)
        if cap is not None:
            return cap

        body_lines = fn.body.splitlines() if fn else []
        fn_start = getattr(fn, "body_start_line", fn.start_line) if fn else 1
        max_idx = min(len(body_lines), line_no - fn_start) if line_no >= fn_start else len(body_lines)
        assign_pat = re.compile(rf'(?:^|[;{{}}\s]){re.escape(s)}\s*=(?!=)\s*(.+?)(?:;|$)')
        for idx in range(max_idx - 1, -1, -1):
            line = body_lines[idx]
            m = assign_pat.search(line)
            if m:
                rhs = m.group(1).strip()
                return self._resolve_upper_bound(rhs, fn, fn_start + idx, ast_ctx)

        return None

    @staticmethod
    def _is_signed_var(var_name: str, fn: CFunction, ast_ctx: CASTContext) -> bool:
        if not fn:
            return True
        var_obj = fn.variables.get(var_name) or (ast_ctx.global_variables.get(var_name) if ast_ctx else None)
        if var_obj:
            return var_obj.is_signed
        param = next((p for p in fn.parameters if p.name == var_name), None)
        if param:
            from ..ast_analyzer import is_unsigned_type
            return not is_unsigned_type(param.type_name, getattr(ast_ctx, "unsigned_typedefs", None))
        return True

    def _eval_branch_bounds(
        self,
        cond_str: str,
        var_name: str,
        dest_capacity: int,
        curr_upper: bool,
        curr_lower: bool,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Tuple[Tuple[bool, bool], Tuple[bool, bool]]:
        v_esc = re.escape(var_name)
        if not re.search(r'\b' + v_esc + r'\b', cond_str):
            return (curr_upper, curr_lower), (curr_upper, curr_lower)

        true_upper, true_lower = curr_upper, curr_lower
        false_upper, false_lower = curr_upper, curr_lower

        # Upper bound checks
        for m in re.finditer(r'\b' + v_esc + r'\s*(<=|>=|<|>|==)\s*([^&|;)]+)', cond_str):
            op, rhs = m.group(1), m.group(2).strip()
            ub = self._resolve_upper_bound(rhs, fn, line_no, ast_ctx)
            if ub is not None:
                if op in ('<=', '=='):
                    if ub <= dest_capacity:
                        true_upper = True
                elif op == '<':
                    if ub - 1 <= dest_capacity:
                        true_upper = True
                elif op == '>=':
                    if ub - 1 <= dest_capacity:
                        false_upper = True
                elif op == '>':
                    if ub <= dest_capacity:
                        false_upper = True

        for m in re.finditer(r'([^&|;(]+)\s*(<=|>=|<|>|==)\s*\b' + v_esc + r'\b', cond_str):
            lhs, op = m.group(1).strip(), m.group(2)
            ub = self._resolve_upper_bound(lhs, fn, line_no, ast_ctx)
            if ub is not None:
                if op in ('>=', '=='):
                    if ub <= dest_capacity:
                        true_upper = True
                elif op == '>':
                    if ub - 1 <= dest_capacity:
                        true_upper = True
                elif op == '<=':
                    if ub - 1 <= dest_capacity:
                        false_upper = True
                elif op == '<':
                    if ub <= dest_capacity:
                        false_upper = True

        # Non-negative lower bound checks (var >= 0, var > -1)
        for m in re.finditer(r'\b' + v_esc + r'\s*(>=|>|<|<=|==)\s*(-?\d+)\b', cond_str):
            op, val = m.group(1), int(m.group(2))
            if op in ('>=', '==') and val >= 0:
                true_lower = True
            elif op == '>' and val >= -1:
                true_lower = True
            elif op in ('<', '<=') and val <= 0:
                false_lower = True

        for m in re.finditer(r'(-?\d+)\s*(<=|<|>|>=|==)\s*\b' + v_esc + r'\b', cond_str):
            val, op = int(m.group(1)), m.group(2)
            if op in ('<=', '==') and val >= 0:
                true_lower = True
            elif op == '<' and val >= -1:
                true_lower = True
            elif op in ('>', '>=') and val <= 0:
                false_lower = True

        return (true_upper, true_lower), (false_upper, false_lower)

    def _is_min_clamp_bound(
        self,
        expr_str: Optional[str],
        var_name: str,
        dest_capacity: int,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Tuple[bool, bool]:
        if not expr_str:
            return False, False
        v_esc = re.escape(var_name)
        if not re.search(r'\b' + v_esc + r'\b', expr_str):
            return False, False

        upper = False
        lower = False

        m_clamp = re.search(r'\bclamp\s*\(\s*' + v_esc + r'\s*,\s*(-?\d+)\s*,\s*([^)]+)\)', expr_str)
        if m_clamp:
            min_v = int(m_clamp.group(1))
            max_expr = m_clamp.group(2).strip()
            ub = self._resolve_upper_bound(max_expr, fn, line_no, ast_ctx)
            if min_v >= 0:
                lower = True
            if ub is not None and ub <= dest_capacity:
                upper = True
            return upper, lower

        m_call = re.search(r'\bmin\s*\(([^)]+)\)', expr_str)
        if m_call:
            args = [a.strip() for a in m_call.group(1).split(',')]
            for arg in args:
                if arg == var_name:
                    continue
                ub = self._resolve_upper_bound(arg, fn, line_no, ast_ctx)
                if ub is not None and ub <= dest_capacity:
                    upper = True

        return upper, lower

    def _is_size_var_gated(
        self,
        var_name: str,
        dest_capacity: int,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> bool:
        if not fn or not ast_ctx:
            return False

        is_signed = self._is_signed_var(var_name, fn, ast_ctx)
        init_lower = not is_signed

        cfg = _ast_cfg_for_function(ast_ctx, fn)
        if cfg is not None and cfg.entry is not None:
            target_node_ids = [nid for nid, node in cfg.nodes.items() if node.line_number == line_no and any(tf in (node.expr_str or '') for tf in self.TARGET_FUNCS)]
            if not target_node_ids:
                target_node_ids = [nid for nid, node in cfg.nodes.items() if node.line_number == line_no]

            if target_node_ids:
                target_node_id = target_node_ids[0]
                import collections
                queue = collections.deque([(cfg.entry, False, init_lower)])
                visited = set()
                path_reached = False

                while queue:
                    curr_id, upper_b, lower_b = queue.popleft()
                    state_key = (curr_id, upper_b, lower_b)
                    if state_key in visited:
                        continue
                    visited.add(state_key)

                    if curr_id == target_node_id:
                        path_reached = True
                        if not (upper_b and lower_b):
                            return False
                        continue

                    node = cfg.nodes[curr_id]
                    new_upper, new_lower = upper_b, lower_b

                    if var_name in node.writes:
                        u_bound, l_bound = self._is_min_clamp_bound(node.expr_str, var_name, dest_capacity, fn, node.line_number, ast_ctx)
                        new_upper = u_bound
                        new_lower = l_bound or (not is_signed)

                    if node.kind in ("if_cond", "while_cond", "do_cond") and node.expr_str:
                        true_st, false_st = self._eval_branch_bounds(
                            node.expr_str, var_name, dest_capacity, new_upper, new_lower, fn, node.line_number, ast_ctx
                        )
                        if len(node.successors) >= 2:
                            queue.append((node.successors[0], true_st[0], true_st[1]))
                            queue.append((node.successors[1], false_st[0], false_st[1]))
                        elif len(node.successors) == 1:
                            succ_node = cfg.nodes[node.successors[0]]
                            if_ast = getattr(node, '_ast_node', None)
                            is_inside_if = False
                            if if_ast and getattr(if_ast, 'iftrue', None):
                                def _is_ast_child(child, parent):
                                    if parent is None or child is None:
                                        return False
                                    if parent is child:
                                        return True
                                    for _, c in getattr(parent, 'children', lambda: [])():
                                        if _is_ast_child(child, c):
                                            return True
                                    return False
                                is_inside_if = _is_ast_child(getattr(succ_node, '_ast_node', None), if_ast.iftrue)

                            if is_inside_if:
                                queue.append((node.successors[0], true_st[0], true_st[1]))
                            else:
                                queue.append((node.successors[0], false_st[0], false_st[1]))
                        continue

                    for succ_id in node.successors:
                        queue.append((succ_id, new_upper, new_lower))

                if path_reached:
                    return True

        return self._is_size_var_gated_lexical(var_name, dest_capacity, fn, line_no, ast_ctx)

    def _is_size_var_gated_lexical(
        self,
        var_name: str,
        dest_capacity: int,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> bool:
        is_signed = self._is_signed_var(var_name, fn, ast_ctx)
        v_esc = re.escape(var_name)
        body_lines = fn.body.splitlines() if fn else []
        fn_start = getattr(fn, "body_start_line", fn.start_line) if fn else 1
        line_idx = line_no - fn_start

        start_idx = max(0, line_idx - 15)
        preceding_lines = body_lines[start_idx:line_idx]

        curr_u = False
        curr_l = not is_signed

        for idx, p_line in enumerate(preceding_lines):
            if not re.search(r'\b' + v_esc + r'\b', p_line):
                continue

            u_m, l_m = self._is_min_clamp_bound(p_line, var_name, dest_capacity, fn, fn_start + start_idx + idx, ast_ctx)
            if u_m:
                curr_u = True
            if l_m:
                curr_l = True

            if re.search(r'\b(?:if|assert|ASSERT|while)\b', p_line):
                (t_u, t_l), _ = self._eval_branch_bounds(p_line, var_name, dest_capacity, curr_u, curr_l, fn, fn_start + start_idx + idx, ast_ctx)
                curr_u, curr_l = t_u, t_l

            if curr_u and curr_l:
                subsequent = preceding_lines[idx + 1:]
                if not any(re.search(rf'(?:^|[;{{}}\s]){v_esc}\s*=(?!=)', l) for l in subsequent):
                    return True

        return False

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        target = masked_line_content or line_content
        if target.lstrip().startswith('#'):
            return issues

        for callee in self.TARGET_FUNCS:
            for m in re.finditer(rf'\b{re.escape(callee)}\s*\(', target):
                call_args = BannedFunctionsRule._extract_call_args(line_content, m.end() - 1)
                if not call_args or len(call_args) < 3:
                    continue

                if callee in ("memcpy", "memmove"):
                    dest_arg, src_arg, size_arg = call_args[0], call_args[1], call_args[2]
                else:  # memset
                    dest_arg, val_arg, size_arg = call_args[0], call_args[1], call_args[2]

                dest_clean = dest_arg.strip()
                dest_clean = re.sub(
                    r'^\s*\(\s*(?:const\s+)?(?:char|int8_t|uint8_t|void|unsigned\s+char|signed\s+char|int)\s*\*+\s*\)\s*',
                    '',
                    dest_clean,
                ).strip()
                if dest_clean.startswith('&'):
                    dest_clean = dest_clean[1:].strip()

                m_decl = re.search(rf'\b(?:char|int|float|double|uint\w+_t|size_t|struct\s+\w+|\w+)\s+(?:\*|\s)*\b{re.escape(dest_clean)}\s*\[\s*(\d+)\s*\]', full_code)
                dest_cap = int(m_decl.group(1)) if m_decl else None

                if dest_cap is None:
                    continue

                const_size = int(size_arg) if size_arg.isdigit() else None
                if const_size is not None and const_size > dest_cap:
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=f"Buffer Overflow in '{callee}': size argument ({const_size} bytes) provably exceeds destination buffer capacity ({dest_cap} bytes for '{dest_arg}'). Provable out-of-bounds write.",
                        column_number=m.start() + 1,
                        engine="Regex",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=f"{callee}({dest_arg}, ..., {dest_cap});"
                    ))

        return issues

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        reported_calls = set()

        for fn in ast_ctx.functions:
            for call in fn.calls:
                callee, line_no, raw_args = call[0], call[1], call[2]
                if callee not in self.TARGET_FUNCS:
                    continue

                args = None
                snippet = _source_snippet(ast_ctx, line_no, "")
                if snippet:
                    paren_pos = snippet.find('(')
                    if paren_pos != -1:
                        args = BannedFunctionsRule._extract_call_args(snippet, paren_pos)

                req_args = 3
                if not args or len(args) < req_args:
                    multiline_code = "\n".join(ast_ctx.source_lines[line_no - 1 : line_no + 10]) if (ast_ctx and ast_ctx.source_lines) else ""
                    paren_pos = multiline_code.find('(') if multiline_code else -1
                    if paren_pos != -1:
                        args = BannedFunctionsRule._extract_call_args(multiline_code, paren_pos)

                if not args or len(args) < req_args:
                    if raw_args:
                        args = BannedFunctionsRule._extract_call_args(f"{callee}({raw_args})", len(callee))
                if not args or len(args) < req_args:
                    args = [a.strip() for a in raw_args.split(',')] if raw_args else []

                if callee in ("memcpy", "memmove") and len(args) >= 3:
                    dest_arg, src_arg, size_arg = args[0], args[1], args[2]
                elif callee == "memset" and len(args) >= 3:
                    dest_arg, val_arg, size_arg = args[0], args[1], args[2]
                else:
                    continue

                dest_cap = self._resolve_dest_capacity(dest_arg, fn, line_no, ast_ctx)
                if dest_cap is None:
                    continue

                const_size, var_size = self._resolve_size_arg(size_arg, fn, line_no, ast_ctx)

                key = (line_no, callee, dest_arg)
                if key in reported_calls:
                    continue

                if const_size is not None:
                    if const_size > dest_cap:
                        reported_calls.add(key)
                        snippet = _source_snippet(ast_ctx, line_no, f"{callee}({raw_args})")
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Buffer Overflow in '{callee}': size argument ({const_size} bytes) provably exceeds destination buffer capacity ({dest_cap} bytes for '{dest_arg}'). Provable out-of-bounds write.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"{callee}({dest_arg}, ..., {dest_cap});"
                        ))
                elif var_size is not None:
                    if not self._is_size_var_gated(var_size, dest_cap, fn, line_no, ast_ctx):
                        reported_calls.add(key)
                        snippet = _source_snippet(ast_ctx, line_no, f"{callee}({raw_args})")
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Potentially Unchecked Buffer Overflow in '{callee}': variable size argument '{var_size}' is not gated by a bounds check against destination capacity ({dest_cap} bytes for '{dest_arg}').",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({var_size} <= {dest_cap}) {{\n    {snippet}\n}}"
                        ))

        return issues
