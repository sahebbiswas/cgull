"""
Rules for Memory Allocation, Null-checks, Lifecycles, and Pointer Safety.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ..ast_analyzer import CASTContext, CFunction
from ..cfg import StructuredCFG, CFGEvent, build_cfg, find_function_def, Nullness, Initialization, Allocation


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
):
    if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
        return None
    funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
    if funcdef is None:
        return None
    cfg = build_cfg(funcdef, alloc_funcs=alloc_funcs, dealloc_funcs=dealloc_funcs)
    initial_initialized = set(p.name for p in fn.parameters if p.name) | set(ast_ctx.global_variables.keys()) | {v for v, var in fn.variables.items() if var.has_initializer}
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
    work = list(cfg.nodes[freed_node_id].successors)
    visited = set()
    while work:
        nid = work.pop(0)
        if nid in visited:
            continue
        visited.add(nid)
        node = cfg.nodes[nid]

        accessed_vars = node.derefs | (node.reads - node.writes)
        for var in sorted(accessed_vars):
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
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, alloc_funcs=self.alloc_funcs, dealloc_funcs=self.dealloc_funcs)
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
        for fn in ast_ctx.functions:
            ptr_params = [p for p in fn.parameters if p.is_pointer and p.name]
            cfg = _ast_cfg_for_function(ast_ctx, fn)

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
                            key = (node.line_number, deref_var, "null_deref")
                            if key not in reported_nodes:
                                reported_nodes.add(key)
                                snippet = _source_snippet(ast_ctx, node.line_number, node.expr_str)
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=node.line_number,
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
                    key = (unsafe.line_number, param.name, "param_missing_check")
                    if key not in reported_nodes:
                        reported_nodes.add(key)
                        snippet = _source_snippet(ast_ctx, unsafe.line_number, unsafe.expr_str)
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=unsafe.line_number,
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
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn)
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
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, dealloc_funcs=self.dealloc_funcs)
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
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, dealloc_funcs=self.dealloc_funcs)
            if cfg is not None:
                reported_uafs = set()
                for node in cfg.nodes.values():
                    for freed_ptr in node.freed:
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
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn)
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

        # 2. Exit call check (program exit)
        if node.kind == "funccall":
            expr_lower = node.expr_str.lower()
            if any(re.search(rf'\b{re.escape(ef)}\b', expr_lower) for ef in exit_call_names):
                continue

        # 3. Ownership transfer check
        if node.kind in ("assignment", "decl"):
            if node.reads & aliases:
                if node.writes:
                    written_var = next(iter(node.writes))
                    if written_var in fn.variables:
                        aliases = aliases | {written_var}
                    else:
                        continue
                else:
                    continue

        # 4. Return statement check
        if node.kind == "return":
            if node.reads & aliases:
                continue
            is_null = any(cfg.query_nullness(a, curr_id) == Nullness.NULL for a in aliases)
            if not is_null:
                if curr_id not in reported_node_ids:
                    reported_node_ids.add(curr_id)
                    leak_nodes.append(node)
            continue

        # 5. Overwrite check
        if curr_id == alloc_node_id:
            overwritten = []
        else:
            overwritten = [w for w in node.writes if w in aliases]
        if overwritten:
            remaining_aliases = aliases - set(overwritten)
            if not remaining_aliases:
                is_null = any(cfg.query_nullness(w, curr_id) == Nullness.NULL for w in overwritten)
                if not is_null:
                    if curr_id not in reported_node_ids:
                        reported_node_ids.add(curr_id)
                        leak_nodes.append(node)
                continue
            else:
                aliases = remaining_aliases

        # 6. End of CFG check
        if not node.successors:
            is_null = any(cfg.query_nullness(a, curr_id) == Nullness.NULL for a in aliases)
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

        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, alloc_funcs=self.alloc_funcs, dealloc_funcs=self.dealloc_funcs)
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
