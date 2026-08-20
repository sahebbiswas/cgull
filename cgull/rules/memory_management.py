"""
Rules for Memory Allocation, Null-checks, Lifecycles, and Pointer Safety.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ..ast_analyzer import CASTContext, CFunction
from ..cfg import StructuredCFG, build_cfg, find_function_def, Nullness, Initialization, Allocation


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
    """Yield all reachable nodes where ptr_name is accessed after free."""
    work = list(cfg.nodes[freed_node_id].successors)
    visited = set()
    while work:
        nid = work.pop(0)
        if nid in visited:
            continue
        visited.add(nid)
        node = cfg.nodes[nid]

        if cfg.query_allocation(ptr_name, nid) in (Allocation.FREED, Allocation.MAYBE_FREED):
            if not node.kind.endswith('_cond'):
                if ptr_name in node.derefs or (ptr_name in node.reads and ptr_name not in node.writes):
                    yield node
                    continue

        if ptr_name in node.writes:
            # Reassignment ends freed lifetime
            continue

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

    def __init__(
        self,
        extra_alloc_funcs: Optional[List[str]] = None,
        extra_realloc_funcs: Optional[List[str]] = None,
        extra_dealloc_funcs: Optional[List[str]] = None,
    ):
        super().__init__()
        self.alloc_funcs: Set[str] = set(self.DEFAULT_ALLOC_FUNCS)
        self.realloc_funcs: Set[str] = set(self.DEFAULT_REALLOC_FUNCS)
        if extra_alloc_funcs:
            self.add_extra_alloc_funcs(extra_alloc_funcs)
        if extra_realloc_funcs:
            self.add_extra_realloc_funcs(extra_realloc_funcs)

    def add_extra_alloc_funcs(self, extra_allocs: List[str]) -> None:
        self.alloc_funcs.update(extra_allocs)

    def add_extra_realloc_funcs(self, extra_reallocs: List[str]) -> None:
        self.realloc_funcs.update(extra_reallocs)
        self.alloc_funcs.update(extra_reallocs)

    def add_extra_dealloc_funcs(self, extra_deallocs: List[str]) -> None:
        pass

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        alloc_pattern = "|".join(re.escape(f) for f in sorted(self.alloc_funcs, key=len, reverse=True))
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, alloc_funcs=self.alloc_funcs)
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
    description = "Ensure pointer arguments are checked against NULL before being dereferenced inside function body."
    implementation_method = "AST parsing to extract pointer parameters and verify conditional checks"
    implementation_complexity = "Medium"
    chances_of_false_positives = "High"
    cwe_id = "CWE-476"
    remediation_suggestion = "Add a guard clause at function entry: if (param == NULL) { return ERROR_CODE; }"
    sample_vulnerable_code = "int process_data(int *data, char *tag) {\n    *data = 100; // Dereferenced without NULL check\n    return 0;\n}"
    sample_remediated_code = "int process_data(int *data, char *tag) {\n    if (data == NULL || tag == NULL) return -EINVAL;\n    *data = 100;\n    return 0;\n}"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            ptr_params = [p for p in fn.parameters if p.is_pointer and p.name]
            if not ptr_params:
                continue
            cfg = _ast_cfg_for_function(ast_ctx, fn)
            if cfg is None:
                # Parser unavailable: preserve the previous lexical fallback.
                body_lines = fn.body.splitlines()
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
                        line_no = fn.start_line + i
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
                continue

            for param in ptr_params:
                unsafe = _find_unsafe_param_deref(cfg, param.name)
                if unsafe is None:
                    continue
                line_no = unsafe.line_number
                snippet = _source_snippet(ast_ctx, line_no, unsafe.expr_str)
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    message=f"Pointer parameter '{param.name}' in function '{fn.name}' is dereferenced without a preceding NULL check.",
                    column_number=1,
                    engine="AST",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"if ({param.name} == NULL) return -EINVAL;"
                ))
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
    implementation_method = "AST dataflow analysis tracking free() state"
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
    implementation_method = "AST dataflow analysis tracking free() and subsequent pointer references"
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
                for node in cfg.nodes.values():
                    for freed_ptr in node.freed:
                        for use_node in _find_uaf_uses(cfg, node.node_id, freed_ptr):
                            use_line = use_node.line_number
                            snippet = _source_snippet(ast_ctx, use_line, use_node.expr_str)
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=use_line,
                                code_snippet=snippet,
                                message=f"Potential Use-After-Free: pointer '{freed_ptr}' was freed at line {node.line_number} and accessed here.",
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
