"""
Rules for Memory Allocation, Null-checks, Lifecycles, and Pointer Safety.
"""

import re
from typing import List, Optional
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine
from ..ast_analyzer import CASTContext, CFunction


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

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        alloc_fn_names = {"malloc", "calloc", "realloc", "aligned_alloc"}

        for fn in ast_ctx.functions:
            if fn.cfg_nodes:
                alloc_nodes = [n for n in fn.cfg_nodes if n.kind == "allocation" and n.target_var]

                for alloc_node in alloc_nodes:
                    ptr_name = alloc_node.target_var
                    line_no = alloc_node.line_number
                    checked = False
                    start_idx = fn.cfg_nodes.index(alloc_node)
                    for next_node in fn.cfg_nodes[start_idx + 1:]:
                        if ptr_name in next_node.null_checked_vars:
                            checked = True
                            break
                        if next_node.kind not in ("if_cond", "while_cond", "for_cond", "switch_cond") and ptr_name in next_node.read_vars:
                            break

                    if not checked:
                        snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else alloc_node.expr_str
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Return value of dynamic memory allocation for '{ptr_name}' is not checked for NULL before use.",
                            column_number=1,
                            engine="AST",
                            auto_fix_replacement=f"if ({ptr_name} == NULL) {{\n    return -1; // Handle out-of-memory\n}}"
                        ))
            else:
                body_lines = fn.body.splitlines()
                depths = _brace_depths(body_lines)
                alloc_regex = re.compile(r'\b(\w+)\s*=\s*(?:\([^\)]+\)\s*)?(?:malloc|calloc|realloc|aligned_alloc)\s*\(')
                for i, line in enumerate(body_lines):
                    line_no = fn.start_line + 1 + i
                    m = alloc_regex.search(line)
                    if m:
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
                                auto_fix_replacement=f"if ({ptr_name} == NULL) {{\n    return -1; // Handle out-of-memory\n}}"
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
            ptr_params = [p for p in fn.parameters if p.is_pointer]
            if not ptr_params:
                continue

            body_lines = fn.body.splitlines()
            for param in ptr_params:
                p_name = param.name
                # Look if parameter is checked in first 5 lines
                checked = False
                for line in body_lines[:min(6, len(body_lines))]:
                    if re.search(rf'\bif\s*\([^)]*?\b{re.escape(p_name)}\s*(?:==\s*NULL|!=\s*NULL|==\s*0|!=\s*0)\b', line) or \
                       re.search(rf'\bif\s*\(\s*!{re.escape(p_name)}\b', line) or \
                       re.search(rf'\bassert\s*\([^)]*?\b{re.escape(p_name)}\b', line):
                        checked = True
                        break

                if not checked:
                    # Look for immediate dereference in function body: *p, p->field, p[i]
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
                                auto_fix_replacement=f"if ({p_name} == NULL) return -EINVAL;"
                            ))
                            break  # Report first dereference per parameter
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
    analysis_engine = AnalysisEngine.HYBRID

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
                    auto_fix_replacement=line_content.replace(f"{v_name};", f"{v_name} = NULL;")
                ))
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

    MAX_LOOKAHEAD_LINES = 200

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            if fn.cfg_nodes:
                for idx, node in enumerate(fn.cfg_nodes):
                    if node.freed_vars:
                        for freed_ptr in node.freed_vars:
                            free_line = node.line_number
                            for future_node in fn.cfg_nodes[idx + 1:]:
                                if freed_ptr in future_node.written_vars:
                                    break
                                if freed_ptr in future_node.read_vars:
                                    use_line = future_node.line_number
                                    snippet = ast_ctx.source_lines[use_line - 1].strip() if use_line <= len(ast_ctx.source_lines) else future_node.expr_str
                                    issues.append(self.create_issue(
                                        file_path=file_path,
                                        line_number=use_line,
                                        code_snippet=snippet,
                                        message=f"Potential Use-After-Free: pointer '{freed_ptr}' was freed at line {free_line} and accessed here.",
                                        column_number=1,
                                        engine="AST",
                                        auto_fix_replacement=f"// Ensure {freed_ptr} is set to NULL after free() and not accessed"
                                    ))
                                    break
            else:
                body_lines = fn.body.splitlines()
                depths = _brace_depths(body_lines)
                for i, line in enumerate(body_lines):
                    line_no = fn.start_line + 1 + i
                    free_match = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', line)
                    if free_match:
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
                                    auto_fix_replacement=f"// Ensure {freed_ptr} is set to NULL after free() and not accessed"
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
            for v_name, var in fn.variables.items():
                if not var.has_initializer and not var.is_pointer and not var.is_volatile:
                    # Check if declaration line was bare uninitialized
                    decl_line_content = ast_ctx.source_lines[var.declaration_line - 1] if var.declaration_line <= len(ast_ctx.source_lines) else ""
                    if "=" not in decl_line_content and "{" not in decl_line_content:
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=var.declaration_line,
                            code_snippet=decl_line_content,
                            message=f"Local variable '{v_name}' is declared without initialization. Initialize at declaration to prevent reading stack garbage.",
                            column_number=1,
                            engine="AST",
                            auto_fix_replacement=decl_line_content.replace(f"{v_name};", f"{v_name} = 0;")
                        ))
        return issues


class UnsafeSensitiveMemoryClearingRule(BaseRule):
    rule_id = "CGULL-008"
    name = "Unsafe Sensitive Memory Clearing"
    impact = Severity.HIGH
    category = RuleCategory.CRYPTO
    description = "Flag memset() used on sensitive local buffers just before scope exit/return, which optimizing compilers can silently eliminate (Dead Store Elimination)."
    implementation_method = "AST parsing to track buffer scope exit and subsequent reads"
    implementation_complexity = "High"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-14"
    remediation_suggestion = "Use non-optimizable memory wipe functions such as explicit_bzero(), memset_s(), or SecureZeroMemory() instead of memset()."
    sample_vulnerable_code = "char password[64];\n// ... cryptographic operations ...\nmemset(password, 0, sizeof(password));\nreturn 0; // Compiler dead-store optimizer may erase memset!"
    sample_remediated_code = "explicit_bzero(password, sizeof(password)); // Or memset_s(password, sizeof(password), 0, sizeof(password));"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # memset(key, 0, len) followed within 3 lines by return or }
        m = re.search(r'\bmemset\s*\(\s*(\w+)\s*,\s*0\s*,\s*([^)]+)\)', line_content)
        if m:
            buf_name = m.group(1)
            # Check if name is sensitive or near return
            is_sensitive_name = any(k in buf_name.lower() for k in ['key', 'secret', 'pass', 'token', 'auth', 'hash', 'iv', 'pin', 'cred', 'buf'])
            is_near_return = False
            for offset in range(1, 4):
                if line_number - 1 + offset < len(source_lines):
                    next_l = source_lines[line_number - 1 + offset]
                    if "return" in next_l or next_l.strip() == "}":
                        is_near_return = True
                        break

            if is_sensitive_name or is_near_return:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Potentially unsafe memory wipe using memset('{buf_name}', 0, ...). Compilers frequently optimize out memset prior to return (Dead Store Elimination / CWE-14).",
                    column_number=m.start() + 1,
                    engine="Regex",
                    auto_fix_replacement=f"explicit_bzero({buf_name}, {m.group(2).strip()});"
                ))
        return issues
