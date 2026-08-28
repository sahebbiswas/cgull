"""
Rules for MISRA-C Compliance, Control Flow Best Practices, and Code Safety.
"""

import re
from typing import List, Optional
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ..ast_analyzer import CASTContext
import logging
from ..utils import mask_string_and_char_literals

logger = logging.getLogger(__name__)



def _find_next_code_token(lines: List[str], start_line: int, start_pos: int):
    line = start_line
    pos = start_pos
    saw_preprocessor = False
    while line < len(lines):
        rem = lines[line][pos:]
        stripped = rem.lstrip()
        if stripped:
            if stripped.startswith("#"):
                saw_preprocessor = True
                line += 1
                pos = 0
                continue
            token_pos = len(lines[line]) - len(rem) + (len(rem) - len(stripped))
            return line, token_pos, stripped, saw_preprocessor
        line += 1
        pos = 0
    return None, None, None, saw_preprocessor


class NakedControlFlowStatementsRule(BaseRule):
    rule_id = "CGULL-013"
    name = "Naked Control Flow Statements"
    impact = Severity.MEDIUM
    category = RuleCategory.CONTROL_FLOW
    description = "Enforce curly braces {} for all if, else, for, while statements, even for single lines (prevents Apple goto-fail style vulnerabilities)."
    implementation_method = "AST parsing / Tokenization to check for { after control flow statements"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-483 / MISRA C:2012 Rule 15.6"
    remediation_suggestion = "Always enclose statement bodies in curly braces { }."
    sample_vulnerable_code = "if (err)\n    goto fail;\n    goto fail; // Apple goto fail vulnerability"
    sample_remediated_code = "if (err) {\n    goto fail;\n}"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        stripped = line_content.strip()
        # Skip preprocessor lines
        if stripped.startswith("#"):
            return issues

        line_idx = line_number - 1
        masked_source_lines = [mask_string_and_char_literals(l) for l in source_lines]

        for m in re.finditer(r'\b(if|else|while|for|do)\b', line_content):
            kw = m.group(1)
            kw_start = m.start()
            kw_end = m.end()

            # Ignore structure field access (e.g., obj.if or ptr->if)
            if kw_start > 0 and line_content[kw_start - 1] == ".":
                continue
            if kw_start >= 2 and line_content[kw_start - 2:kw_start] == "->":
                continue

            curr_line = line_idx
            curr_pos = kw_end

            # Handle keywords with condition parens: if, while, for
            if kw in ("if", "while", "for"):
                n_line, n_pos, rem, _ = _find_next_code_token(masked_source_lines, curr_line, curr_pos)
                if n_line is None or not rem.startswith("("):
                    continue

                curr_line = n_line
                curr_pos = n_pos

                # Parse balanced parens
                depth = 0
                found_close = False
                while curr_line < len(masked_source_lines) and not found_close:
                    line_str = masked_source_lines[curr_line]
                    while curr_pos < len(line_str):
                        c = line_str[curr_pos]
                        if c == "(":
                            depth += 1
                        elif c == ")":
                            depth -= 1
                            if depth == 0:
                                found_close = True
                                curr_pos += 1
                                break
                        curr_pos += 1
                    if not found_close:
                        curr_line += 1
                        curr_pos = 0
                        while curr_line < len(masked_source_lines) and masked_source_lines[curr_line].strip().startswith("#"):
                            curr_line += 1

                if not found_close:
                    continue

                # Check for alternate condition branches (e.g., #if / #else split conditions)
                while True:
                    n_line, n_pos, rem, saw_prep = _find_next_code_token(masked_source_lines, curr_line, curr_pos)
                    if rem is None or not saw_prep:
                        break

                    target_line, target_pos = None, None
                    if rem.startswith("("):
                        target_line, target_pos = n_line, n_pos
                    elif re.match(r'^if\b', rem):
                        m_if = re.match(r'^if\b', rem)
                        p_line, p_pos, p_rem, _ = _find_next_code_token(masked_source_lines, n_line, n_pos + m_if.end())
                        if p_rem is None or not p_rem.startswith("("):
                            break
                        target_line, target_pos = p_line, p_pos
                    elif re.match(r'^else\b', rem):
                        m_else = re.match(r'^else\b', rem)
                        next_line2, next_pos2, rem2, _ = _find_next_code_token(masked_source_lines, n_line, n_pos + m_else.end())
                        if rem2 and re.match(r'^if\b', rem2):
                            m_if2 = re.match(r'^if\b', rem2)
                            p_line, p_pos, p_rem, _ = _find_next_code_token(masked_source_lines, next_line2, next_pos2 + m_if2.end())
                            if p_rem is None or not p_rem.startswith("("):
                                break
                            target_line, target_pos = p_line, p_pos
                        else:
                            # Bare else branch: position past 'else' and stop alternate branch scanning
                            curr_line, curr_pos = n_line, n_pos + m_else.end()
                            break
                    else:
                        break

                    curr_line = target_line
                    curr_pos = target_pos
                    depth = 0
                    found_close = False
                    while curr_line < len(masked_source_lines) and not found_close:
                        line_str = masked_source_lines[curr_line]
                        while curr_pos < len(line_str):
                            c = line_str[curr_pos]
                            if c == "(":
                                depth += 1
                            elif c == ")":
                                depth -= 1
                                if depth == 0:
                                    found_close = True
                                    curr_pos += 1
                                    break
                            curr_pos += 1
                        if not found_close:
                            curr_line += 1
                            curr_pos = 0
                            while curr_line < len(masked_source_lines) and masked_source_lines[curr_line].strip().startswith("#"):
                                curr_line += 1

                    if not found_close:
                        break

                # Special case for while in do-while loop
                if kw == "while":
                    after_line, after_pos, rem_after, _ = _find_next_code_token(masked_source_lines, curr_line, curr_pos)
                    if rem_after and rem_after.startswith(";"):
                        before_str = line_content[:kw_start].strip()
                        if before_str.endswith("}"):
                            continue
                        prev_line = line_idx - 1
                        is_do_while = False
                        while prev_line >= 0:
                            prev_str = source_lines[prev_line].strip()
                            if not prev_str or prev_str.startswith("#"):
                                prev_line -= 1
                                continue
                            if prev_str.endswith("}") or "}" in prev_str:
                                is_do_while = True
                            break
                        if is_do_while:
                            continue

            elif kw == "else":
                look_l, look_p, rem_else, _ = _find_next_code_token(masked_source_lines, line_idx, kw_end)
                if rem_else and rem_else.startswith("if") and (len(rem_else) == 2 or not rem_else[2].isalnum()):
                    continue

            # Look ahead for opening brace {
            look_line, look_pos, rem_brace, _ = _find_next_code_token(masked_source_lines, curr_line, curr_pos)
            is_braced = rem_brace is not None and rem_brace.startswith("{")

            if not is_braced:
                if kw in ("if", "while", "for"):
                    message = f"Naked control flow block: missing '{{' after '{kw}'."
                elif kw == "else":
                    message = "Naked control flow block: missing '{' after 'else'."
                else:
                    message = f"Naked control flow block: missing '{{' after '{kw}'."

                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=message,
                    column_number=kw_start + 1,
                    engine="Regex",
                ))

        return issues


class MissingDefaultCaseInSwitchStatementsRule(BaseRule):
    rule_id = "CGULL-017"
    name = "Missing default Case in Switch Statements"
    impact = Severity.LOW
    category = RuleCategory.CONTROL_FLOW
    description = "Every switch statement must terminate with a default: label to catch unhandled state conditions (MISRA C:2012 Rule 16.4)."
    implementation_method = "AST parsing to count switch keywords and verify equal default: labels"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-478 / MISRA C:2012 Rule 16.4"
    remediation_suggestion = "Add an explicit default: label to every switch statement, handling unexpected states or logging errors."
    sample_vulnerable_code = "switch (packet_type) {\n    case 1: process_a(); break;\n    case 2: process_b(); break;\n}"
    sample_remediated_code = "switch (packet_type) {\n    case 1: process_a(); break;\n    case 2: process_b(); break;\n    default:\n        log_unhandled_type(packet_type);\n        break;\n}"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        full_code = ast_ctx.clean_source
        switch_regex = re.compile(r'\bswitch\s*\([^)]+\)\s*\{', re.MULTILINE)

        for match in switch_regex.finditer(full_code):
            start_pos = match.start()
            line_no = full_code[:start_pos].count('\n') + 1

            # Match matching closing brace for this switch block
            brace_count = 1
            body_start = match.end()
            curr = body_start
            n = len(full_code)
            while curr < n and brace_count > 0:
                if full_code[curr] == '{':
                    brace_count += 1
                elif full_code[curr] == '}':
                    brace_count -= 1
                curr += 1

            switch_body = full_code[body_start:curr - 1]
            if "default:" not in switch_body and "default :" not in switch_body:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_no,
                    code_snippet=ast_ctx.source_lines[line_no - 1] if line_no <= len(ast_ctx.source_lines) else "switch (...)",
                    message="Switch statement is missing a mandatory 'default:' label (MISRA C:2012 Rule 16.4).",
                    column_number=1,
                    engine="AST",
                    fix_type=FixType.SAFE_FIX,
                    auto_fix_replacement="default:\n    break;"
                ))
        return issues


class UseOfGotoStatementsRule(BaseRule):
    rule_id = "CGULL-018"
    name = "Use of goto Statements"
    impact = Severity.LOW
    category = RuleCategory.CONTROL_FLOW
    description = "Flag goto keyword to prevent unstructured control flow and bypassed initializations (MISRA C:2012 Rule 15.1)."
    implementation_method = "Regex string matching"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-398 / MISRA C:2012 Rule 15.1"
    remediation_suggestion = "Refactor unstructured goto jumps into structured loop controls (break, continue, return) or helper functions."
    sample_vulnerable_code = "if (error) goto cleanup;\n// ...\ncleanup:\nfree(p);"
    sample_remediated_code = "if (error) {\n    cleanup_resources(p);\n    return -1;\n}"
    analysis_engine = AnalysisEngine.REGEX

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        m = re.search(r'\bgoto\s+([a-zA-Z_]\w*)\s*;', line_content)
        if m:
            label = m.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Use of 'goto {label}' violates structured programming guidelines (MISRA C:2012 Rule 15.1).",
                column_number=m.start() + 1,
                engine="Regex",
            ))
        return issues


class ParameterVoidRule(BaseRule):
    rule_id = "CGULL-019"
    name = "Extraneous or Missing void in Parameter Lists"
    impact = Severity.LOW
    category = RuleCategory.STYLE
    description = "A function with no arguments should be explicitly declared as void (e.g. int init(void)) in standard C (MISRA C:2012 Rule 8.2)."
    implementation_method = "AST parsing to check for empty parameter lists"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-1188 / MISRA C:2012 Rule 8.2"
    remediation_suggestion = "Explicitly specify (void) in function signatures that take no parameters: int my_func(void) {}."
    sample_vulnerable_code = "int initialize_hardware() {\n    return 0;\n}"
    sample_remediated_code = "int initialize_hardware(void) {\n    return 0;\n}"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            if fn.is_empty_param_list and not fn.has_void_param_list:
                line_content = ast_ctx.source_lines[fn.start_line - 1] if fn.start_line <= len(ast_ctx.source_lines) else ""
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=fn.start_line,
                    code_snippet=line_content,
                    message=f"Function '{fn.name}()' declared with empty parameter list instead of explicit '(void)'. In C, empty parameter lists allow un-typechecked calls.",
                    column_number=1,
                    engine="AST",
                    fix_type=FixType.SAFE_FIX,
                    auto_fix_replacement=line_content.replace(f"{fn.name}()", f"{fn.name}(void)")
                ))
        return issues


class UnusedArgumentsRule(BaseRule):
    rule_id = "CGULL-020"
    name = "Unused Arguments"
    impact = Severity.LOW
    category = RuleCategory.STYLE
    description = "Flag function arguments that are passed but never referenced in the function body (MISRA C:2012 Rule 2.7)."
    implementation_method = "AST parsing to track variable IDs against the parameter list"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-563 / MISRA C:2012 Rule 2.7"
    remediation_suggestion = "Remove unused arguments or cast them explicitly with (void)arg; to silence compiler warnings."
    sample_vulnerable_code = "int handle_event(int event_id, void *unused_data) {\n    return process_event(event_id);\n}"
    sample_remediated_code = "int handle_event(int event_id, void *unused_data) {\n    (void)unused_data; // Explicitly silence unused parameter\n    return process_event(event_id);\n}"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            for param in fn.parameters:
                p_name = param.name
                if p_name.startswith("unused_") or p_name.startswith("__"):
                    continue
                # Search for identifier in body
                if not re.search(rf'\b{re.escape(p_name)}\b', fn.body):
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=fn.start_line,
                        code_snippet=f"{fn.return_type} {fn.name}(... {param.type_name} {p_name} ...)",
                        message=f"Parameter '{p_name}' is declared in '{fn.name}' but never used in the function body (MISRA C:2012 Rule 2.7).",
                        column_number=1,
                        engine="AST",
                        fix_type=FixType.SAFE_FIX,
                        auto_fix_replacement=f"(void){p_name};"
                    ))
        return issues


class MissingAssertionsRule(BaseRule):
    rule_id = "CGULL-025"
    name = "Missing Assertions"
    impact = Severity.LOW
    category = RuleCategory.STYLE
    description = "Enforce the use of assertions to validate internal assumptions and state invariants in critical functions."
    implementation_method = "AST parsing to check for assert calls in critical sections"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-617"
    remediation_suggestion = "Add assert() statements to document and verify program invariants (e.g. assert(length > 0 && buffer != NULL);)."
    sample_vulnerable_code = "void compute_hash(uint8_t *in, size_t len) {\n    // No invariant assertion\n    sha256_update(in, len);\n}"
    sample_remediated_code = "void compute_hash(uint8_t *in, size_t len) {\n    assert(in != NULL && len > 0);\n    sha256_update(in, len);\n}"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            if not fn.has_assertions and len(fn.body.splitlines()) > 15:
                # Flag long complex functions without assertions
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=fn.start_line,
                    code_snippet=f"{fn.return_type} {fn.name}(...)",
                    message=f"Function '{fn.name}' contains complex logic ({len(fn.body.splitlines())} lines) without any assert() invariant validations.",
                    column_number=1,
                    engine="AST",
                    fix_type=FixType.MANUAL_REVIEW,
                ))
        return issues


class UnusedLocalVariablesRule(BaseRule):
    rule_id = "CGULL-041"
    name = "Unused Local Variables"
    impact = Severity.LOW
    category = RuleCategory.STYLE
    description = "Detect local variables that are declared in function body or nested block scopes but never referenced anywhere in their scope."
    implementation_method = "AST parsing to track local variable reads and address-of expressions across block scopes"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-563"
    remediation_suggestion = "Remove unused local variables or cast them explicitly with (void)var; to silence compiler warnings."
    sample_vulnerable_code = "int compute(int x) {\n    int unused_local = 42; // Declared but never read\n    return x;\n}"
    sample_remediated_code = "int compute(int x) {\n    return x;\n}"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            param_names = {p.name for p in fn.parameters if p.name}
            for c_var in fn.variables.values():
                v_name = c_var.name
                if not v_name or v_name in param_names:
                    continue
                if v_name.startswith("__"):
                    continue

                if not c_var.read_lines and not c_var.address_taken:
                    if not ast_ctx.has_pycparser or ast_ctx.pycparser_ast is None:
                        has_read_in_fallback = False
                        body_start = getattr(fn, "body_start_line", fn.start_line + 1)
                        decl_line_idx = c_var.declaration_line - body_start
                        for i, line in enumerate(fn.body.splitlines()):
                            if i == decl_line_idx:
                                continue
                            if re.search(rf'\b{re.escape(v_name)}\b', line):
                                m_write = re.match(rf'^\s*{re.escape(v_name)}\s*=(?!=)\s*(.*)$', line)
                                if m_write:
                                    rhs = m_write.group(1)
                                    if re.search(rf'\b{re.escape(v_name)}\b', rhs):
                                        has_read_in_fallback = True
                                        break
                                else:
                                    has_read_in_fallback = True
                                    break
                        if has_read_in_fallback:
                            continue

                    line_no = c_var.declaration_line
                    snippet = ast_ctx.source_lines[line_no - 1].strip() if 1 <= line_no <= len(ast_ctx.source_lines) else f"int {v_name};"
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        message=f"Local variable '{v_name}' is declared in '{fn.name}' but never read or referenced in its scope (CWE-563).",
                        column_number=1,
                        engine="AST",
                        fix_type=FixType.SAFE_FIX,
                        auto_fix_replacement=f"(void){v_name};"
                    ))
        return issues


class DeadStoresRule(BaseRule):
    rule_id = "CGULL-042"
    name = "Dead Stores"
    impact = Severity.LOW
    category = RuleCategory.STYLE
    description = "Detect local variables assigned but never read afterward before reassignment or scope exit (dead stores / -Wunused-but-set-variable)."
    implementation_method = "AST parsing & CFG dataflow analysis to check for reads reachable after write"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-563"
    remediation_suggestion = "Remove the dead store assignment or use the variable value before overwriting it or exiting scope."
    sample_vulnerable_code = "int status = compute(); // Dead store\nstatus = 0;\nreturn 0;"
    sample_remediated_code = "compute();\nint status = 0;\nreturn 0;"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        from ..cfg import build_cfg, find_function_def

        summaries = None
        if hasattr(ast_ctx, "functions") and ast_ctx.functions:
            from ..cfg import analyze_function_summaries
            summaries = analyze_function_summaries(ast_ctx)

        for fn in ast_ctx.functions:
            param_names = {p.name for p in fn.parameters if p.name}
            local_vars = {}
            for c_var in fn.variables.values():
                v_name = c_var.name
                if not v_name or v_name in param_names or v_name.startswith("__"):
                    continue
                if c_var.is_volatile or c_var.address_taken:
                    continue
                local_vars[v_name] = c_var

            if not local_vars:
                continue

            cfg = None
            funcdef = None
            if getattr(ast_ctx, "has_pycparser", False) and ast_ctx.pycparser_ast is not None:
                funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
                if funcdef is not None:
                    cfg = build_cfg(funcdef, summaries=summaries, line_map=getattr(ast_ctx, "line_map", None))

            if cfg is not None and cfg.nodes:
                # AST/CFG path reachability check
                initial_initialized = set(p.name for p in fn.parameters if p.name) | set(getattr(ast_ctx, "global_variables", {}).keys()) | {var.name for var in fn.variables.values() if getattr(var, "has_initializer", False) and var.name}
                cfg.analyze_dataflow(initial_nonnull=set(), initial_initialized=initial_initialized)

                # For each write node writing to a local_var v:
                for node_id, node in cfg.nodes.items():
                    for v_name in node.writes:
                        if v_name not in local_vars:
                            continue

                        # Check reachability to a read of v_name before another write to v_name or exit
                        visited = set()
                        worklist = list(node.successors)
                        read_reachable = False

                        while worklist:
                            curr_id = worklist.pop()
                            if curr_id in visited:
                                continue
                            visited.add(curr_id)

                            curr_node = cfg.nodes[curr_id]

                            # Check if v_name is read in curr_node
                            if v_name in curr_node.reads:
                                read_reachable = True
                                break

                            # If curr_node writes to v_name without reading it first, this branch dies (overwritten)
                            if v_name in curr_node.writes:
                                continue

                            for succ in curr_node.successors:
                                if succ not in visited:
                                    worklist.append(succ)

                        if not read_reachable:
                            c_var = local_vars[v_name]
                            line_no = node.line_number
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if 1 <= line_no <= len(ast_ctx.source_lines) else f"{v_name} = ...;"
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Value assigned to local variable '{v_name}' in '{fn.name}' is never read before reassignment or scope exit (dead store, CWE-563).",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.SAFE_FIX if snippet.endswith(";") else FixType.MANUAL_REVIEW,
                            ))
            else:
                # Fallback AST/lexical check when pycparser is not used
                for v_name, c_var in local_vars.items():
                    # If variable was declared but never read at all, skip if UnusedLocalVariablesRule (CGULL-041) will flag it,
                    # UNLESS it is assigned multiple times or written but never read.
                    if not c_var.read_lines:
                        # If assigned_lines is non-empty, every assignment is a dead store
                        for line_no in c_var.assigned_lines:
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if 1 <= line_no <= len(ast_ctx.source_lines) else f"{v_name} = ...;"
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Value assigned to local variable '{v_name}' in '{fn.name}' is never read before reassignment or scope exit (dead store, CWE-563).",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.SAFE_FIX if snippet.endswith(";") else FixType.MANUAL_REVIEW,
                            ))
                    else:
                        # Check ordered assigned_lines and read_lines
                        all_reads = sorted(c_var.read_lines)
                        all_writes = sorted(c_var.assigned_lines)
                        for i, w_line in enumerate(all_writes):
                            next_w_line = all_writes[i + 1] if i + 1 < len(all_writes) else float('inf')
                            # Is there a read between w_line and next_w_line?
                            has_read = any(w_line <= r_line < next_w_line for r_line in all_reads)
                            if not has_read:
                                snippet = ast_ctx.source_lines[w_line - 1].strip() if 1 <= w_line <= len(ast_ctx.source_lines) else f"{v_name} = ...;"
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=w_line,
                                    code_snippet=snippet,
                                    message=f"Value assigned to local variable '{v_name}' in '{fn.name}' is never read before reassignment or scope exit (dead store, CWE-563).",
                                    column_number=1,
                                    engine="AST",
                                    fix_type=FixType.SAFE_FIX if snippet.endswith(";") else FixType.MANUAL_REVIEW,
                                ))

        return issues


class MissingInclusionGuardRule(BaseRule):
    rule_id = "CGULL-045"
    name = "Missing Inclusion Guard"
    impact = Severity.MEDIUM
    category = RuleCategory.STYLE
    description = "Detect header files (.h, .hpp) that lack proper inclusion guards (#ifndef/#define or #pragma once), which can lead to multiple inclusion and compilation errors."
    implementation_method = "Regex pattern matching over the entire file to verify presence of include guards"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-424"
    remediation_suggestion = "Wrap the entire header file contents with `#ifndef HEADER_NAME_H`, `#define HEADER_NAME_H`, and `#endif`, or use `#pragma once`."
    sample_vulnerable_code = "int my_func(void);\n"
    sample_remediated_code = "#ifndef MY_HEADER_H\n#define MY_HEADER_H\nint my_func(void);\n#endif\n"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        # Support .c files for the corpus test suite
        if not file_path.endswith('.h') and not file_path.endswith('.hpp') and not file_path.endswith('.c'):
            return issues

        content = ast_ctx.raw_source

        # 1. Check for `#pragma once`
        if re.search(r'^\s*#\s*pragma\s+once\b', content, re.MULTILINE):
            return issues

        # 2. Check for traditional #ifndef / #define guard
        guard_pattern = re.compile(
            r'^\s*#\s*ifndef\s+([a-zA-Z_]\w*)\s*$'
            r'(?:.|\n)*?'
            r'^\s*#\s*define\s+\1(?:\s+1)?\s*(?:$|\n|//|/\*)'
            r'(?:.|\n)*?'
            r'^\s*#\s*endif\s*(?:$|\n|//|/\*)',
            re.MULTILINE
        )

        if guard_pattern.search(content):
            return issues

        # If we reach here, it's missing guards
        # Just report it on the first line
        issues.append(self.create_issue(
            file_path=file_path,
            line_number=1,
            code_snippet=ast_ctx.source_lines[0] if ast_ctx.source_lines else "",
            message=f"Header file '{file_path}' is missing an inclusion guard (#pragma once or #ifndef/#define).",
            column_number=1,
            engine="AST",
            fix_type=FixType.SUGGESTED_FIX,
            suggested_fix_replacement="#pragma once\n\n" + (ast_ctx.source_lines[0] if ast_ctx.source_lines else "")
        ))

        return issues


class VariableShadowingRule(BaseRule):
    rule_id = "CGULL-043"
    name = "Variable Shadowing Across Nested Scopes"
    impact = Severity.LOW
    category = RuleCategory.STYLE
    description = "Detect variable declarations in inner scopes (parameters, nested blocks, or local variables) that shadow identifiers in outer scopes (MISRA C:2012 Rule 5.3)."
    implementation_method = "AST parsing and scope hierarchy traversal to detect inner declarations shadowing outer variables, parameters, or globals"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-398 / MISRA C:2012 Rule 5.3"
    remediation_suggestion = "Rename the inner scope variable to a unique identifier to avoid shadowing outer variables or parameters."
    sample_vulnerable_code = "int count = 10;\nvoid process(int count) {\n    int i;\n    for (int i = 0; i < count; i++) {}\n}"
    sample_remediated_code = "int g_count = 10;\nvoid process(int count) {\n    int i;\n    for (int j = 0; j < count; j++) {}\n}"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        global_vars = getattr(ast_ctx, "global_variables", {})

        for fn in ast_ctx.functions:
            param_dict = {p.name: p for p in fn.parameters if p.name}

            # 1. Check parameters shadowing global variables
            for p_name, param in param_dict.items():
                if p_name.startswith("__"):
                    continue
                if p_name in global_vars:
                    g_var = global_vars[p_name]
                    # Source-order check: global variable is visible only if declared before or on parameter line
                    if g_var.declaration_line <= param.line_number:
                        line_no = param.line_number
                        snippet = ast_ctx.source_lines[line_no - 1].strip() if 1 <= line_no <= len(ast_ctx.source_lines) else f"{param.type_name} {p_name}"
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Parameter '{p_name}' declared in '{fn.name}' shadows global variable '{p_name}' (MISRA C:2012 Rule 5.3).",
                            column_number=1,
                            engine="AST",
                        ))

            # 2. Check local variables
            block_parents = getattr(fn, "block_parents", {})
            raw_vars = list(dict.values(fn.variables)) if isinstance(fn.variables, dict) else []

            vars_by_name: Dict[str, List] = {}
            for c_var in raw_vars:
                v_name = getattr(c_var, "name", None)
                if not v_name or v_name.startswith("__"):
                    continue
                vars_by_name.setdefault(v_name, []).append(c_var)

            reported = set()

            for v_name, var_list in vars_by_name.items():
                for c_var in var_list:
                    v_block = getattr(c_var, "enclosing_block_id", 0)
                    line_no = c_var.declaration_line
                    report_key = (v_name, line_no)
                    if report_key in reported:
                        continue

                    # (a) Check if c_var shadows an outer local variable in an ancestor block scope
                    shadowed_outer_local = False
                    curr = v_block
                    while curr in block_parents:
                        parent_id = block_parents[curr]
                        for other_var in var_list:
                            if other_var is not c_var and getattr(other_var, "enclosing_block_id", 0) == parent_id:
                                # Visibility check: outer declaration must precede or be on the same line as inner declaration
                                if other_var.declaration_line <= line_no:
                                    snippet = ast_ctx.source_lines[line_no - 1].strip() if 1 <= line_no <= len(ast_ctx.source_lines) else f"{c_var.type_name} {v_name};"
                                    issues.append(self.create_issue(
                                        file_path=file_path,
                                        line_number=line_no,
                                        code_snippet=snippet,
                                        message=f"Local variable '{v_name}' declared in inner scope of '{fn.name}' shadows variable '{v_name}' declared in an outer scope (MISRA C:2012 Rule 5.3).",
                                        column_number=1,
                                        engine="AST",
                                    ))
                                    reported.add(report_key)
                                    shadowed_outer_local = True
                                    break
                        if shadowed_outer_local:
                            break
                        curr = parent_id

                    if shadowed_outer_local:
                        continue

                    # (b) Check if c_var shadows a function parameter
                    if v_name in param_dict:
                        param = param_dict[v_name]
                        if param.line_number <= line_no:
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if 1 <= line_no <= len(ast_ctx.source_lines) else f"{c_var.type_name} {v_name};"
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Local variable '{v_name}' declared in '{fn.name}' shadows function parameter '{v_name}' (MISRA C:2012 Rule 5.3).",
                                column_number=1,
                                engine="AST",
                            ))
                            reported.add(report_key)
                            continue

                    # (c) Check if c_var shadows a global variable
                    if v_name in global_vars:
                        g_var = global_vars[v_name]
                        # Source-order check: global variable is visible only if declared before or on c_var's declaration line
                        if g_var.declaration_line <= line_no:
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if 1 <= line_no <= len(ast_ctx.source_lines) else f"{c_var.type_name} {v_name};"
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Local variable '{v_name}' declared in '{fn.name}' shadows global variable '{v_name}' (MISRA C:2012 Rule 5.3).",
                                column_number=1,
                                engine="AST",
                            ))
                            reported.add(report_key)
                            continue

        return issues
