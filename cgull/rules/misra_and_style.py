"""
Rules for MISRA-C Compliance, Control Flow Best Practices, and Code Safety.
"""

import re
from typing import List, Optional
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ..ast_analyzer import CASTContext
from ..utils import mask_string_and_char_literals


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
                found_paren = False
                while curr_line < len(masked_source_lines):
                    rem = masked_source_lines[curr_line][curr_pos:]
                    rem_stripped = rem.strip()
                    if rem_stripped:
                        if rem_stripped.startswith("#"):
                            curr_line += 1
                            curr_pos = 0
                            continue
                        if rem_stripped.startswith("("):
                            found_paren = True
                            curr_pos = masked_source_lines[curr_line].find("(", curr_pos)
                            break
                        else:
                            break
                    curr_line += 1
                    curr_pos = 0

                if not found_paren:
                    continue

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
                    next_line = curr_line
                    next_pos = curr_pos
                    next_char = None
                    while next_line < len(masked_source_lines):
                        rem = masked_source_lines[next_line][next_pos:].strip()
                        if rem:
                            if rem.startswith("#"):
                                next_line += 1
                                next_pos = 0
                                continue
                            next_char = rem[0]
                            break
                        next_line += 1
                        next_pos = 0

                    if next_char == "(":
                        curr_line = next_line
                        curr_pos = masked_source_lines[next_line].find("(", next_pos)

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
                    else:
                        if next_line < len(masked_source_lines) and next_char is not None:
                            curr_line = next_line
                            curr_pos = next_pos
                        break

                # Special case for while in do-while loop
                if kw == "while":
                    after_paren_line = curr_line
                    after_paren_pos = curr_pos
                    next_char_after = None
                    while after_paren_line < len(masked_source_lines):
                        rem_after = masked_source_lines[after_paren_line][after_paren_pos:].strip()
                        if rem_after:
                            if rem_after.startswith("#"):
                                after_paren_line += 1
                                after_paren_pos = 0
                                continue
                            next_char_after = rem_after[0]
                            break
                        after_paren_line += 1
                        after_paren_pos = 0
                    if next_char_after == ";":
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
                look_l = line_idx
                look_p = kw_end
                is_else_if = False
                while look_l < len(masked_source_lines):
                    rem_else = masked_source_lines[look_l][look_p:].strip()
                    if rem_else:
                        if rem_else.startswith("#"):
                            look_l += 1
                            look_p = 0
                            continue
                        if rem_else.startswith("if") and (len(rem_else) == 2 or not rem_else[2].isalnum()):
                            is_else_if = True
                        break
                    look_l += 1
                    look_p = 0
                if is_else_if:
                    continue

            # Look ahead for opening brace {
            look_line = curr_line
            look_pos = curr_pos
            is_braced = False

            while look_line < len(masked_source_lines):
                line_str = masked_source_lines[look_line][look_pos:].strip()
                if not line_str or line_str.startswith("#"):
                    look_line += 1
                    look_pos = 0
                    continue
                else:
                    if line_str.startswith("{"):
                        is_braced = True
                    else:
                        is_braced = False
                    break

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
