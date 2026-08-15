"""
Rules for MISRA-C Compliance, Control Flow Best Practices, and Code Safety.
"""

import re
from typing import List, Optional
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine
from ..ast_analyzer import CASTContext


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

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str]) -> List[Issue]:
        issues = []
        # Check if line has if (...) or while (...) or for (...) without { at end or next line
        stripped = line_content.strip()
        # Single line if without brace: e.g. if (x) do_something();
        m = re.match(r'^(if\s*\([^)]+\)|while\s*\([^)]+\)|for\s*\([^)]+\))\s+([^{;]+;)', stripped)
        if m:
            ctrl = m.group(1)
            stmt = m.group(2)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Naked control flow statement without enclosing curly braces '{{ }}' in '{ctrl}'. Single-line statements are error-prone.",
                column_number=1,
                engine="Regex",
                auto_fix_replacement=f"{ctrl} {{\n    {stmt}\n}}"
            ))
        elif re.match(r'^(if\s*\([^)]+\)|while\s*\([^)]+\)|for\s*\([^)]+\)|else)$', stripped):
            # Check next line
            if line_number < len(source_lines):
                next_line = source_lines[line_number].strip()
                if not next_line.startswith('{'):
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=f"Naked control flow block: '{stripped}' lacks enclosing '{{' on the next line.",
                        column_number=1,
                        engine="Regex",
                        auto_fix_replacement=f"{stripped} {{\n    {next_line}\n}}"
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

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str]) -> List[Issue]:
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
                    auto_fix_replacement="assert(/* invariant */);"
                ))
        return issues
