"""
Rules for Banned & Insecure Functions and Format Strings.
"""

import re
from typing import List, Optional
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ..ast_analyzer import CASTContext


class BannedFunctionsRule(BaseRule):
    rule_id = "CGULL-001"
    name = "Banned Functions"
    impact = Severity.HIGH
    category = RuleCategory.STRINGS
    description = "Flag the usage of legacy string/memory functions that lack bounds checking (gets, strcpy, strcat, sprintf, vsprintf, scanf %s)."
    implementation_method = "Regex string matching"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-676 / CWE-120"
    remediation_suggestion = "Replace with safe, bounds-checking alternatives: use gets_s / fgets instead of gets; strncpy_s / snprintf instead of strcpy/strcat; snprintf instead of sprintf."
    sample_vulnerable_code = "char dest[32];\ngets(dest);\nstrcpy(dest, src);\nsprintf(dest, \"%s\", input);"
    sample_remediated_code = "char dest[32];\nfgets(dest, sizeof(dest), stdin);\nsnprintf(dest, sizeof(dest), \"%s\", src);"
    analysis_engine = AnalysisEngine.REGEX

    BANNED_FUNCS = {
        "gets": ("gets() allows arbitrary buffer overflow into the stack without bounds checking.", "fgets(buffer, sizeof(buffer), stdin)"),
        "strcpy": ("strcpy() does not check destination buffer size, causing stack buffer overflows.", "strncpy_s(dest, dest_size, src, _TRUNCATE) or snprintf(dest, sizeof(dest), \"%s\", src)"),
        "strcat": ("strcat() can append past the buffer boundary leading to memory corruption.", "strncat(dest, src, sizeof(dest) - strlen(dest) - 1)"),
        "sprintf": ("sprintf() writes unbounded output into the buffer.", "snprintf(dest, sizeof(dest), fmt, ...)"),
        "vsprintf": ("vsprintf() lacks buffer bounds protection.", "vsnprintf(dest, sizeof(dest), fmt, ap)"),
        "scanf": ("scanf() with unbounded %s can overflow input buffers.", "scanf(\"%31s\", dest) with explicit width specifier"),
    }

    def __init__(self, extra_banned_funcs: Optional[dict] = None):
        super().__init__()
        self.banned_funcs = dict(self.BANNED_FUNCS)
        if extra_banned_funcs:
            self.add_extra_banned_funcs(extra_banned_funcs)

    def add_extra_banned_funcs(self, extra_banned_funcs: dict) -> None:
        for fn_name, details in extra_banned_funcs.items():
            if isinstance(details, tuple):
                self.banned_funcs[fn_name] = details
            elif isinstance(details, dict):
                reason = details.get("reason", f"Banned function call '{fn_name}'")
                remediation = details.get("remediation", f"Avoid using {fn_name}()")
                self.banned_funcs[fn_name] = (reason, remediation)
            elif isinstance(details, str):
                self.banned_funcs[fn_name] = (details, f"Avoid using {fn_name}()")

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        match_target = masked_line_content or line_content
        for fn_name, (reason, fix) in self.banned_funcs.items():
            pattern = rf'\b{re.escape(fn_name)}\s*\('
            # Match against the string-literal-masked view so a banned
            # function name that only appears as text inside a string
            # literal (e.g. a log message mentioning "gets()") isn't
            # flagged as an actual call.
            m = re.search(pattern, match_target)
            if m:
                # Special check for scanf: only flag if format specifier has %s without width.
                # This needs the REAL (unmasked) format-string content, so it
                # intentionally checks line_content rather than match_target.
                if fn_name == "scanf":
                    if re.search(r'scanf\s*\(\s*"[^"]*%s[^"]*"', line_content):
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=line_content,
                            message=f"Insecure function call '{fn_name}': {reason}",
                            column_number=m.start() + 1,
                            engine="Regex",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=fix,
                        ))
                else:
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=f"Banned insecure function call '{fn_name}': {reason}",
                        column_number=m.start() + 1,
                        engine="Regex",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=fix,
                    ))
        return issues


class FormatStringRule(BaseRule):
    rule_id = "CGULL-002"
    name = "Format String Vulnerabilities"
    impact = Severity.HIGH
    category = RuleCategory.STRINGS
    description = "Detect when printing functions do not use a string literal as the format argument (e.g. printf(buffer) instead of printf(\"%s\", buffer))."
    implementation_method = "Regex matching to check if format arg is a variable"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-134"
    remediation_suggestion = "Always use a constant string literal format specifier, e.g. printf(\"%s\", buffer) instead of printf(buffer)."
    sample_vulnerable_code = "char user_input[256];\nprintf(user_input);\nsyslog(LOG_ERR, user_input);"
    sample_remediated_code = "char user_input[256];\nprintf(\"%s\", user_input);\nsyslog(LOG_ERR, \"%s\", user_input);"
    analysis_engine = AnalysisEngine.HYBRID

    PRINT_FUNCS = ["printf", "fprintf", "sprintf", "snprintf", "syslog", "vprintf", "vfprintf"]

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        match_target = masked_line_content or line_content
        # printf(var) or printf(var, ...) where first arg is not "..."
        for fn in ["printf", "vprintf"]:
            m = re.search(rf'\b{fn}\s*\(\s*([^",\s][^,\)]*)\s*\)', match_target)
            if m:
                arg = line_content[m.start(1):m.end(1)].strip()
                if not arg.startswith('"') and not arg.startswith('L"'):
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=f"Non-literal format string passed to {fn}({arg}). An attacker can inject %x, %n, or %s to leak or overwrite memory.",
                        column_number=m.start() + 1,
                        engine="Regex",
                        fix_type=FixType.SAFE_FIX,
                        auto_fix_replacement=f'{fn}("%s", {arg})'
                    ))

        # fprintf(stream, var) or syslog(priority, var)
        for fn in ["fprintf", "syslog", "dprintf"]:
            m = re.search(rf'\b{fn}\s*\(\s*[^,]+,\s*([^",\s][^,\)]*)\s*\)', match_target)
            if m:
                arg = line_content[m.start(1):m.end(1)].strip()
                if not arg.startswith('"') and not arg.startswith('L"'):
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=f"Non-literal format string passed to {fn}(..., {arg}). Format string vulnerability allows arbitrary read/write.",
                        column_number=m.start() + 1,
                        engine="Regex",
                    ))
        return issues


class UncheckedSnprintfReturnRule(BaseRule):
    rule_id = "CGULL-026"
    name = "Unchecked snprintf() Return Value"
    impact = Severity.HIGH
    category = RuleCategory.STRINGS
    description = "Flag the direct accumulation of snprintf() return value into an offset without checking for truncation. snprintf() returns the number of bytes it *would* have written, leading to underflow if used directly on truncation."
    implementation_method = "Regex string matching"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-131"
    remediation_suggestion = "Check the return value of snprintf() to ensure it is not less than zero and not greater than or equal to the buffer size before using it."
    sample_vulnerable_code = "int offset = 0;\noffset += snprintf(buf + offset, size - offset, \"%s\", str);"
    sample_remediated_code = "int offset = 0;\nint n = snprintf(buf + offset, size - offset, \"%s\", str);\nif (n < 0 || n >= size - offset) { /* handle error */ }\noffset += n;"
    analysis_engine = AnalysisEngine.REGEX

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        match_target = masked_line_content or line_content

        m = re.search(r'\b(\w+)\s*\+=\s*snprintf\s*\(', match_target)
        if m:
            var_name = m.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Direct accumulation of snprintf() return value into '{var_name}'. If snprintf truncates, it returns the intended length, leading to buffer overflow on subsequent uses.",
                column_number=m.start() + 1,
                engine="Regex",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement=f"int n = snprintf(...);\nif (n < 0 || n >= remaining_size) {{ ... }}\n{var_name} += n;"
            ))
        return issues


class UnsafeIntegerConversionsRule(BaseRule):
    rule_id = "CGULL-012"
    name = "Unsafe Integer Conversions"
    impact = Severity.MEDIUM
    category = RuleCategory.ARITHMETIC
    description = "Flag functions converting strings to integers without error reporting or overflow validation (atoi, atol, atoll, atof)."
    implementation_method = "Regex string matching (suggest strtol)"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-704 / CWE-190"
    remediation_suggestion = "Replace atoi/atol/atoll with strtol/strtoll/strtoul which provide endptr error validation and errno checking for overflow (ERANGE)."
    sample_vulnerable_code = "int port = atoi(argv[1]);\nlong val = atol(str);"
    sample_remediated_code = "char *endptr;\nerrno = 0;\nlong val = strtol(str, &endptr, 10);\nif (errno == ERANGE || *endptr != '\\0') { /* handle error */ }"
    analysis_engine = AnalysisEngine.REGEX

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        match_target = masked_line_content or line_content
        for fn in ["atoi", "atol", "atoll", "atof"]:
            m = re.search(rf'\b{fn}\s*\(([^)]+)\)', match_target)
            if m:
                arg = m.group(1).strip()
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Use of insecure conversion function '{fn}({arg})'. '{fn}' does not detect numeric overflow or invalid characters.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"strtol({arg}, &endptr, 10)"
                ))
        return issues

class CommandInjectionRule(BaseRule):
    rule_id = "CGULL-030"
    name = "Command Injection Vulnerability"
    impact = Severity.HIGH
    category = RuleCategory.CONTROL_FLOW
    description = "Flag the use of system(), popen(), or execlp/execvp (PATH-searching variants) with non-literal string arguments, which can lead to OS command injection."
    implementation_method = "AST parsing & regex to check for non-literal command arguments"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-78"
    remediation_suggestion = "Avoid shell invocation; use execve() with a fixed argv array and no shell interpretation; validate/allowlist input if a shell is unavoidable."
    sample_vulnerable_code = "char cmd[256];\nsnprintf(cmd, sizeof(cmd), \"ls %s\", user_input);\nsystem(cmd);"
    sample_remediated_code = "char *args[] = {\"ls\", user_input, NULL};\nexecve(\"/bin/ls\", args, envp);"
    analysis_engine = AnalysisEngine.HYBRID

    TARGET_FUNCS = {"system", "popen", "execlp", "execvp", "execvpe", "execlpe"}

    @staticmethod
    def _is_type_decl(arg: str) -> bool:
        first_word = arg.strip().split()[0] if arg.strip().split() else ""
        return first_word in {"const", "char", "int", "void", "struct", "FILE", "unsigned", "signed", "long", "short"}

    @staticmethod
    def _is_literal_arg(arg: str) -> bool:
        s = arg.strip()
        return (
            (s.startswith('"') and s.endswith('"')) or
            (s.startswith('L"') and s.endswith('"')) or
            (s.startswith('u8"') and s.endswith('"')) or
            (s.startswith('u"') and s.endswith('"')) or
            (s.startswith('U"') and s.endswith('"'))
        )

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            for call in fn.calls:
                callee, line_no, raw_args = call[0], call[1], call[2]

                if callee in self.TARGET_FUNCS:
                    args_str = raw_args.strip()

                    # Extract first arg, balancing parens/quotes
                    paren_depth = 0
                    in_quote = False
                    quote_char = None
                    arg_end = -1
                    for i, c in enumerate(args_str):
                        if in_quote:
                            if c == quote_char and (i == 0 or args_str[i-1] != '\\'):
                                in_quote = False
                        elif c in ('"', "'"):
                            in_quote = True
                            quote_char = c
                        elif c == '(':
                            paren_depth += 1
                        elif c == ')':
                            paren_depth -= 1
                        elif c == ',' and paren_depth == 0:
                            arg_end = i
                            break

                    if arg_end != -1:
                        first_arg = args_str[:arg_end].strip()
                    else:
                        first_arg = args_str.strip()

                    if not first_arg:
                        continue

                    if not self._is_literal_arg(first_arg):
                        code_snippet = ast_ctx.source_lines[line_no - 1].strip() if 0 < line_no <= len(ast_ctx.source_lines) else f"{callee}(...)"
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=code_snippet,
                            message=f"Non-literal string passed to {callee}(...). An attacker can inject arbitrary OS commands.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement="Use exec() family functions (execve) with an array of arguments to bypass the shell."
                        ))
        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        match_target = masked_line_content or line_content
        for fn in self.TARGET_FUNCS:
            m = re.search(rf'\b{re.escape(fn)}\s*\(\s*([^",\s][^,\)]*)\s*', match_target)
            if m:
                arg = line_content[m.start(1):m.end(1)].strip()
                if self._is_type_decl(arg):
                    continue
                if not self._is_literal_arg(arg):
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=f"Non-literal string passed to {fn}(...). An attacker can inject arbitrary OS commands.",
                        column_number=m.start() + 1,
                        engine="Regex",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement="Use exec() family functions (execve) with an array of arguments to bypass the shell."
                    ))
        return issues
