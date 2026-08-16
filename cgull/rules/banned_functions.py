"""
Rules for Banned & Insecure Functions and Format Strings.
"""

import re
from typing import List, Optional
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine
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

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        match_target = masked_line_content or line_content
        for fn_name, (reason, fix) in self.BANNED_FUNCS.items():
            pattern = rf'\b{fn_name}\s*\('
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
                            auto_fix_replacement=fix,
                        ))
                else:
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=f"Banned insecure function call '{fn_name}': {reason}",
                        column_number=m.start() + 1,
                        engine="Regex",
                        auto_fix_replacement=fix,
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
        # printf(var) or printf(var, ...) where first arg is not "..."
        for fn in ["printf", "vprintf"]:
            m = re.search(rf'\b{fn}\s*\(\s*([^",\s][^,\)]*)\s*\)', line_content)
            if m:
                arg = m.group(1).strip()
                if not arg.startswith('"') and not arg.startswith('L"'):
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=f"Non-literal format string passed to {fn}({arg}). An attacker can inject %x, %n, or %s to leak or overwrite memory.",
                        column_number=m.start() + 1,
                        engine="Regex",
                        auto_fix_replacement=f'{fn}("%s", {arg})'
                    ))

        # fprintf(stream, var) or syslog(priority, var)
        for fn in ["fprintf", "syslog", "dprintf"]:
            m = re.search(rf'\b{fn}\s*\(\s*[^,]+,\s*([^",\s][^,\)]*)\s*\)', line_content)
            if m:
                arg = m.group(1).strip()
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
                    auto_fix_replacement=f"strtol({arg}, &endptr, 10)"
                ))
        return issues
