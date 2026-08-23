"""
Rules for Banned & Insecure Functions and Format Strings.
"""

import re
from typing import List, Optional, Tuple
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ..ast_analyzer import CASTContext


class BannedFunctionsRule(BaseRule):
    rule_id = "CGULL-001"
    name = "Banned Functions"
    impact = Severity.HIGH
    category = RuleCategory.STRINGS
    description = "Flag the usage of legacy string/memory/file functions that lack bounds checking or introduce race conditions (gets, strcpy, strcat, sprintf, vsprintf, scanf %s, mktemp, tmpnam, tempnam)."
    implementation_method = "Regex string matching"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-676 / CWE-120 / CWE-377"
    remediation_suggestion = "Replace with safe, bounds-checking or race-free alternatives: use gets_s / fgets instead of gets; strncpy_s / snprintf instead of strcpy/strcat; snprintf instead of sprintf; mkstemp instead of mktemp/tmpnam/tempnam."
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
        "mktemp": ("mktemp() generates a temporary file name with race condition risks (CWE-377); it does not safely open the file.", "mkstemp(template)"),
        "tmpnam": ("tmpnam() generates a temporary file name vulnerable to race conditions (CWE-377). Use mkstemp() instead.", "mkstemp(template)"),
        "tempnam": ("tempnam() generates a temporary file name vulnerable to race conditions (CWE-377). Use mkstemp() instead.", "mkstemp(template)"),
    }

    def __init__(self, extra_banned_funcs: Optional[dict] = None):
        super().__init__()
        self.banned_funcs = dict(self.BANNED_FUNCS)
        self._dest_size_cache = {}
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

    @staticmethod
    def _extract_call_args(line_content: str, start_offset: int) -> Optional[Tuple[str, str]]:
        """
        Extracts top-level two arguments (dest, src) from a function call like strcpy(dest, src).
        start_offset should be the position of '(' in line_content.
        """
        paren_depth = 1
        in_quote = False
        quote_char = None
        escape = False
        args = []
        cur_arg = []

        i = start_offset + 1
        n = len(line_content)
        while i < n:
            c = line_content[i]
            if escape:
                cur_arg.append(c)
                escape = False
            elif c == '\\':
                cur_arg.append(c)
                escape = True
            elif in_quote:
                cur_arg.append(c)
                if c == quote_char:
                    in_quote = False
            elif c in ('"', "'"):
                in_quote = True
                quote_char = c
                cur_arg.append(c)
            elif c == '(':
                paren_depth += 1
                cur_arg.append(c)
            elif c == ')':
                paren_depth -= 1
                if paren_depth == 0:
                    args.append("".join(cur_arg).strip())
                    break
                cur_arg.append(c)
            elif c == ',' and paren_depth == 1:
                args.append("".join(cur_arg).strip())
                cur_arg = []
            else:
                cur_arg.append(c)
            i += 1

        if len(args) >= 2:
            return args[0], args[1]
        return None

    @staticmethod
    def _get_string_literal_length(src_expr: str) -> Optional[int]:
        """
        Computes the unescaped byte length of a C string literal (or concatenated
        string literals like "foo" "bar"). Returns None if src_expr is not
        a strictly ASCII string literal (non-ASCII characters or wide prefixes make byte size uncertain).
        """
        s = src_expr.strip()
        if not s:
            return None

        literal_part_re = re.compile(r'^(?:u8)?"((?:[^"\\]|\\.)*)"')
        pos = 0
        total_len = 0
        matched_any = False

        while pos < len(s):
            while pos < len(s) and s[pos].isspace():
                pos += 1
            if pos >= len(s):
                break

            m = literal_part_re.match(s[pos:])
            if not m:
                return None

            content = m.group(1)
            if any(ord(c) > 127 for c in content):
                return None

            unescaped = re.sub(r'\\(?:[0-7]{1,3}|x[0-9a-fA-F]{1,2}|.)', 'x', content)
            if any(ord(c) > 127 for c in unescaped):
                return None

            total_len += len(unescaped)
            pos += m.end()
            matched_any = True

        return total_len if matched_any else None

    def _resolve_dest_buffer_size(self, dest_expr: str, line_number: int, source_lines: List[str], full_code: str, file_path: str = "") -> Optional[int]:
        """
        Resolves the declared array size of dest_expr within current function scope.
        Requires dest_expr to be a simple identifier (rejects offsets, indexing, member access).
        Handles direct array declarations, macro array sizes, and pointer variables
        assigned from fixed-size arrays.
        """
        cache_key = (file_path, line_number, dest_expr)
        if cache_key in self._dest_size_cache:
            return self._dest_size_cache[cache_key]

        dest_clean = dest_expr.strip()
        dest_clean = re.sub(r'^\s*\(\s*(?:char|int8_t|uint8_t|void|unsigned\s+char|signed\s+char)\s*\*+\s*\)\s*', '', dest_clean).strip()
        if not re.match(r'^[a-zA-Z_]\w*$', dest_clean):
            self._dest_size_cache[cache_key] = None
            return None

        var_name = dest_clean

        func_header_re = re.compile(
            r'^[ \t]*(?:(?:static|inline|extern|const|unsigned|signed|struct\s+\w+|\w+)\s+)+(\*?\s*[\w_]+)\s*\([^)]*\)\s*\{?'
        )
        fn_start_idx = 0
        for i in range(min(line_number - 1, len(source_lines) - 1), -1, -1):
            line = source_lines[i]
            if func_header_re.match(line):
                fn_start_idx = i
                break

        first_fn_start_idx = len(source_lines)
        for i, line in enumerate(source_lines):
            if func_header_re.match(line):
                first_fn_start_idx = i
                break

        def _find_macro_val(macro_name: str) -> Optional[int]:
            def_m = re.search(rf'#\s*define\s+{re.escape(macro_name)}\s+(\d+|0x[0-9a-fA-F]+)\b', full_code)
            if def_m:
                val_str = def_m.group(1)
                return int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)
            const_m = re.search(rf'\bconst\s+(?:int|size_t|uint\w+_t)\s+{re.escape(macro_name)}\s*=\s*(\d+|0x[0-9a-fA-F]+)\b', full_code)
            if const_m:
                val_str = const_m.group(1)
                return int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)
            return None

        def _lookup_array_size_in_lines(target_var: str, start_l: int, end_l: int) -> Optional[int]:
            decl_pattern = rf'\b(?:char|int8_t|uint8_t|int|unsigned\s+char|signed\s+char|wchar_t|struct\s+\w+|\w+)\s+(?:\*|\s)*\b{re.escape(target_var)}\s*\[\s*([^\]]+)\s*\]'
            for idx in range(end_l - 1, start_l - 1, -1):
                if idx < len(source_lines):
                    line = source_lines[idx]
                    decl_m = re.search(decl_pattern, line)
                    if decl_m:
                        dim_expr = decl_m.group(1).strip()
                        if dim_expr.isdigit():
                            return int(dim_expr)
                        return _find_macro_val(dim_expr)
            return None

        # 1. Check in-scope local array declaration
        size = _lookup_array_size_in_lines(var_name, fn_start_idx, line_number)
        if size is not None:
            self._dest_size_cache[cache_key] = size
            return size

        # 2. Check in-scope pointer alias assignment from array or aliased pointer (e.g. data = dataBuffer; data = &dataBuffer[0];)
        alias_assign_pattern = re.compile(
            rf'(?:^|[;{{}}\s])(?:(?:\w+\s+)*\*+\s*)?{re.escape(var_name)}\s*=(?!=)\s*(.+?)(?:;|$)'
        )
        for idx in range(line_number - 1, fn_start_idx - 1, -1):
            if idx < len(source_lines):
                line = source_lines[idx]
                m_assign = alias_assign_pattern.search(line)
                if m_assign:
                    rhs = m_assign.group(1).strip()
                    rhs_clean = re.sub(r'^(?:\([^\)]+\)\s*)+', '', rhs).strip()

                    alias_target = None
                    offset = 0

                    m_idx = re.match(r'^&\s*([a-zA-Z_]\w*)\s*\[\s*(\d+)\s*\]$', rhs_clean)
                    m_add1 = re.match(r'^([a-zA-Z_]\w*)\s*\+\s*(\d+)$', rhs_clean)
                    m_add2 = re.match(r'^(\d+)\s*\+\s*([a-zA-Z_]\w*)$', rhs_clean)
                    m_simple = re.match(r'^(?:&\s*)?([a-zA-Z_]\w*)(?:\s*\[\s*0\s*\])?$', rhs_clean)

                    if m_idx:
                        alias_target = m_idx.group(1)
                        offset = int(m_idx.group(2))
                    elif m_add1:
                        alias_target = m_add1.group(1)
                        offset = int(m_add1.group(2))
                    elif m_add2:
                        alias_target = m_add2.group(2)
                        offset = int(m_add2.group(1))
                    elif m_simple:
                        alias_target = m_simple.group(1)
                        offset = 0

                    if alias_target and alias_target != var_name and alias_target not in ('NULL', 'nullptr'):
                        size = _lookup_array_size_in_lines(alias_target, fn_start_idx, line_number)
                        if size is None:
                            size = _lookup_array_size_in_lines(alias_target, 0, first_fn_start_idx)
                        if size is not None:
                            res_size = max(0, size - offset)
                            self._dest_size_cache[cache_key] = res_size
                            return res_size

        # 3. Fallback: check global array declaration (before any function starts)
        size = _lookup_array_size_in_lines(var_name, 0, first_fn_start_idx)
        self._dest_size_cache[cache_key] = size
        return size

    def _resolve_src_literal_length(self, src_expr: str, line_number: int, source_lines: List[str], full_code: str) -> Optional[int]:
        """
        Resolves the C string literal byte length of src_expr.
        Handles direct string literals, or variables initialized or assigned
        with C string literals within the current function scope.
        """
        direct_len = self._get_string_literal_length(src_expr)
        if direct_len is not None:
            return direct_len

        src_clean = src_expr.strip()
        src_clean = re.sub(r'^\s*\(\s*(?:const\s+)?(?:char|int8_t|uint8_t|void|unsigned\s+char|signed\s+char)\s*\*+\s*\)\s*', '', src_clean).strip()
        if not re.match(r'^[a-zA-Z_]\w*$', src_clean):
            return None

        var_name = src_clean

        func_header_re = re.compile(
            r'^[ \t]*(?:(?:static|inline|extern|const|unsigned|signed|struct\s+\w+|\w+)\s+)+(\*?\s*[\w_]+)\s*\([^)]*\)\s*\{?'
        )
        fn_start_idx = 0
        for i in range(min(line_number - 1, len(source_lines) - 1), -1, -1):
            line = source_lines[i]
            if func_header_re.match(line):
                fn_start_idx = i
                break

        assign_pat = re.compile(
            rf'(?:^|[;{{}}\s])(?:(?:\w+\s+)*\*+\s*)?{re.escape(var_name)}\s*(?:\[[^\]]*\])?\s*=(?!=)\s*(.+?)(?:;|$)'
        )

        for idx in range(min(line_number - 1, len(source_lines) - 1), fn_start_idx - 1, -1):
            line = source_lines[idx]
            m_assign = assign_pat.search(line)
            if m_assign:
                rhs = m_assign.group(1).strip()
                lit_len = self._get_string_literal_length(rhs)
                if lit_len is not None:
                    return lit_len

        return None

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        if line_content.lstrip().startswith('#'):
            return issues

        match_target = masked_line_content or line_content
        for fn_name, (reason, fix) in self.banned_funcs.items():
            pattern = rf'\b{re.escape(fn_name)}\s*\('
            # Match against the string-literal-masked view so a banned
            # function name that only appears as text inside a string
            # literal (e.g. a log message mentioning "gets()") isn't
            # flagged as an actual call.
            m = re.search(pattern, match_target)
            if m:
                # Skip function prototypes and definition headers (e.g., "char *mktemp(char *template);")
                decl_pattern = rf'^\s*(?!(?:return|if|while|for|switch|else)\b)(?:(?:extern|static|inline|const|volatile|unsigned|signed|short|long|char|int|void|double|float|struct\s+\w+|union\s+\w+|enum\s+\w+|\w+)\s*|\*\s*)+\b{re.escape(fn_name)}\s*\([^;{{}}]*\)[^;{{}}]*\s*(?:;|\{{)?\s*$'
                if re.match(decl_pattern, line_content.strip()):
                    continue
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
                elif fn_name == "strcpy":
                    args = self._extract_call_args(line_content, m.end() - 1)
                    if args:
                        dest_arg, src_arg = args
                        src_len = self._resolve_src_literal_length(src_arg, line_number, source_lines, full_code)
                        if src_len is not None:
                            dest_size = self._resolve_dest_buffer_size(dest_arg, line_number, source_lines, full_code, file_path)
                            required_bytes = src_len + 1
                            if dest_size is not None and dest_size > required_bytes:
                                issue = self.create_issue(
                                    file_path=file_path,
                                    line_number=line_number,
                                    code_snippet=line_content,
                                    message=f"Insecure function call '{fn_name}': source is a literal ('{src_arg}', length {src_len}) provably shorter than destination buffer size ({dest_size}). Currently bounded, but {fn_name}() is fragile to future edits — prefer snprintf or strncpy_s.",
                                    column_number=m.start() + 1,
                                    engine="Regex",
                                    fix_type=FixType.SUGGESTED_FIX,
                                    suggested_fix_replacement=fix,
                                )
                                issue.impact = Severity.LOW
                                issues.append(issue)
                                continue

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

    PRINT_FUNC_ARG_INDEX = {
        "printf": 0,
        "vprintf": 0,
        "fprintf": 1,
        "vfprintf": 1,
        "sprintf": 1,
        "vsprintf": 1,
        "syslog": 1,
        "dprintf": 1,
        "vdprintf": 1,
        "snprintf": 2,
        "vsnprintf": 2,
    }
    PRINT_FUNCS = list(PRINT_FUNC_ARG_INDEX.keys())

    @staticmethod
    def _is_literal_format(arg: str) -> bool:
        s = arg.strip()
        return (
            s.startswith('"') or
            s.startswith('L"') or
            s.startswith('u8"') or
            s.startswith('u"') or
            s.startswith('U"')
        )

    @staticmethod
    def _split_call_args(line_content: str, start_paren_offset: int) -> List[str]:
        paren_depth = 1
        bracket_depth = 0
        brace_depth = 0
        in_quote = False
        quote_char = None
        escape = False
        args = []
        cur_arg = []

        i = start_paren_offset + 1
        n = len(line_content)
        while i < n:
            c = line_content[i]
            if escape:
                cur_arg.append(c)
                escape = False
            elif c == '\\':
                cur_arg.append(c)
                escape = True
            elif in_quote:
                cur_arg.append(c)
                if c == quote_char:
                    in_quote = False
            elif c in ('"', "'"):
                in_quote = True
                quote_char = c
                cur_arg.append(c)
            elif c == '(':
                paren_depth += 1
                cur_arg.append(c)
            elif c == ')':
                paren_depth -= 1
                if paren_depth == 0:
                    args.append("".join(cur_arg).strip())
                    cur_arg = []
                    break
                cur_arg.append(c)
            elif c == '[':
                bracket_depth += 1
                cur_arg.append(c)
            elif c == ']':
                if bracket_depth > 0:
                    bracket_depth -= 1
                cur_arg.append(c)
            elif c == '{':
                brace_depth += 1
                cur_arg.append(c)
            elif c == '}':
                if brace_depth > 0:
                    brace_depth -= 1
                cur_arg.append(c)
            elif c == ',' and paren_depth == 1 and bracket_depth == 0 and brace_depth == 0:
                args.append("".join(cur_arg).strip())
                cur_arg = []
            else:
                cur_arg.append(c)
            i += 1

        if cur_arg and paren_depth == 0:
            args.append("".join(cur_arg).strip())
        return args

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        if line_content.lstrip().startswith('#'):
            return issues

        match_target = masked_line_content or line_content

        for fn, target_idx in self.PRINT_FUNC_ARG_INDEX.items():
            pattern = rf'\b{re.escape(fn)}\s*\('
            for m in re.finditer(pattern, match_target):
                # Skip function declarations / prototypes / definition headers
                decl_pattern = rf'^\s*(?!(?:return|if|while|for|switch|else)\b)(?:(?:extern|static|inline|const|volatile|unsigned|signed|short|long|char|int|void|double|float|struct\s+\w+|union\s+\w+|enum\s+\w+|\w+)\s*|\*\s*)+\b{re.escape(fn)}\s*\([^;{{}}]*\)[^;{{}}]*\s*(?:;|\{{)?\s*$'
                if re.match(decl_pattern, line_content.strip()):
                    continue

                paren_pos = m.end() - 1
                args = self._split_call_args(line_content, paren_pos)
                if len(args) > target_idx:
                    arg = args[target_idx]
                    if not self._is_literal_format(arg):
                        msg = (
                            f"Non-literal format string passed to {fn}({arg}). An attacker can inject %x, %n, or %s to leak or overwrite memory."
                            if target_idx == 0 else
                            f"Non-literal format string passed to {fn}(..., {arg}). Format string vulnerability allows arbitrary read/write."
                        )
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=line_content,
                            message=msg,
                            column_number=m.start() + 1,
                            engine="Regex",
                            fix_type=FixType.SAFE_FIX if fn == "printf" else FixType.SUGGESTED_FIX,
                            auto_fix_replacement=f'{fn}("%s", {arg})' if fn == "printf" else None,
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

    @staticmethod
    def _extract_first_arg_multiline(line_idx: int, char_offset: int, source_lines: List[str]) -> str:
        paren_depth = 1
        in_quote = False
        quote_char = None
        chars = []

        cur_line = line_idx
        cur_pos = char_offset

        while cur_line < len(source_lines):
            line = source_lines[cur_line]
            while cur_pos < len(line):
                c = line[cur_pos]
                if in_quote:
                    chars.append(c)
                    if c == quote_char and (cur_pos == 0 or line[cur_pos - 1] != '\\'):
                        in_quote = False
                elif c in ('"', "'"):
                    in_quote = True
                    quote_char = c
                    chars.append(c)
                elif c == '(':
                    paren_depth += 1
                    chars.append(c)
                elif c == ')':
                    paren_depth -= 1
                    if paren_depth == 0:
                        break
                    chars.append(c)
                else:
                    chars.append(c)
                cur_pos += 1

            if paren_depth == 0:
                break

            chars.append('\n')
            cur_line += 1
            cur_pos = 0

        full_args_str = "".join(chars).strip()
        if not full_args_str:
            return ""

        p_depth = 0
        q_in = False
        q_char = None
        arg_end = -1
        for i, c in enumerate(full_args_str):
            if q_in:
                if c == q_char and (i == 0 or full_args_str[i-1] != '\\'):
                    q_in = False
            elif c in ('"', "'"):
                q_in = True
                q_char = c
            elif c == '(':
                p_depth += 1
            elif c == ')':
                p_depth -= 1
            elif c == ',' and p_depth == 0:
                arg_end = i
                break

        if arg_end != -1:
            return full_args_str[:arg_end].strip()
        return full_args_str.strip()

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        if line_content.lstrip().startswith('#'):
            return issues

        match_target = masked_line_content or line_content
        for fn in self.TARGET_FUNCS:
            for m in re.finditer(rf'\b{re.escape(fn)}\s*\(', match_target):
                char_offset = m.end()
                first_arg = self._extract_first_arg_multiline(line_number - 1, char_offset, source_lines)
                if not first_arg:
                    continue
                if self._is_type_decl(first_arg):
                    continue
                if not self._is_literal_arg(first_arg):
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

class StrncpyNullTerminationRule(BaseRule):
    rule_id = "CGULL-037"
    name = "Improper Null Termination (strncpy)"
    impact = Severity.HIGH
    category = RuleCategory.STRINGS
    description = "strncpy() does not guarantee null termination if the source string is larger than or equal to the specified length. This causes out-of-bounds reads/writes."
    implementation_method = "Regex line matching for strncpy calls"
    implementation_complexity = "Low"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-170"
    remediation_suggestion = "Explicitly null-terminate the destination buffer after calling strncpy: dest[sizeof(dest) - 1] = '\\0'; or use safe alternatives like strncpy_s or snprintf."
    sample_vulnerable_code = "char buf[10];\nstrncpy(buf, input, sizeof(buf));\nprintf(\"%s\", buf);"
    sample_remediated_code = "char buf[10];\nstrncpy(buf, input, sizeof(buf));\nbuf[sizeof(buf) - 1] = '\\0';\nprintf(\"%s\", buf);"
    analysis_engine = AnalysisEngine.REGEX

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        target = masked_line_content or line_content

        # Skip preprocessor directives
        if target.lstrip().startswith('#'):
            return issues

        # Avoid function prototypes/declarations e.g., void *strncpy(void *dest, const void *src, size_t n);
        if re.search(r'^\s*(?:extern\s+)?(?:[a-zA-Z_]\w*\s+)+\*?\s*strncpy\s*\(', target):
            return issues

        for m in re.finditer(r'\b(strncpy)\s*\(', target):
            func_name = m.group(1)
            # Try to extract destination buffer name using the substring starting at the match
            substr = target[m.start():]
            m_args = re.search(r'^strncpy\s*\(\s*([a-zA-Z_]\w*(?:->\w+|\.\w+|\[[^\]]+\])?)\s*,', substr)
            dest_buf = m_args.group(1) if m_args else "unknown"

            # Check next few lines for null termination explicitly
            has_null_term = False
            if dest_buf != "unknown":
                base_var = re.match(r'^([a-zA-Z_]\w*)', dest_buf)
                if base_var:
                    base_var_name = base_var.group(1)
                    for i in range(line_number, min(line_number + 5, len(source_lines))):
                        next_line = source_lines[i]
                        if re.search(r"\b" + base_var_name + r"\s*\[[^\]]+\]\s*=\s*(?:'\\0'|0)\s*;", next_line):
                            has_null_term = True
                            break

            if not has_null_term:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content.strip(),
                    message=f"'{func_name}()' does not guarantee null termination. Explicitly null-terminate the buffer (CWE-170).",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"{line_content.strip()}\n{dest_buf}[/*size*/ - 1] = '\\0';" if dest_buf != "unknown" else None
                ))

        return issues
