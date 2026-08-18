"""
Rules for Cryptography, Timing Attack Prevention, Type Qualifiers, and Fault Injection.
"""

import re
from typing import List, Optional
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ..ast_analyzer import CASTContext, _format_pycparser_type, _format_pycparser_expr, _extract_identifiers_from_ast, _PRELUDE_LINE_COUNT


def _is_sensitive_identifier(token: str) -> bool:
    """Check if an identifier token indicates a security-sensitive value."""
    t = token.lower()
    non_sec_terms = [
        'key_count', 'key_cnt', 'key_index', 'key_idx', 'key_len', 'key_length',
        'key_size', 'key_id', 'key_type', 'key_num', 'key_name', 'key_tag',
        'key_offset', 'key_list', 'key_arr', 'key_array', 'key_table', 'key_slot',
        'keys_count', 'max_keys', 'num_keys', 'keyword', 'keyboard', 'signal',
        'assignment', 'designation', 'header', 'magic', 'version', 'count',
        'length', 'size', 'index'
    ]
    if any(non_sec in t for non_sec in non_sec_terms):
        return False

    if any(k in t for k in ['secret', 'password', 'passwd', 'token', 'auth', 'hash', 'digest', 'mac', 'hmac', 'pin', 'cert', 'credential', 'cred', 'privkey', 'private_key', 'session', 'apikey', 'api_key']):
        if 'sig' in t and not ('signature' in t or 'sig' in t.split('_') or t.startswith('sig') or t.endswith('sig')):
            return False
        if 'pass' in t and not ('password' in t or 'passwd' in t or 'pass' in t.split('_') or t.startswith('pass') or t.endswith('pass')):
            return False
        return True

    if 'key' in t or 'crypto' in t:
        if t == 'keys':
            return False
        return True

    return False


def _is_sensitive_type(type_name: str) -> bool:
    """Check if a type name explicitly indicates sensitive secret data (excluding generic uint8_t/char/byte)."""
    t = type_name.lower()
    for k in ['crypto', 'secret', 'key', 'hash', 'token', 'credential', 'cipher', 'privkey', 'auth_t', 'mac_t', 'digest_t']:
        if k in t:
            if k == 'key' and any(ex in t for ex in ['key_count', 'key_index', 'key_len', 'key_id']):
                continue
            return True
    return False


def _is_security_function_context(fn_name: str) -> bool:
    """Check if a function name indicates a security-relevant context."""
    f = fn_name.lower()
    sec_terms = ['auth', 'login', 'permission', 'credential', 'crypto', 'security', 'token', 'password', 'passwd', 'signature', 'mac', 'hmac', 'pfx', 'cert', 'verifier', 'authenticate', 'sec_cmp']
    if any(term in f for term in sec_terms):
        return True

    if any(action in f for action in ['check', 'verify', 'validate', 'compare']):
        if any(noun in f for noun in ['hash', 'token', 'mac', 'sig', 'key', 'secret', 'auth', 'cert', 'pin', 'cred', 'pass']):
            if not any(non_sec in f for non_sec in ['bounds', 'header', 'length', 'len', 'size', 'version', 'count', 'magic', 'index', 'type']):
                return True
    return False


class NonConstantTimeMemoryComparisonRule(BaseRule):
    rule_id = "CGULL-005"
    name = "Non-Constant Time Memory Comparison"
    impact = Severity.HIGH
    category = RuleCategory.CRYPTO
    description = "Flag standard memcmp(), strcmp(), or strncmp() in crypto, token, or security checks that leak execution timing information."
    implementation_method = "AST type analysis / function context with fallback name heuristics"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-208 / CWE-385"
    remediation_suggestion = "Use constant-time comparison routines like CRYPTO_memcmp(), sodium_memcmp(), or timingsafe_bcmp() for secrets and authentication tokens."
    sample_vulnerable_code = "if (memcmp(calculated_hash, expected_hash, 32) == 0) {\n    grant_admin_access();\n}"
    sample_remediated_code = "if (CRYPTO_memcmp(calculated_hash, expected_hash, 32) == 0) {\n    grant_admin_access();\n}"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        target_funcs = {"memcmp", "strcmp", "strncmp", "bcmp"}

        for fn in ast_ctx.functions:
            fn_is_sec_ctx = _is_security_function_context(fn.name)

            # Symbol type map in this function scope
            var_types: dict = {}
            for p in fn.parameters:
                var_types[p.name] = p.type_name.lower()
            for v_name, v_obj in fn.variables.items():
                var_types[v_name] = v_obj.type_name.lower()
            for g_name, g_obj in ast_ctx.global_variables.items():
                if g_name not in var_types:
                    var_types[g_name] = g_obj.type_name.lower()

            for callee, line_no, raw_args in fn.calls:
                if callee in target_funcs:
                    arg_list = [a.strip() for a in raw_args.split(',')] if raw_args else []

                    if callee == "bcmp":
                        should_flag = True
                    else:
                        has_sensitive_type = False
                        has_sensitive_name = False

                        for arg in arg_list:
                            identifiers = re.findall(r'\b[a-zA-Z_]\w*\b', arg)
                            for id_token in identifiers:
                                if _is_sensitive_identifier(id_token):
                                    has_sensitive_name = True
                                    break

                                tname = var_types.get(id_token, "")
                                if not tname and fn.parameters:
                                    for p in fn.parameters:
                                        if p.name == id_token:
                                            tname = p.type_name.lower()
                                            break
                                if tname and _is_sensitive_type(tname):
                                    has_sensitive_type = True
                                    break
                            if has_sensitive_name or has_sensitive_type:
                                break

                        should_flag = False
                        if has_sensitive_name or has_sensitive_type:
                            should_flag = True
                        elif fn_is_sec_ctx:
                            is_non_sec_metadata = any(
                                any(non_sec in id_tok.lower() for non_sec in ['count', 'length', 'size', 'index', 'version', 'magic', 'header'])
                                for arg in arg_list
                                for id_tok in re.findall(r'\b[a-zA-Z_]\w*\b', arg)
                            )
                            if not is_non_sec_metadata:
                                should_flag = True

                    if should_flag:
                        snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else f"{callee}({raw_args})"
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Standard comparison '{callee}()' on security-sensitive values ({raw_args.strip()}) is vulnerable to timing side-channel attacks (CWE-208).",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"CRYPTO_memcmp({raw_args})"
                        ))
        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Fallback for line-based scanner when AST is not used
        m = re.search(r'\b(memcmp|strcmp|strncmp|bcmp)\s*\(([^)]+)\)', line_content)
        if m:
            func_name = m.group(1)
            args = m.group(2)
            if func_name == "bcmp":
                should_flag = True
            else:
                identifiers = re.findall(r'\b[a-zA-Z_]\w*\b', args)
                should_flag = any(_is_sensitive_identifier(tok) for tok in identifiers)

            if should_flag:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Standard comparison '{func_name}()' on security-sensitive values ({args.strip()}) is vulnerable to timing side-channel attacks (CWE-208).",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"CRYPTO_memcmp({args})"
                ))
        return issues


class StrippingVolatileQualifiersRule(BaseRule):
    rule_id = "CGULL-009"
    name = "Stripping Volatile Qualifiers"
    impact = Severity.HIGH
    category = RuleCategory.CONTROL_FLOW
    description = "Prevent casts or function calls that silently remove volatile from hardware/registers or shared memory pointers."
    implementation_method = "AST type analysis & cast node inspection with fallback name heuristics"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-562 / CWE-704"
    remediation_suggestion = "Maintain volatile qualifiers on all pointers referencing hardware registers, MMIO, or multithreaded shared state."
    sample_vulnerable_code = "volatile uint32_t *reg = (volatile uint32_t *)0x4000;\nuint32_t *p = (uint32_t *)reg; // Strips volatile"
    sample_remediated_code = "volatile uint32_t *reg = (volatile uint32_t *)0x4000;\nvolatile uint32_t *p = reg; // Preserves volatile"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []

        for fn in ast_ctx.functions:
            # Build map of volatile symbols in this function scope
            volatile_vars: set = set()

            for p in fn.parameters:
                if 'volatile' in p.type_name:
                    volatile_vars.add(p.name)

            for v_name, v_obj in fn.variables.items():
                if v_obj.is_volatile or 'volatile' in v_obj.type_name:
                    volatile_vars.add(v_name)

            for g_name, g_obj in ast_ctx.global_variables.items():
                if g_obj.is_volatile or 'volatile' in g_obj.type_name:
                    volatile_vars.add(g_name)

            # Analyze pycparser AST if available
            if ast_ctx.pycparser_ast:
                from pycparser import c_ast

                # Find the FuncDef for this function
                for ext in ast_ctx.pycparser_ast.ext:
                    if isinstance(ext, c_ast.FuncDef) and ext.decl.name == fn.name:
                        # Inspect parameters
                        if ext.decl.type.args and getattr(ext.decl.type.args, "params", None):
                            for param in ext.decl.type.args.params:
                                p_name = getattr(param, "name", None)
                                quals = getattr(param, "quals", []) or []
                                type_quals = getattr(getattr(param, "type", None), "quals", []) or []
                                inner_type = getattr(getattr(param, "type", None), "type", None)
                                inner_quals = getattr(inner_type, "quals", []) or []
                                if "volatile" in quals or "volatile" in type_quals or "volatile" in inner_quals:
                                    if p_name:
                                        volatile_vars.add(p_name)

                        # Visitor to find Cast nodes where expression is volatile
                        class CastVisitor(c_ast.NodeVisitor):
                            def __init__(self, outer_rule, fn_start):
                                self.outer_rule = outer_rule
                                self.fn_start = fn_start

                            def visit_Cast(self, node):
                                cast_to_type, _, _, is_vol, _, _, _, _ = _format_pycparser_type(node.to_type)
                                # Check if target type is missing volatile
                                target_has_volatile = is_vol or "volatile" in cast_to_type
                                if not target_has_volatile:
                                    # Check if expression being cast contains a known volatile variable
                                    expr_ids = _extract_identifiers_from_ast(node.expr)
                                    volatile_ids = expr_ids.intersection(volatile_vars)
                                    if volatile_ids:
                                        line_no = (node.coord.line - _PRELUDE_LINE_COUNT) if node.coord else self.fn_start
                                        v_name = sorted(list(volatile_ids))[0]
                                        snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else _format_pycparser_expr(node)
                                        issues.append(self.outer_rule.create_issue(
                                            file_path=file_path,
                                            line_number=line_no,
                                            code_snippet=snippet,
                                            message=f"Explicit type cast potentially strips 'volatile' qualifier from variable '{v_name}', allowing unsafe compiler register caching.",
                                            column_number=1,
                                            engine="AST",
                                        ))
                                self.generic_visit(node)

                        CastVisitor(self, fn.start_line).visit(ext.body)
            else:
                # Fallback AST analysis using regex/code lines and volatile_vars map
                body_lines = fn.body.splitlines()
                cast_regex = re.compile(r'\(\s*(?!volatile\b)(?:unsigned\s+|signed\s+|struct\s+\w+|\w+)\s*\*+\s*\)\s*(\w+)')
                for i, line in enumerate(body_lines):
                    line_no = fn.start_line + i
                    for m in cast_regex.finditer(line):
                        var_name = m.group(1)
                        is_vol = var_name in volatile_vars or any(k in var_name.lower() for k in ['reg', 'mmio', 'hw', 'io', 'port', 'shared', 'vol'])
                        if is_vol:
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=line.strip(),
                                message=f"Explicit type cast potentially strips 'volatile' qualifier from variable '{var_name}', allowing unsafe compiler register caching.",
                                column_number=m.start() + 1,
                                engine="AST",
                            ))

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        # Line scanner fallback only when scan_ast is not executed (REGEX mode)
        issues = []
        m = re.search(r'\(\s*(?!volatile\b)(?:unsigned\s+|signed\s+|struct\s+\w+|\w+)\s*\*+\s*\)\s*(\w*(?:reg|mmio|hw|io|port|shared|vol)\w*)', line_content, re.IGNORECASE)
        if m:
            var_name = m.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Explicit type cast potentially strips 'volatile' qualifier from variable '{var_name}', allowing unsafe compiler register caching.",
                column_number=m.start() + 1,
                engine="Regex",
            ))
        return issues


class IllegalFunctionPointerConversionsRule(BaseRule):
    rule_id = "CGULL-011"
    name = "Illegal Function Pointer Conversions"
    impact = Severity.HIGH
    category = RuleCategory.CONTROL_FLOW
    description = "Prevent conversions between function pointers and data pointers (void *) or integers to mitigate Return-Oriented Programming (ROP) and CFI violations."
    implementation_method = "AST type analysis & cast node inspection with fallback name heuristics"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-843 / CWE-588"
    remediation_suggestion = "Store and cast function pointers only using matching function pointer typedefs, never void* or integer types."
    sample_vulnerable_code = "void *callback = (void *)my_handler; // Illegal func ptr to object ptr conversion\nint addr = (int)my_handler;"
    sample_remediated_code = "typedef void (*handler_fn)(int);\nhandler_fn callback = my_handler;"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []

        # Collect function names and function pointer variables in the file
        func_names = {f.name for f in ast_ctx.functions}
        func_ptr_vars = set()

        for fn in ast_ctx.functions:
            for p in fn.parameters:
                if p.is_pointer and ('(' in p.type_name or 'fn' in p.type_name.lower() or 'func' in p.type_name.lower() or 'handler' in p.type_name.lower() or 'cb' in p.type_name.lower()):
                    func_ptr_vars.add(p.name)
            for v_name, v_obj in fn.variables.items():
                if v_obj.is_pointer and ('(' in v_obj.type_name or 'fn' in v_obj.type_name.lower() or 'func' in v_obj.type_name.lower() or 'handler' in v_obj.type_name.lower() or 'cb' in v_obj.type_name.lower()):
                    func_ptr_vars.add(v_name)

        for g_name, g_obj in ast_ctx.global_variables.items():
            if g_obj.is_pointer and ('(' in g_obj.type_name or 'fn' in g_obj.type_name.lower() or 'func' in g_obj.type_name.lower()):
                func_ptr_vars.add(g_name)

        all_func_symbols = func_names.union(func_ptr_vars)

        if ast_ctx.pycparser_ast:
            from pycparser import c_ast

            class FuncPtrCastVisitor(c_ast.NodeVisitor):
                def __init__(self, outer_rule):
                    self.outer_rule = outer_rule

                def visit_Cast(self, node):
                    to_type_str, is_ptr, is_fp, _, _, _, _, _ = _format_pycparser_type(node.to_type)
                    # Check if target cast type is data pointer (e.g. void *) or integer type (e.g. int, long, uintptr_t, uint32_t)
                    is_data_ptr_or_int = (is_ptr and "void" in to_type_str) or any(it in to_type_str for it in ['int', 'long', 'short', 'intptr_t', 'uintptr_t', 'uint32_t', 'uint64_t', 'size_t'])

                    if is_data_ptr_or_int and not is_fp:
                        # Check expression being cast
                        expr_ids = _extract_identifiers_from_ast(node.expr)
                        fn_ids = expr_ids.intersection(all_func_symbols)
                        if fn_ids:
                            line_no = (node.coord.line - _PRELUDE_LINE_COUNT) if node.coord else 1
                            target = sorted(list(fn_ids))[0]
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else _format_pycparser_expr(node)
                            issues.append(self.outer_rule.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Dangerous function pointer conversion for '{target}' (cast between function pointer and data pointer/integer violates ISO C and Control Flow Integrity).",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.MANUAL_REVIEW,
                            ))

                    self.generic_visit(node)

            FuncPtrCastVisitor(self).visit(ast_ctx.pycparser_ast)
        else:
            # Fallback AST analysis using regex & known function symbols
            cast_regex = re.compile(r'\(\s*(?:void\s*\*|int|long|short|uint32_t|uint64_t|intptr_t|uintptr_t|size_t|unsigned\s+int)\s*\)\s*([a-zA-Z_]\w*)\b')
            for line_no, line in enumerate(ast_ctx.source_lines, 1):
                for m in cast_regex.finditer(line):
                    target = m.group(1)
                    if target in all_func_symbols or any(k in target.lower() for k in ['_handler', '_fn', '_callback', '_hook', 'func', 'proc']):
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=line.strip(),
                            message=f"Dangerous function pointer conversion for '{target}' (cast between function pointer and data pointer/integer violates ISO C and Control Flow Integrity).",
                            column_number=m.start() + 1,
                            engine="AST",
                            fix_type=FixType.MANUAL_REVIEW,
                        ))

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Cast to (void *) or (int) / (long) on function names or func ptrs
        m = re.search(r'\(\s*(?:void\s*\*|int|long|uint32_t|unsigned\s+int)\s*\)\s*([a-zA-Z_]\w*(?:_handler|_fn|_callback|_hook|func))\b', line_content)
        if m:
            target = m.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Dangerous function pointer conversion for '{target}' (cast between function pointer and data pointer/integer violates ISO C and Control Flow Integrity).",
                column_number=m.start() + 1,
                engine="Regex",
                fix_type=FixType.MANUAL_REVIEW,
            ))
        return issues


class SinglePointOfFailureControlFlowRule(BaseRule):
    rule_id = "CGULL-016"
    name = "Single-Point-of-Failure Control Flow"
    impact = Severity.MEDIUM
    category = RuleCategory.CONTROL_FLOW
    description = "Flag simple boolean return checks (1/0 or true/false) in critical security, auth, or secure boot functions vulnerable to fault injection glitching."
    implementation_method = "AST parsing to check return types and state macros in security/auth functions"
    implementation_complexity = "Medium"
    chances_of_false_positives = "High"
    cwe_id = "CWE-1240"
    remediation_suggestion = "Use multi-bit hamming-distance status words (e.g. AUTH_SUCCESS = 0x5A5A5A5A, AUTH_FAILED = 0xA5A5A5A5) to protect against single-bit clock/voltage glitching."
    sample_vulnerable_code = "int verify_boot_signature(void) {\n    if (check_keys()) return 1;\n    return 0; // A 1-bit CPU fault can bypass security\n}"
    sample_remediated_code = "#define SECURE_OK 0x5A5A5A5AU\n#define SECURE_FAIL 0xA5A5A5A5U\nuint32_t verify_boot_signature(void) {\n    if (check_keys()) return SECURE_OK;\n    return SECURE_FAIL;\n}"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            if fn.returns_boolean:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=fn.start_line,
                    code_snippet=f"{fn.return_type} {fn.name}(...)",
                    message=f"Security function '{fn.name}' returns simple binary 0/1 boolean. Hardware glitch or single-bit flip can bypass authorization.",
                    column_number=1,
                    engine="AST",
                    fix_type=FixType.MANUAL_REVIEW,
                ))
        return issues


class InsecureDataStorageRule(BaseRule):
    rule_id = "CGULL-024"
    name = "Insecure Data Storage"
    impact = Severity.MEDIUM
    category = RuleCategory.CRYPTO
    description = "Flag storage of sensitive data (passwords, encryption keys, auth tokens) in plaintext static buffers or unencrypted memory."
    implementation_method = "AST parsing and lexical matching to track sensitive variable names and plaintext string literals"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-312 / CWE-798"
    remediation_suggestion = "Do not hardcode secrets or store credentials in static plaintext memory. Use hardware keystores (TPM/HSM) or secure enclave storage."
    sample_vulnerable_code = "const char *admin_password = \"SuperSecret123!\";\nchar api_key[64] = \"AIzaSyD-secret-key\";"
    sample_remediated_code = "// Load credentials dynamically from secure vault/environment\nchar *api_key = getenv(\"API_KEY\");"
    analysis_engine = AnalysisEngine.REGEX

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Match hardcoded password/key/secret strings
        m = re.search(r'(?:char\s*\*|char\s+\w+\[\]|string)\s*(\w*(?:password|secret|apikey|api_key|private_key|auth_token)\w*)\s*=\s*"([^"]+)"', line_content, re.IGNORECASE)
        if m:
            var_name = m.group(1)
            val = m.group(2)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Hardcoded sensitive credential/key in plaintext variable '{var_name}' (CWE-312/CWE-798).",
                column_number=m.start() + 1,
                engine="Regex",
                fix_type=FixType.MANUAL_REVIEW,
            ))
        return issues
