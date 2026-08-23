"""
Rules for Cryptography, Timing Attack Prevention, Type Qualifiers, and Fault Injection.
"""

import re
from typing import List, Optional, Tuple, Set, Dict
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
        'length', 'size', 'index', 'driver', 'given', 'derive'
    ]
    if any(non_sec in t for non_sec in non_sec_terms):
        return False

    substring_terms = [
        'secret', 'password', 'passwd', 'token', 'auth', 'hash', 'digest',
        'hmac', 'cert', 'credential', 'cred', 'privkey', 'private_key',
        'session', 'apikey', 'api_key', 'nonce', 'salt', 'seed'
    ]
    segment_terms = ['iv', 'pin', 'mac']

    parts = [p for p in re.split(r'[^a-z0-9]', t) if p]

    if any(k in t for k in substring_terms):
        if 'sig' in t and not ('signature' in t or 'sig' in parts):
            return False
        if 'pass' in t and not ('password' in t or 'passwd' in t or 'pass' in parts):
            return False
        return True

    if any(k in parts for k in segment_terms):
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


def _is_predictable_or_constant_seed(expr: str) -> bool:
    """
    Check if a seed expression for srand/srandom is predictable or constant.
    Predictable sources include time(), clock(), getpid(), getppid(), gettimeofday(), clock_gettime().
    Constant seeds include integer literals (0, 1, 42, 0x1234), NULL, or simple constant expressions.
    """
    s = expr.strip()
    if not s:
        return True

    predictable_fn_regex = re.compile(r'\b(time|clock|getpid|getppid|gettimeofday|clock_gettime|timespec_get)\s*\(')
    if predictable_fn_regex.search(s):
        return True

    uncasted = re.sub(r'^\s*\(\s*(?:unsigned\s+|signed\s+|int|long|short|uint32_t|time_t)*\s*\)\s*', '', s).strip()

    if uncasted in ("0", "NULL", "1"):
        return True

    if re.match(r'^(?:0x[0-9a-fA-F]+|\d+)[uUlL]*$', uncasted):
        return True

    if re.match(r'^[A-Z_][A-Z0-9_]*$', uncasted):
        return True

    return False


def _is_security_function_context(fn_name: str) -> bool:
    """Check if a function name indicates a security-relevant context."""
    f = fn_name.lower()
    parts = [p for p in re.split(r'[^a-z0-9]', f) if p]

    sec_substrings = [
        'auth', 'login', 'permission', 'credential', 'crypto', 'security',
        'token', 'password', 'passwd', 'signature', 'hmac', 'pfx', 'cert',
        'verifier', 'authenticate', 'sec_cmp', 'nonce', 'salt', 'seed'
    ]
    sec_segments = ['iv', 'pin', 'mac']

    if any(term in f for term in sec_substrings):
        return True

    if any(term in parts for term in sec_segments):
        return True

    if any(action in f for action in ['check', 'verify', 'validate', 'compare', 'generate', 'create', 'init', 'get', 'make', 'derive']):
        if any(noun in f for noun in ['hash', 'token', 'mac', 'sig', 'key', 'secret', 'auth', 'cert', 'pin', 'cred', 'pass', 'nonce', 'salt', 'seed']) or any(noun in parts for noun in ['iv']):
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

            for call in fn.calls:
                callee, line_no, raw_args = call[0], call[1], call[2]
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


def _split_fn_args(raw_args: str) -> List[str]:
    """Split comma-separated arguments at top paren/quote depth."""
    args = []
    curr = []
    paren = 0
    in_quote = False
    quote_char = None
    for i, c in enumerate(raw_args):
        if in_quote:
            curr.append(c)
            if c == quote_char and (i == 0 or raw_args[i - 1] != '\\'):
                in_quote = False
        elif c in ('"', "'"):
            in_quote = True
            quote_char = c
            curr.append(c)
        elif c in ('(', '[', '{'):
            paren += 1
            curr.append(c)
        elif c in (')', ']', '}'):
            paren -= 1
            curr.append(c)
        elif c == ',' and paren == 0:
            args.append("".join(curr).strip())
            curr = []
        else:
            curr.append(c)
    if curr:
        args.append("".join(curr).strip())
    return args


def _clean_path_arg(expr: str) -> str:
    """Normalize path argument expression for comparison by removing casts and parens."""
    s = expr.strip()
    s = re.sub(r'^\s*\(\s*(?:const\s+)?char\s*\*+\s*\)\s*', '', s)
    s = re.sub(r'^\s*\(\s*(?:void\s*\*|int|long)\s*\)\s*', '', s)
    s = s.strip().lstrip('(').rstrip(')')
    return re.sub(r'\s+', '', s)


def _extract_balanced_parens(text: str, start_paren_pos: int) -> Tuple[Optional[str], int]:
    """
    Given text and position of opening '(', returns (inside_args_str, closing_paren_pos).
    Handles string literals, character literals, escape sequences, and nested parens.
    """
    if start_paren_pos >= len(text) or text[start_paren_pos] != '(':
        return None, start_paren_pos

    paren_depth = 0
    in_string = False
    in_char = False
    escape = False
    j = start_paren_pos
    n = len(text)

    while j < n:
        c = text[j]
        if escape:
            escape = False
        elif c == '\\':
            escape = True
        elif c == '"' and not in_char:
            in_string = not in_string
        elif c == "'" and not in_string:
            in_char = not in_char
        elif not in_string and not in_char:
            if c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth -= 1
                if paren_depth == 0:
                    return text[start_paren_pos + 1 : j], j
        j += 1

    return None, j


def _find_else_branch_calls(pycparser_ast) -> Set[Tuple[int, int]]:
    """Find pairs of (check_line, else_use_line) where use is in the iffalse branch of check_cond."""
    from pycparser import c_ast
    excluded_pairs = set()

    class IfVisitor(c_ast.NodeVisitor):
        def visit_If(self, node):
            if node.cond and node.iffalse:
                cond_calls = []
                class CondVisitor(c_ast.NodeVisitor):
                    def visit_FuncCall(self, call_node):
                        callee = _format_pycparser_expr(call_node.name)
                        if callee in CHECK_FILE_FUNCS:
                            line_no = (call_node.coord.line - _PRELUDE_LINE_COUNT) if call_node.coord else 1
                            cond_calls.append((callee, line_no))
                CondVisitor().visit(node.cond)

                if cond_calls:
                    iffalse_line_nos = []
                    class ElseVisitor(c_ast.NodeVisitor):
                        def visit_FuncCall(self, call_node):
                            callee = _format_pycparser_expr(call_node.name)
                            if callee in USE_FILE_FUNCS:
                                line_no = (call_node.coord.line - _PRELUDE_LINE_COUNT) if call_node.coord else 1
                                iffalse_line_nos.append(line_no)
                    ElseVisitor().visit(node.iffalse)

                    for _, check_line in cond_calls:
                        for use_line in iffalse_line_nos:
                            excluded_pairs.add((check_line, use_line))

            self.generic_visit(node)

    if pycparser_ast:
        IfVisitor().visit(pycparser_ast)

    return excluded_pairs


CHECK_FILE_FUNCS: dict = {
    "access": 0,
    "faccessat": 1,
    "stat": 0,
    "lstat": 0,
    "fstatat": 1,
}

USE_FILE_FUNCS: dict = {
    "open": 0,
    "openat": 1,
    "fopen": 0,
    "freopen": 0,
    "chmod": 0,
    "fchmodat": 1,
    "chown": 0,
    "fchownat": 1,
    "remove": 0,
    "unlink": 0,
    "unlinkat": 1,
    "rmdir": 0,
    "truncate": 0,
}


class ToctouFileAccessRule(BaseRule):
    rule_id = "CGULL-035"
    name = "Time-of-Check to Time-of-Use (TOCTOU) File Access"
    impact = Severity.HIGH
    category = RuleCategory.CONTROL_FLOW
    description = "Detect time-of-check to time-of-use (TOCTOU) file access race conditions where file status/access checks (access, stat, lstat, faccessat, fstatat) are followed by file operations (open, fopen, chmod, chown, remove, unlink, rmdir, truncate, etc.) on the same file path."
    implementation_method = "AST / CFG call sequencing & regex lookahead for path argument identity"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-367"
    remediation_suggestion = "Avoid separate check-then-act file access calls. Open the file first and perform status/access checks directly on the opened file descriptor using fstat(), fchmod(), or fchown() to eliminate race conditions."
    sample_vulnerable_code = "if (access(filepath, R_OK) == 0) {\n    fd = open(filepath, O_RDONLY);\n}"
    sample_remediated_code = "fd = open(filepath, O_RDONLY);\nif (fd >= 0) {\n    fstat(fd, &st);\n}"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        else_pairs = _find_else_branch_calls(ast_ctx.pycparser_ast) if ast_ctx.pycparser_ast else set()

        for fn in ast_ctx.functions:
            check_calls = []
            for idx, call in enumerate(fn.calls):
                callee, line_no, raw_args = call[0], call[1], call[2]
                if callee in CHECK_FILE_FUNCS:
                    args = _split_fn_args(raw_args)
                    arg_idx = CHECK_FILE_FUNCS[callee]
                    if arg_idx < len(args):
                        raw_path = args[arg_idx]
                        clean_path = _clean_path_arg(raw_path)
                        if clean_path:
                            check_calls.append((idx, callee, line_no, raw_path, clean_path))

            if not check_calls:
                continue

            reported_pairs = set()
            for check_idx, check_fn, check_line, raw_path, clean_path in check_calls:
                path_var = re.findall(r'\b[a-zA-Z_]\w*\b', clean_path)
                var_name = path_var[0] if path_var else None

                for use_idx in range(check_idx + 1, len(fn.calls)):
                    use_call = fn.calls[use_idx]
                    use_fn, use_line, raw_use_args = use_call[0], use_call[1], use_call[2]
                    if use_line < check_line:
                        continue
                    if (check_line, use_line) in else_pairs:
                        continue

                    if use_fn in USE_FILE_FUNCS:
                        use_args = _split_fn_args(raw_use_args)
                        use_arg_idx = USE_FILE_FUNCS[use_fn]
                        if use_arg_idx < len(use_args):
                            raw_use_path = use_args[use_arg_idx]
                            clean_use_path = _clean_path_arg(raw_use_path)

                            if clean_use_path == clean_path:
                                reassigned = False
                                if var_name and var_name in fn.variables:
                                    v_obj = fn.variables[var_name]
                                    if any(check_line < assign_l <= use_line for assign_l in v_obj.assigned_lines):
                                        reassigned = True

                                if not ast_ctx.pycparser_ast:
                                    body_lines = fn.body.splitlines()
                                    start_offset = max(0, check_line - fn.start_line)
                                    end_offset = min(len(body_lines), use_line - fn.start_line + 1)
                                    sub_body = " ".join(body_lines[start_offset:end_offset])
                                    if "else" in sub_body and any(re.search(r'\belse\b', l) for l in body_lines[start_offset:max(start_offset, end_offset - 1)]):
                                        reassigned = True

                                if not reassigned and (check_line, use_line) not in reported_pairs:
                                    snippet = ast_ctx.source_lines[use_line - 1].strip() if 1 <= use_line <= len(ast_ctx.source_lines) else f"{use_fn}({raw_use_args})"
                                    issues.append(self.create_issue(
                                        file_path=file_path,
                                        line_number=use_line,
                                        code_snippet=snippet,
                                        message=f"TOCTOU (Time-of-Check to Time-of-Use) file access risk: '{check_fn}()' check at line {check_line} on '{raw_path}' followed by '{use_fn}()' operation (CWE-367).",
                                        column_number=1,
                                        engine="AST",
                                        fix_type=FixType.SUGGESTED_FIX,
                                        suggested_fix_replacement="Open file descriptor directly and perform operations on fd (e.g. open() then fstat())",
                                    ))
                                    reported_pairs.add((check_line, use_line))

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        if line_content.lstrip().startswith('#'):
            return issues

        target_line = masked_line_content if masked_line_content else line_content
        check_pattern = re.compile(
            r'\b(access|faccessat|stat|lstat|fstatat)\s*\('
        )

        m = check_pattern.search(target_line)
        if not m:
            return issues

        check_fn = m.group(1)
        start_paren_pos = m.end() - 1

        raw_args_masked, _ = _extract_balanced_parens(target_line, start_paren_pos)
        if raw_args_masked is None:
            return issues

        raw_args_unmasked, _ = _extract_balanced_parens(line_content, start_paren_pos)
        raw_args_display = raw_args_unmasked if raw_args_unmasked is not None else raw_args_masked

        args_masked = _split_fn_args(raw_args_masked)
        args_display = _split_fn_args(raw_args_display)

        arg_idx = CHECK_FILE_FUNCS.get(check_fn, 0)
        if arg_idx >= len(args_masked):
            return issues

        clean_path = _clean_path_arg(args_masked[arg_idx])
        raw_path_display = args_display[arg_idx] if arg_idx < len(args_display) else args_masked[arg_idx]

        if not clean_path:
            return issues

        path_var = re.findall(r'\b[a-zA-Z_]\w*\b', clean_path)
        var_name = path_var[0] if path_var else None

        use_pattern = re.compile(
            r'\b(open|openat|fopen|freopen|chmod|fchmodat|chown|fchownat|remove|unlink|unlinkat|rmdir|truncate)\s*\('
        )

        from ..utils import mask_string_and_char_literals
        masked_lines = [mask_string_and_char_literals(l) for l in source_lines]
        limit = min(line_number + 50, len(source_lines))
        net_depth = 0
        in_else_branch = False

        for j in range(line_number - 1, limit):
            future_line = source_lines[j]
            future_target_line = masked_lines[j] if j < len(masked_lines) else future_line

            if j > line_number - 1 and var_name and re.search(rf'\b{re.escape(var_name)}\s*=(?!=)', future_target_line):
                break

            if j > line_number - 1 and re.search(r'\belse\b', future_target_line):
                in_else_branch = True

            if not in_else_branch:
                for m_use in use_pattern.finditer(future_target_line):
                    use_fn = m_use.group(1)
                    u_start_paren = m_use.end() - 1

                    u_args_masked, _ = _extract_balanced_parens(future_target_line, u_start_paren)
                    if u_args_masked is None:
                        continue

                    u_args = _split_fn_args(u_args_masked)
                    u_arg_idx = USE_FILE_FUNCS.get(use_fn, 0)
                    if u_arg_idx < len(u_args):
                        clean_u_path = _clean_path_arg(u_args[u_arg_idx])
                        if clean_u_path == clean_path:
                            use_line_no = j + 1
                            if use_line_no == line_number and u_start_paren <= start_paren_pos:
                                continue

                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=use_line_no,
                                code_snippet=future_line.strip(),
                                message=f"TOCTOU (Time-of-Check to Time-of-Use) file access risk: '{check_fn}()' check at line {line_number} on '{raw_path_display}' followed by '{use_fn}()' operation (CWE-367).",
                                column_number=m_use.start() + 1,
                                engine="Regex",
                                fix_type=FixType.SUGGESTED_FIX,
                                suggested_fix_replacement="Open file descriptor directly and perform operations on fd (e.g. open() then fstat())",
                            ))
                            break
                if issues:
                    break

            if j >= line_number - 1:
                depth_delta = future_line.count('{') - future_line.count('}')
                net_depth += depth_delta
                if j > line_number - 1 and net_depth < 0:
                    break

        return issues


class WeakCryptoPrimitivesRule(BaseRule):
    rule_id = "CGULL-031"
    name = "Weak/Broken Cryptographic Primitives"
    impact = Severity.HIGH
    category = RuleCategory.CRYPTO
    description = "Detect calls to weak or broken cryptographic algorithms (MD5, SHA-1 in security contexts, DES, RC4, ECB cipher mode variants)."
    implementation_method = "AST function call inspection and lexical matching for weak crypto routines and ECB cipher modes"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-327"
    remediation_suggestion = "Use modern cryptographic primitives like SHA-256/3 for hashing, AES-GCM or ChaCha20-Poly1305 for authenticated encryption instead of MD5, SHA-1, DES, RC4, or ECB mode."
    sample_vulnerable_code = "MD5(data, len, digest);\nEVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);"
    sample_remediated_code = "SHA256(data, len, digest);\nEVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        clean_lines = ast_ctx.clean_source.splitlines() if ast_ctx.clean_source else ast_ctx.source_lines

        for fn in ast_ctx.functions:
            fn_is_sec_ctx = _is_security_function_context(fn.name)

            for call in fn.calls:
                callee, line_no, raw_args = call[0], call[1], call[2]
                line_content = ast_ctx.source_lines[line_no - 1] if 1 <= line_no <= len(ast_ctx.source_lines) else ""
                clean_line = clean_lines[line_no - 1] if 1 <= line_no <= len(clean_lines) else line_content

                primitive_kind = None
                message = ""

                # 1. MD5 / EVP_md5
                if callee in ("MD5", "EVP_md5") or callee.startswith("MD5_"):
                    primitive_kind = "MD5"
                    message = f"Use of weak/broken cryptographic hash function '{callee}()' (CWE-327)."
                # 2. SHA1 / EVP_sha1 / EVP_md5_sha1
                elif callee in ("SHA1", "EVP_sha1", "EVP_md5_sha1") or callee.startswith("SHA1_"):
                    should_flag = fn_is_sec_ctx
                    if not should_flag:
                        tokens = re.findall(r'\b[a-zA-Z_]\w*\b', clean_line + " " + raw_args)
                        if any(_is_sensitive_identifier(t) for t in tokens if t not in (callee, "SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final", "EVP_sha1", "EVP_md5_sha1")):
                            should_flag = True
                    if should_flag:
                        primitive_kind = "SHA1"
                        message = f"Use of weak cryptographic hash function '{callee}()' in security-sensitive context (CWE-327)."
                # 3. DES_*
                elif callee.startswith("DES_") or callee == "DES":
                    primitive_kind = "DES"
                    message = f"Use of weak/deprecated encryption algorithm '{callee}()' (CWE-327)."
                # 4. RC4
                elif callee == "RC4" or callee.startswith("RC4_"):
                    primitive_kind = "RC4"
                    message = f"Use of weak/broken stream cipher '{callee}()' (CWE-327)."
                # 5. ECB cipher modes
                elif callee.startswith("EVP_") and ("_ecb" in callee or "ecb" in callee):
                    primitive_kind = "ECB"
                    message = f"Use of insecure Electronic Codebook (ECB) cipher mode '{callee}()' (CWE-327)."
                # Also check if raw_args contains weak hash getters or ECB cipher calls
                elif re.search(r'\b(?:EVP_md5|EVP_sha1|EVP_md5_sha1|EVP_[A-Za-z0-9_]*ecb[A-Za-z0-9_]*|DES_[A-Za-z0-9_]*ecb[A-Za-z0-9_]*)\s*\(\s*\)', raw_args):
                    weak_m = re.search(r'\b(EVP_md5|EVP_sha1|EVP_md5_sha1|EVP_[A-Za-z0-9_]*ecb[A-Za-z0-9_]*|DES_[A-Za-z0-9_]*ecb[A-Za-z0-9_]*)\s*\(\s*\)', raw_args)
                    weak_fn = weak_m.group(1) if weak_m else "weak primitive"
                    if "sha1" in weak_fn:
                        primitive_kind = "SHA1"
                        message = f"Use of weak cryptographic hash function '{weak_fn}()' in security-sensitive context (CWE-327)."
                    elif "md5" in weak_fn:
                        primitive_kind = "MD5"
                        message = f"Use of weak/broken cryptographic hash function '{weak_fn}()' (CWE-327)."
                    else:
                        primitive_kind = "ECB"
                        message = f"Use of insecure Electronic Codebook (ECB) cipher mode '{weak_fn}()' (CWE-327)."

                if primitive_kind and message:
                    snippet = line_content.strip() if line_content else f"{callee}({raw_args})"
                    sug_fix = "SHA-256/3, ChaCha20-Poly1305, or AES-GCM"
                    if primitive_kind in ("MD5", "SHA1"):
                        sug_fix = "SHA-256 or SHA-3"
                    elif primitive_kind in ("DES", "RC4", "ECB"):
                        sug_fix = "AES-256-GCM or ChaCha20-Poly1305"

                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        message=message,
                        column_number=1,
                        engine="AST",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=sug_fix
                    ))

        return issues

    @staticmethod
    def _is_decl_or_prototype(line_content: str, match_pos: int) -> bool:
        prefix = line_content[:match_pos].strip()
        if not prefix:
            return False
        first_token = prefix.split()[0]
        type_keywords = {"unsigned", "signed", "char", "int", "void", "short", "long", "struct", "enum", "union", "extern", "typedef", "static", "inline", "const", "volatile", "unsigned char", "size_t"}
        if first_token in type_keywords:
            if ";" in line_content and not re.search(r'=\s*|\bif\b|\bwhile\b|\breturn\b', prefix):
                return True
        return False

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        if line_content.lstrip().startswith('#'):
            return issues

        target_line = masked_line_content if masked_line_content else line_content

        from ..utils import mask_string_and_char_literals

        # 1. MD5 / EVP_md5
        m_md5 = re.search(r'\b(MD5|MD5_Init|MD5_Update|MD5_Final|MD5_[A-Za-z0-9_]+|EVP_md5)\s*\(', target_line)
        if m_md5 and not self._is_decl_or_prototype(line_content, m_md5.start()):
            fn_name = m_md5.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Use of weak/broken cryptographic hash function '{fn_name}()' (CWE-327).",
                column_number=m_md5.start() + 1,
                engine="Regex",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement="SHA-256 or SHA-3"
            ))

        # 2. SHA1 / EVP_sha1 / EVP_md5_sha1 (in sec context)
        m_sha1 = re.search(r'\b(SHA1|SHA1_Init|SHA1_Update|SHA1_Final|SHA1_[A-Za-z0-9_]+|EVP_sha1|EVP_md5_sha1)\s*\(', target_line)
        if m_sha1 and not self._is_decl_or_prototype(line_content, m_sha1.start()):
            fn_name = m_sha1.group(1)
            start_line_idx = max(0, line_number - 4)
            end_line_idx = min(line_number, len(source_lines))
            context_lines = [
                mask_string_and_char_literals(source_lines[i]) for i in range(start_line_idx, end_line_idx)
            ]
            context_str = " ".join(context_lines)
            tokens = re.findall(r'\b[a-zA-Z_]\w*\b', context_str)
            if any(_is_sensitive_identifier(t) for t in tokens if not t.startswith("SHA1") and not t.startswith("EVP_sha1") and not t.startswith("EVP_md5")):
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Use of weak cryptographic hash function '{fn_name}()' in security-sensitive context (CWE-327).",
                    column_number=m_sha1.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement="SHA-256 or SHA-3"
                ))

        # 3. DES_*
        m_des = re.search(r'\b(DES_[A-Za-z0-9_]+|DES)\s*\(', target_line)
        if m_des and not self._is_decl_or_prototype(line_content, m_des.start()):
            fn_name = m_des.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Use of weak/deprecated encryption algorithm '{fn_name}()' (CWE-327).",
                column_number=m_des.start() + 1,
                engine="Regex",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement="AES-256-GCM or ChaCha20-Poly1305"
            ))

        # 4. RC4
        m_rc4 = re.search(r'\b(RC4|RC4_set_key|RC4_[A-Za-z0-9_]+)\s*\(', target_line)
        if m_rc4 and not self._is_decl_or_prototype(line_content, m_rc4.start()):
            fn_name = m_rc4.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Use of weak/broken stream cipher '{fn_name}()' (CWE-327).",
                column_number=m_rc4.start() + 1,
                engine="Regex",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement="AES-256-GCM or ChaCha20-Poly1305"
            ))

        # 5. ECB cipher modes
        m_ecb = re.search(r'\b(EVP_[A-Za-z0-9_]*ecb[A-Za-z0-9_]*)\s*\(', target_line)
        if m_ecb and not self._is_decl_or_prototype(line_content, m_ecb.start()):
            fn_name = m_ecb.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Use of insecure Electronic Codebook (ECB) cipher mode '{fn_name}()' (CWE-327).",
                column_number=m_ecb.start() + 1,
                engine="Regex",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement="AES-256-GCM or ChaCha20-Poly1305"
            ))

        return issues


class NoInsecureRandRule(BaseRule):
    rule_id = "CGULL-028"
    name = "Insecure PRNG for Security-Sensitive Use"
    impact = Severity.HIGH
    category = RuleCategory.CRYPTO
    description = "rand(), random(), drand48(), or srand(time(NULL)) are non-cryptographic PRNGs and vulnerable to prediction or seed recovery when used for security-sensitive values."
    implementation_method = "AST function calls / AST variable tracking & regex pattern matching in security-sensitive contexts"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-338"
    remediation_suggestion = "Replace rand()/random()/srand() with cryptographically secure random sources such as getrandom(), arc4random(), arc4random_buf(), or OpenSSL RAND_bytes()."
    sample_vulnerable_code = "int token = rand();\nsrand(time(NULL));"
    sample_remediated_code = "uint32_t token = arc4random();\n// Or getrandom(&token, sizeof(token), 0);"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        target_funcs = {"rand", "random", "drand48", "mrand48", "lrand48", "srand", "srandom"}
        clean_lines = ast_ctx.clean_source.splitlines() if ast_ctx.clean_source else ast_ctx.source_lines

        for fn in ast_ctx.functions:
            fn_is_sec_ctx = _is_security_function_context(fn.name)

            # Build scope symbol types and names
            var_types: dict = {}
            for p in fn.parameters:
                var_types[p.name] = p.type_name.lower()
            for v_name, v_obj in fn.variables.items():
                var_types[v_name] = v_obj.type_name.lower()
            for g_name, g_obj in ast_ctx.global_variables.items():
                if g_name not in var_types:
                    var_types[g_name] = g_obj.type_name.lower()

            for call in fn.calls:
                callee, line_no, raw_args = call[0], call[1], call[2]
                target_var = call[3] if len(call) > 3 else None

                if callee in target_funcs:
                    line_content = ast_ctx.source_lines[line_no - 1] if 1 <= line_no <= len(ast_ctx.source_lines) else ""
                    clean_line = clean_lines[line_no - 1] if 1 <= line_no <= len(clean_lines) else line_content
                    should_flag = False

                    if callee in {"srand", "srandom"}:
                        if _is_predictable_or_constant_seed(raw_args) or fn_is_sec_ctx:
                            should_flag = True
                        else:
                            tokens = re.findall(r'\b[a-zA-Z_]\w*\b', clean_line)
                            if any(_is_sensitive_identifier(t) for t in tokens):
                                should_flag = True
                    else:
                        if fn_is_sec_ctx:
                            should_flag = True

                        if target_var and _is_sensitive_identifier(target_var):
                            should_flag = True

                        start_line_idx = max(0, line_no - 4)
                        context_snippet = " ".join(clean_lines[start_line_idx:line_no])
                        tokens = re.findall(r'\b[a-zA-Z_]\w*\b', context_snippet)
                        if any(_is_sensitive_identifier(t) for t in tokens if t not in target_funcs):
                            should_flag = True

                        for t_tok in tokens:
                            if _is_sensitive_type(var_types.get(t_tok, "")):
                                should_flag = True
                                break

                    if should_flag:
                        snippet = line_content.strip() if line_content else f"{callee}({raw_args})"
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Use of predictable pseudo-random number generator '{callee}()' in security-sensitive context (CWE-338).",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement="getrandom(), arc4random(), or OpenSSL RAND_bytes()"
                        ))

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        target_line = masked_line_content if masked_line_content else line_content

        target_regex = re.compile(r'\b(rand|random|drand48|mrand48|lrand48)\s*\(\s*\)|\b(srand|srandom)\s*\(([^)]*)\)')
        m = target_regex.search(target_line)
        if m:
            callee = m.group(1) or m.group(2)
            args = m.group(3) if m.group(3) else ""
            should_flag = False

            if callee in ("srand", "srandom"):
                if _is_predictable_or_constant_seed(args):
                    should_flag = True
                else:
                    tokens = re.findall(r'\b[a-zA-Z_]\w*\b', target_line)
                    if any(_is_sensitive_identifier(t) for t in tokens):
                        should_flag = True
            else:
                start_line_idx = max(0, line_number - 4)
                context_lines = [
                    masked_line_content if i == line_number - 1 and masked_line_content else source_lines[i]
                    for i in range(start_line_idx, line_number)
                    if i < len(source_lines)
                ]
                context_str = " ".join(context_lines)
                tokens = re.findall(r'\b[a-zA-Z_]\w*\b', context_str)
                if any(_is_sensitive_identifier(t) for t in tokens if t != callee):
                    should_flag = True

            if should_flag:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Use of predictable pseudo-random number generator '{callee}()' in security-sensitive context (CWE-338).",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement="getrandom(), arc4random(), or OpenSSL RAND_bytes()"
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
        m = re.search(r'(?:const\s+)?(?:char|string)\s*\*?\s*(\w*(?:password|secret|apikey|api_key|private_key|auth_token)\w*)\s*(?:\[[^\]]*\])?\s*=\s*"([^"]+)"', line_content, re.IGNORECASE)
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

class ImproperChrootJailRule(BaseRule):
    rule_id = "CGULL-039"
    name = "Improper chroot() Jail"
    impact = Severity.HIGH
    category = RuleCategory.CRYPTO
    description = "Detect calls to chroot() that are not immediately followed by chdir() to restrict the working directory. A missing chdir(\"/\") allows attackers to escape the chroot jail using relative paths."
    implementation_method = "AST traversal to find chroot() and ensure chdir() is called within the same function"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-243"
    remediation_suggestion = "Always call chdir(\"/\") or another directory inside the jail immediately after chroot() to restrict the working directory."
    sample_vulnerable_code = "chroot(\"/var/jail\");\n// FLAW: Missing chdir()"
    sample_remediated_code = "chroot(\"/var/jail\");\nchdir(\"/\");"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        clean_lines = ast_ctx.clean_source.splitlines() if ast_ctx.clean_source else ast_ctx.source_lines
        for fn in ast_ctx.functions:
            for i, call in enumerate(fn.calls):
                callee, line_no, args = call[0], call[1], call[2]
                if callee == "chroot":
                    has_subsequent_chdir = False
                    for j in range(i + 1, len(fn.calls)):
                        if fn.calls[j][0] == "chdir":
                            has_subsequent_chdir = True
                            break
                    if not has_subsequent_chdir:
                        if any(iss.line_number == line_no for iss in issues):
                            continue

                        line_idx = (line_no - 1) if (line_no and line_no > 0) else 0
                        clean_snippet = clean_lines[line_idx].strip() if line_idx < len(clean_lines) else f"chroot({args});"
                        snippet = ast_ctx.source_lines[line_idx].strip() if line_idx < len(ast_ctx.source_lines) else f"chroot({args});"
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message="chroot() called without a subsequent chdir(). This allows attackers to escape the chroot jail using relative paths (CWE-243).",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=clean_snippet.strip(";") + ";\nchdir(\"/\");"
                        ))

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        match_target = masked_line_content or line_content
        # fallback regex check
        if re.search(r'\bchroot\s*\(', match_target):
            has_chdir = False
            brace_depth = 0

            # Start tracking brace depth from the current line
            for i in range(line_number, len(source_lines) + 1):
                # Use masked content for lookahead to avoid string literals
                line = source_lines[i - 1]
                # A simplistic mask for lookahead
                masked_lookahead = re.sub(r'\"(\\.|[^\"])*\"', '""', line)
                masked_lookahead = re.sub(r"\'(\\.|[^\'])*\'", "''", masked_lookahead)

                # Check for chdir
                if re.search(r'\bchdir\s*\(', masked_lookahead):
                    if brace_depth >= 0:
                        has_chdir = True
                        break

                # Track braces
                brace_depth += masked_lookahead.count('{')
                brace_depth -= masked_lookahead.count('}')

                # If we exit the block, stop scanning
                if brace_depth < 0:
                    break

            if not has_chdir:
                m = re.search(r'\bchroot\s*\(', match_target)
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content.strip(),
                    message="chroot() called without a subsequent chdir(). This allows attackers to escape the chroot jail using relative paths (CWE-243).",
                    column_number=m.start() + 1 if m else 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=line_content.strip().strip(";") + ";\nchdir(\"/\");"
                ))
        return issues
