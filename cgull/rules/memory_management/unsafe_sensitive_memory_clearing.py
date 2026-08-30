"""
Memory Management Rule Submodule.
"""

import re
import logging
from typing import Dict, List, Optional, Set, Tuple

from ..base import BaseRule
from ..banned_functions import BannedFunctionsRule
from ...models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ...ast_analyzer import CASTContext, CFunction, get_type_byte_size, is_unsigned_type
from ...utils import extract_call_args, split_call_args, extract_balanced_parens
from ...cfg import StructuredCFG, CFGEvent, build_cfg, find_function_def, Nullness, Initialization, Allocation, analyze_function_summaries, FunctionSummary
from .helpers import (
    _brace_depths,
    _source_snippet,
    _ast_cfg_for_function,
    _find_unsafe_allocation_use,
    _find_unsafe_param_deref,
    _find_uaf_uses,
    _find_memory_leak_exits,
)

logger = logging.getLogger(__name__)
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
                    line_str = ast_ctx.source_lines[line_no - 1] if 0 < line_no <= len(ast_ctx.source_lines) else ""
                    matched_call = None
                    if line_str:
                        for m in re.finditer(r'\bmemset\s*\(', line_str):
                            inner, end_pos = extract_balanced_parens(line_str, m.end() - 1)
                            if inner is not None:
                                parts = split_call_args(inner)
                                if len(parts) == 3 and parts[1].strip() in ('0', '0U', '0x0', '0x00'):
                                    matched_call = (m.start() + 1, m.start(), end_pos + 1, parts[0].strip(), parts[1].strip(), parts[2].strip())
                                    break

                    if matched_call:
                        col_no, call_start, call_end, buf_expr, val_arg, len_arg = matched_call
                    else:
                        arg_parts = split_call_args(raw_args) if raw_args else []
                        if len(arg_parts) != 3 or arg_parts[1].strip() not in ('0', '0U', '0x0', '0x00'):
                            continue
                        buf_expr = arg_parts[0].strip()
                        val_arg = arg_parts[1].strip()
                        len_arg = arg_parts[2].strip()
                        col_no = 1
                        call_start, call_end = None, None

                    buf_idents = re.findall(r'\b[a-zA-Z_]\w*\b', buf_expr)
                    buf_name = buf_idents[0] if buf_idents else buf_expr

                    # Check if buf_name or any identifier in buf_expr is sensitive by name or type or function context
                    is_sensitive_name = any(any(k in ident.lower() for k in sensitive_name_keywords) for ident in buf_idents)
                    is_sensitive_type = False
                    for ident in buf_idents:
                        var_obj = fn.variables.get(ident)
                        if var_obj:
                            t_lower = var_obj.type_name.lower()
                            if any(k in t_lower for k in sensitive_name_keywords):
                                is_sensitive_type = True
                                break

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
                                if any(ident in next_n.read_vars for ident in buf_idents):
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
                        if call_start is not None and call_end is not None:
                            replacement_call = f"explicit_bzero({buf_expr}, {len_arg})"
                            replacement_line = line_str[:call_start] + replacement_call + line_str[call_end:]
                        else:
                            replacement_line = f"explicit_bzero({buf_expr}, {len_arg});"
                        snippet = line_str.strip() if line_str else f"memset({raw_args});"
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Potentially unsafe memory wipe using memset('{buf_expr}', 0, ...). Compilers frequently optimize out memset prior to return (Dead Store Elimination / CWE-14).",
                            column_number=col_no,
                            engine="AST",
                            fix_type=FixType.SAFE_FIX,
                            auto_fix_replacement=replacement_line.strip()
                        ))
        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        target = masked_line_content or line_content
        if target.lstrip().startswith('#'):
            return issues
        sensitive_name_keywords = {'key', 'secret', 'pass', 'passwd', 'password', 'token', 'auth', 'hash', 'iv', 'pin', 'cred', 'credential', 'priv', 'cert', 'seed', 'session'}
        for m in re.finditer(r'\bmemset\s*\(', target):
            start_paren_pos = m.end() - 1
            inner_str, closing_paren_pos = extract_balanced_parens(line_content, start_paren_pos)
            if inner_str is None:
                continue
            call_args = tuple(split_call_args(inner_str))
            if len(call_args) != 3:
                continue
            val_arg = call_args[1].strip()
            if val_arg not in ('0', '0U', '0x0', '0x00'):
                continue
            buf_expr = call_args[0].strip()
            len_arg = call_args[2].strip()
            buf_idents = re.findall(r'\b[a-zA-Z_]\w*\b', buf_expr)
            is_sensitive_name = any(any(k in ident.lower() for k in sensitive_name_keywords) for ident in buf_idents)
            is_near_return = False
            for offset in range(1, 4):
                if line_number - 1 + offset < len(source_lines):
                    next_l = source_lines[line_number - 1 + offset]
                    if "return" in next_l or next_l.strip() == "}":
                        is_near_return = True
                        break

            if is_sensitive_name and is_near_return:
                call_start = m.start()
                call_end = closing_paren_pos + 1
                replacement_call = f"explicit_bzero({buf_expr}, {len_arg})"
                replacement_line = line_content[:call_start] + replacement_call + line_content[call_end:]
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Potentially unsafe memory wipe using memset('{buf_expr}', 0, ...). Compilers frequently optimize out memset prior to return (Dead Store Elimination / CWE-14).",
                    column_number=call_start + 1,
                    engine="Regex",
                    fix_type=FixType.SAFE_FIX,
                    auto_fix_replacement=replacement_line.strip()
                ))
        return issues
