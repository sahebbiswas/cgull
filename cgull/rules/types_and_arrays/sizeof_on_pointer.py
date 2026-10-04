"""
Rules for Arrays, Integer Overflows, VLAs, Bitwise Operations, and Magic Numbers.
"""

import re
import logging
from typing import Dict, List, Optional, Set, Tuple

from ..base import BaseRule
from ...models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ...ast_analyzer import CASTContext, CFunction, CFGNode, CVariable, CParameter
from ..dead_store_parameters import _fallback_line_scopes, _local_hides_parameter, _raw_local_bindings

logger = logging.getLogger(__name__)


class SizeofOnPointerRule(BaseRule):
    rule_id = "CGULL-029"
    name = "sizeof() on Pointer Type"
    impact = Severity.HIGH
    category = RuleCategory.ARITHMETIC
    description = "Flag the use of sizeof() on a pointer variable. This returns the size of the pointer (e.g., 4 or 8 bytes) rather than the size of the pointed-to memory block, often leading to heap buffer overflows or incomplete memory clearing."
    implementation_method = "AST parsing to check if variables passed to sizeof are declared as pointers"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-467"
    remediation_suggestion = "Use the size of the underlying type (e.g., sizeof(*ptr)) or track the allocated size explicitly."
    sample_vulnerable_code = "char *ptr = malloc(256);\nmemset(ptr, 0, sizeof(ptr)); // Clears only 8 bytes"
    sample_remediated_code = "char *ptr = malloc(256);\nmemset(ptr, 0, 256); // Or track size in a variable"
    analysis_engine = AnalysisEngine.AST

    @staticmethod
    def _is_pointer_binding(binding) -> bool:
        if getattr(binding, "is_pointer", False):
            return True
        type_name = getattr(binding, "type_name", "") or ""
        name = getattr(binding, "name", "") or ""
        return "*" in type_name or "*" in name

    @staticmethod
    def _is_pointer_or_decayed_param(param) -> bool:
        if getattr(param, "is_pointer", False) or getattr(param, "is_array", False):
            return True
        type_name = getattr(param, "type_name", "") or ""
        name = getattr(param, "name", "") or ""
        return "*" in type_name or "*" in name or "[" in type_name or "[" in name

    @staticmethod
    def _resolve_symbol_at_location(
        var_name: str,
        node_line: int,
        fn: CFunction,
        ast_ctx: CASTContext,
        line_scopes: Dict[int, Tuple[int, ...]],
        decl_scopes: Dict[int, Tuple[int, ...]],
        fn_start: int,
        fn_start_exp: int,
    ) -> Tuple[Optional[str], Optional[object]]:
        # 1. Local variable in lexical scope
        if line_scopes:
            offset = node_line - fn_start
            if offset not in line_scopes:
                offset = node_line - fn_start_exp
            current_scope = line_scopes.get(offset, ())
            matching_locals = []
            for c_var in _raw_local_bindings(fn):
                if _local_hides_parameter(c_var, var_name, current_scope, node_line, decl_scopes):
                    matching_locals.append(c_var)
            if matching_locals:
                # Innermost scope wins: longest scope chain or latest declaration line
                best = max(
                    matching_locals,
                    key=lambda v: (
                        len(decl_scopes.get(getattr(v, "declaration_line", 0), ())),
                        getattr(v, "declaration_line", 0),
                    ),
                )
                return ("local", best)

        if var_name in fn.variables:
            for c_var in _raw_local_bindings(fn):
                if getattr(c_var, "name", None) == var_name:
                    decl_line = getattr(c_var, "declaration_line", 0)
                    if decl_line == 0 or node_line == 0 or decl_line <= node_line:
                        if not line_scopes:
                            return ("local", c_var)

        # 2. Function parameter (shadows globals)
        for param in getattr(fn, "parameters", ()):
            if getattr(param, "name", None) == var_name:
                return ("param", param)

        # 3. Global variable
        if getattr(ast_ctx, "global_variables", None) and var_name in ast_ctx.global_variables:
            return ("global", ast_ctx.global_variables[var_name])

        return (None, None)

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []

        for fn in ast_ctx.functions:
            stmts, line_scopes = _fallback_line_scopes(fn) if getattr(fn, "body", None) else ([], {})
            fn_start = int(getattr(fn, "body_start_line", 0) or getattr(fn, "start_line", 0) or 1)
            fn_start_exp = int(getattr(fn, "body_start_line_exp", 0) or getattr(fn, "start_line_exp", 0) or fn_start)
            decl_scopes = {}
            for offset, scope in line_scopes.items():
                decl_scopes[fn_start + offset] = scope
                decl_scopes[fn_start_exp + offset] = scope

            for node in fn.cfg_nodes:
                if node.kind != "sizeof":
                    continue

                # node.expr_str will be "sizeof(...)"
                m = re.match(r'^sizeof\s*\(\s*([a-zA-Z_]\w*)\s*\)$', node.expr_str)
                if not m:
                    continue

                var_name = m.group(1)

                kind, binding = self._resolve_symbol_at_location(
                    var_name, node.line_number, fn, ast_ctx, line_scopes, decl_scopes, fn_start, fn_start_exp
                )

                is_ptr = False
                if kind == "local":
                    is_ptr = self._is_pointer_binding(binding)
                elif kind == "param":
                    is_ptr = self._is_pointer_or_decayed_param(binding)
                elif kind == "global":
                    is_ptr = self._is_pointer_binding(binding)

                if is_ptr:
                    # Get snippet safely from clean_source or source_lines
                    line_no = node.line_number
                    if line_no > 0 and line_no <= len(ast_ctx.source_lines):
                        code_snippet = ast_ctx.source_lines[line_no - 1].strip()
                    else:
                        code_snippet = node.expr_str

                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=node.line_number,
                        code_snippet=code_snippet,
                        message=f"sizeof() used on pointer type '{var_name}'. This returns the size of the pointer, not the allocated memory.",
                        column_number=1,
                        engine="AST",
                        fix_type=FixType.MANUAL_REVIEW,
                    ))
        return issues

