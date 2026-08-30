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
class ReallocOverwriteRule(BaseRule):
    rule_id = "CGULL-032"
    name = "Realloc-Overwrite Memory Leak"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect assigning realloc() return value directly to the pointer variable passed as its argument, which leaks memory if realloc() fails and returns NULL."
    implementation_method = "AST / Regex analysis to detect assignment of realloc return value to the same pointer identifier"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-401"
    remediation_suggestion = "Assign realloc() result to a temporary pointer, check for NULL, and update original pointer only on success: tmp = realloc(ptr, new_size); if (!tmp) { /* handle error, ptr remains valid */ } else { ptr = tmp; }"
    sample_vulnerable_code = "ptr = realloc(ptr, new_size);\nif (!ptr) {\n    return -1; // Leaked original memory block!\n}"
    sample_remediated_code = "void *tmp = realloc(ptr, new_size);\nif (!tmp) {\n    return -1; // ptr still valid\n}\nptr = tmp;"
    analysis_engine = AnalysisEngine.HYBRID

    DEFAULT_REALLOC_FUNCS = {"realloc"}

    def __init__(self, extra_realloc_funcs: Optional[List[str]] = None):
        super().__init__()
        self.realloc_funcs: Set[str] = set(self.DEFAULT_REALLOC_FUNCS)
        if extra_realloc_funcs:
            self.add_extra_realloc_funcs(extra_realloc_funcs)

    def add_extra_realloc_funcs(self, extra_reallocs: List[str]) -> None:
        self.realloc_funcs.update(extra_reallocs)

    @staticmethod
    def _extract_first_arg(raw_args: str) -> str:
        parts = split_call_args(raw_args)
        return parts[0].strip() if parts else raw_args.strip()

    @staticmethod
    def _clean_expr(expr: str) -> str:
        s = expr.strip()
        s = re.sub(r'^\s*\(\s*(?:[a-zA-Z_]\w*\s*\*+|\w+)\s*\)\s*', '', s)
        s = s.strip().lstrip('(').rstrip(')')
        return re.sub(r'\s+', '', s)

    @staticmethod
    def _reconstruct_statement(source_lines: List[str], line_no: int) -> Tuple[str, int]:
        if not source_lines or line_no < 1 or line_no > len(source_lines):
            return "", line_no

        idx = line_no - 1
        start_idx = idx
        while start_idx > 0:
            prev_line = source_lines[start_idx - 1]
            if ';' in prev_line or '{' in prev_line or '}' in prev_line:
                break
            start_idx -= 1

        end_idx = idx
        while end_idx < len(source_lines):
            curr_line = source_lines[end_idx]
            if ';' in curr_line:
                break
            end_idx += 1

        if end_idx >= len(source_lines):
            end_idx = len(source_lines) - 1

        stmt_lines = source_lines[start_idx:end_idx + 1]
        return " ".join(l.strip() for l in stmt_lines), start_idx + 1

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        realloc_pattern = "|".join(re.escape(f) for f in sorted(self.realloc_funcs, key=len, reverse=True))
        assign_regex = re.compile(
            rf'\b([a-zA-Z_]\w*(?:\s*->\s*\w+|\s*\.\s*\w+|\[[^\]]+\])*)\s*=\s*'
            rf'(?:\([^)]+\)\s*)?'
            rf'({realloc_pattern})\s*\('
        )

        for fn in ast_ctx.functions:
            reported_lines_in_fn = set()

            if ast_ctx.has_pycparser and ast_ctx.pycparser_ast is not None:
                for call in fn.calls:
                    callee = call[0]
                    line_no = call[1]
                    raw_args = call[2]
                    target_var = call[3] if len(call) > 3 else None

                    if callee in self.realloc_funcs:
                        arg1_expr = self._extract_first_arg(raw_args)
                        if not arg1_expr:
                            continue

                        lhs_expr = target_var
                        if not lhs_expr:
                            stmt, _ = self._reconstruct_statement(ast_ctx.source_lines, line_no)
                            m = assign_regex.search(stmt)
                            if m:
                                lhs_expr = m.group(1).strip()

                        if lhs_expr and self._clean_expr(lhs_expr) == self._clean_expr(arg1_expr):
                            snippet = _source_snippet(ast_ctx, line_no, f"{callee}({raw_args})")
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Realloc-overwrite memory leak: return value of {callee}() is directly assigned to '{lhs_expr}'. If {callee}() fails and returns NULL, the original buffer at '{lhs_expr}' is leaked.",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.SUGGESTED_FIX,
                                suggested_fix_replacement=f"void *tmp = {callee}({lhs_expr}, ...);\nif (!tmp) {{\n    /* handle allocation failure, {lhs_expr} remains valid */\n}} else {{\n    {lhs_expr} = tmp;\n}}"
                            ))
                            reported_lines_in_fn.add(line_no)
            else:
                body_lines = fn.body.splitlines()
                body_start = getattr(fn, "body_start_line", fn.start_line + 1)
                for i, line in enumerate(body_lines):
                    line_no = body_start + i
                    if line_no in reported_lines_in_fn:
                        continue

                    stmt, _ = self._reconstruct_statement(ast_ctx.source_lines, line_no)
                    for m in assign_regex.finditer(stmt):
                        lhs_expr = m.group(1).strip()
                        callee_fn = m.group(2).strip()
                        arg1_expr = self._extract_first_arg(stmt[m.end():])

                        if self._clean_expr(lhs_expr) == self._clean_expr(arg1_expr):
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=line.strip() if 0 < line_no <= len(ast_ctx.source_lines) else stmt,
                                message=f"Realloc-overwrite memory leak: return value of {callee_fn}() is directly assigned to '{lhs_expr}'. If {callee_fn}() fails and returns NULL, the original buffer at '{lhs_expr}' is leaked.",
                                column_number=m.start() + 1,
                                engine="AST",
                                fix_type=FixType.SUGGESTED_FIX,
                                suggested_fix_replacement=f"void *tmp = {callee_fn}({lhs_expr}, ...);\nif (!tmp) {{\n    /* handle allocation failure, {lhs_expr} remains valid */\n}} else {{\n    {lhs_expr} = tmp;\n}}"
                            ))
                            reported_lines_in_fn.add(line_no)

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        if line_content.lstrip().startswith('#'):
            return issues

        realloc_pattern = "|".join(re.escape(f) for f in sorted(self.realloc_funcs, key=len, reverse=True))
        pattern = re.compile(
            rf'\b([a-zA-Z_]\w*(?:\s*->\s*\w+|\s*\.\s*\w+|\[[^\]]+\])*)\s*=\s*'
            rf'(?:\([^)]+\)\s*)?'
            rf'({realloc_pattern})\s*\('
        )

        match_target = masked_line_content or line_content
        m = pattern.search(match_target)
        if not m:
            return issues

        lhs_expr = m.group(1).strip()
        callee_fn = m.group(2).strip()
        rest_str = line_content[m.end():]
        arg1_expr = self._extract_first_arg(rest_str)

        if not arg1_expr or ';' not in line_content:
            stmt, _ = self._reconstruct_statement(source_lines, line_number)
            m_stmt = pattern.search(stmt)
            if m_stmt:
                lhs_expr = m_stmt.group(1).strip()
                callee_fn = m_stmt.group(2).strip()
                arg1_expr = self._extract_first_arg(stmt[m_stmt.end():])

        if self._clean_expr(lhs_expr) == self._clean_expr(arg1_expr):
            col_no = m.start() + 1
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Realloc-overwrite memory leak: return value of {callee_fn}() is directly assigned to '{lhs_expr}'. If {callee_fn}() fails and returns NULL, the original buffer at '{lhs_expr}' is leaked.",
                column_number=col_no,
                engine="Regex",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement=f"void *tmp = {callee_fn}({lhs_expr}, ...);\nif (!tmp) {{\n    /* handle allocation failure, {lhs_expr} remains valid */\n}} else {{\n    {lhs_expr} = tmp;\n}}"
            ))
        return issues
