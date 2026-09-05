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
class UncheckedDynamicAllocationsRule(BaseRule):
    rule_id = "CGULL-003"
    name = "Unchecked Dynamic Allocations"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Ensure return value of memory allocation (malloc, calloc, realloc, aligned_alloc) is checked for NULL before use."
    implementation_method = "AST parsing / CFG dataflow to verify conditional NULL checks"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-476 / CWE-252"
    remediation_suggestion = "Immediately check allocated pointer against NULL before dereference: if (ptr == NULL) { /* error handling / return */ }"
    sample_vulnerable_code = "char *buf = (char *)malloc(1024);\nbuf[0] = 'A'; // Potential NULL pointer dereference"
    sample_remediated_code = "char *buf = (char *)malloc(1024);\nif (buf == NULL) {\n    return -ENOMEM;\n}\nbuf[0] = 'A';"
    analysis_engine = AnalysisEngine.HYBRID

    DEFAULT_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "aligned_alloc"}
    DEFAULT_REALLOC_FUNCS = {"realloc"}
    DEFAULT_DEALLOC_FUNCS = {"free", "cfree", "vfree"}

    def __init__(
        self,
        extra_alloc_funcs: Optional[List[str]] = None,
        extra_realloc_funcs: Optional[List[str]] = None,
        extra_dealloc_funcs: Optional[List[str]] = None,
    ):
        super().__init__()
        self.alloc_funcs: Set[str] = set(self.DEFAULT_ALLOC_FUNCS)
        self.realloc_funcs: Set[str] = set(self.DEFAULT_REALLOC_FUNCS)
        self.dealloc_funcs: Set[str] = set(self.DEFAULT_DEALLOC_FUNCS)
        if extra_alloc_funcs:
            self.add_extra_alloc_funcs(extra_alloc_funcs)
        if extra_realloc_funcs:
            self.add_extra_realloc_funcs(extra_realloc_funcs)
        if extra_dealloc_funcs:
            self.add_extra_dealloc_funcs(extra_dealloc_funcs)

    def add_extra_alloc_funcs(self, extra_allocs: List[str]) -> None:
        self.alloc_funcs.update(extra_allocs)

    def add_extra_realloc_funcs(self, extra_reallocs: List[str]) -> None:
        self.realloc_funcs.update(extra_reallocs)
        self.alloc_funcs.update(extra_reallocs)

    def add_extra_dealloc_funcs(self, extra_deallocs: List[str]) -> None:
        self.dealloc_funcs.update(extra_deallocs)

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        alloc_pattern = "|".join(re.escape(f) for f in sorted(self.alloc_funcs, key=len, reverse=True))
        session = self.get_analysis_session(ast_ctx)
        if (
            self.alloc_funcs == self.DEFAULT_ALLOC_FUNCS
            and self.realloc_funcs == self.DEFAULT_REALLOC_FUNCS
            and self.dealloc_funcs == self.DEFAULT_DEALLOC_FUNCS
        ):
            summaries = session.function_summaries
        else:
            # Preserve rule-local extension points while still consuming the
            # shared declarative effect registry.
            summaries = analyze_function_summaries(
                ast_ctx,
                alloc_funcs=self.alloc_funcs,
                dealloc_funcs=self.dealloc_funcs,
                realloc_funcs=self.realloc_funcs,
                call_effects=session.semantic_models.call_effects,
            )
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, alloc_funcs=self.alloc_funcs, dealloc_funcs=self.dealloc_funcs, summaries=summaries)
            if cfg is not None:
                for node in cfg.nodes.values():
                    if not node.allocated:
                        continue
                    for ptr_name in node.allocated:
                        unsafe = _find_unsafe_allocation_use(cfg, node.node_id, ptr_name, summaries=summaries)
                        if unsafe is None:
                            continue
                        line_no = node.line_number
                        snippet = _source_snippet(ast_ctx, line_no, node.expr_str)
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Return value of dynamic memory allocation for '{ptr_name}' is not checked for NULL before use.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({ptr_name} == NULL) {{\n    return -1; // Handle out-of-memory\n}}"
                        ))
                continue

            # Parser unavailable: retain the existing lexical fallback.
            body_lines = fn.body.splitlines()
            depths = _brace_depths(body_lines)
            alloc_regex = re.compile(rf'\b(\w+)\s*=\s*(?:\([^\)]+\)\s*)?(?:{alloc_pattern})\s*\(')
            for i, line in enumerate(body_lines):
                line_no = fn.start_line + 1 + i
                m = alloc_regex.search(line)
                if not m:
                    continue
                ptr_name = m.group(1)
                base_depth = depths[i]
                has_check = False
                for j in range(i + 1, min(i + 8, len(body_lines))):
                    if depths[j] < base_depth:
                        break
                    sub_line = body_lines[j]
                    if re.search(rf'\bif\s*\([^)]*?\b{re.escape(ptr_name)}\s*(?:==\s*NULL|!=\s*NULL|==\s*0|!=\s*0)\b', sub_line) or \
                       re.search(rf'\bif\s*\(\s*!{re.escape(ptr_name)}\b', sub_line) or \
                       re.search(rf'\bassert\s*\([^)]*?\b{re.escape(ptr_name)}\b', sub_line):
                        has_check = True
                        break
                if not has_check:
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=line,
                        message=f"Return value of dynamic memory allocation for '{ptr_name}' is not checked for NULL before use.",
                        column_number=m.start() + 1,
                        engine="AST",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=f"if ({ptr_name} == NULL) {{\n    return -1; // Handle out-of-memory\n}}"
                    ))
        return issues
