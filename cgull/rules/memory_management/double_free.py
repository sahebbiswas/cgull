"""
Memory Management Rule Submodule.
"""

import re
import logging
from typing import List, Optional, Set

from ..base import BaseRule
from ...models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ...ast_analyzer import CASTContext
from ...cfg import (
    Allocation,
    analyze_function_summaries,
    analyze_ownership_summaries,
    has_prior_free_effect,
    ownership_effects_for_cfg,
)
from .helpers import (
    _brace_depths,
    _source_snippet,
    _ast_cfg_for_function,
)

logger = logging.getLogger(__name__)


class DoubleFreeRule(BaseRule):
    rule_id = "CGULL-027"
    name = "Double Free"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect calling free() on a pointer that has already been freed."
    implementation_method = "AST dataflow analysis tracking allocation lifecycle across control flow joins (ALLOCATED, MAYBE_ALLOCATED, FREED, MAYBE_FREED)"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-415"
    remediation_suggestion = "Ensure a pointer is freed only once. Set freed pointers to NULL immediately after free()."
    sample_vulnerable_code = "free(ptr);\nfree(ptr); // Double-Free"
    sample_remediated_code = "free(ptr);\nptr = NULL;\nfree(ptr); // Safe: free(NULL) is a no-op"
    analysis_engine = AnalysisEngine.AST

    DEFAULT_DEALLOC_FUNCS = {"free", "cfree", "vfree"}
    MAX_LOOKAHEAD_LINES = 200

    def __init__(self, extra_dealloc_funcs: Optional[List[str]] = None):
        super().__init__()
        self.dealloc_funcs: Set[str] = set(self.DEFAULT_DEALLOC_FUNCS)
        if extra_dealloc_funcs:
            self.add_extra_dealloc_funcs(extra_dealloc_funcs)

    def add_extra_dealloc_funcs(self, extra_deallocs: List[str]) -> None:
        self.dealloc_funcs.update(extra_deallocs)

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        dealloc_pattern = "|".join(re.escape(f) for f in sorted(self.dealloc_funcs, key=len, reverse=True))
        summaries = analyze_function_summaries(ast_ctx, dealloc_funcs=self.dealloc_funcs)
        ownership_summaries = analyze_ownership_summaries(ast_ctx)
        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, dealloc_funcs=self.dealloc_funcs, summaries=summaries)
            if cfg is not None:
                ownership_effects = ownership_effects_for_cfg(cfg, ownership_summaries)
                reported = set()
                for node in cfg.nodes.values():
                    node_effect = ownership_effects.get(node.node_id)
                    freed_ptrs = set(node.freed)
                    if node_effect is not None:
                        freed_ptrs.update(node_effect.freed)
                        freed_ptrs.update(node_effect.maybe_freed)
                    for freed_ptr in freed_ptrs:
                        key = (node.node_id, freed_ptr)
                        if key in reported:
                            continue
                        alloc_status = cfg.query_allocation(freed_ptr, node.node_id)
                        already_freed = alloc_status in (Allocation.FREED, Allocation.MAYBE_FREED)
                        if not already_freed:
                            already_freed = has_prior_free_effect(
                                cfg, node.node_id, freed_ptr, ownership_effects
                            )
                        if already_freed:
                            reported.add(key)
                            snippet = _source_snippet(ast_ctx, node.line_number, node.expr_str)
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=node.line_number,
                                code_snippet=snippet,
                                message=f"Potential Double Free: pointer '{freed_ptr}' is freed here but was already freed.",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.MANUAL_REVIEW,
                            ))
                continue

            body_lines = fn.body.splitlines()
            depths = _brace_depths(body_lines)
            for i, line in enumerate(body_lines):
                line_no = fn.start_line + 1 + i
                free_match = re.search(rf'\b(?:{dealloc_pattern})\s*\(\s*(\w+)\s*\)', line)
                if not free_match:
                    continue
                freed_ptr = free_match.group(1)
                base_depth = depths[i]
                limit = min(i + 1 + self.MAX_LOOKAHEAD_LINES, len(body_lines))
                for j in range(i + 1, limit):
                    if depths[j] < base_depth:
                        break
                    next_line = body_lines[j]
                    next_line_no = fn.start_line + 1 + j
                    # If reassigned to NULL or another value, break
                    if re.search(rf'\b{re.escape(freed_ptr)}\s*=', next_line):
                        break
                    if re.search(rf'\b(?:free|cfree|vfree)\s*\(\s*{re.escape(freed_ptr)}\s*\)', next_line):
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=next_line_no,
                            code_snippet=next_line,
                            message=f"Potential Double Free: pointer '{freed_ptr}' was already freed at line {line_no}.",
                            column_number=1,
                            engine="Regex",
                            fix_type=FixType.MANUAL_REVIEW,
                        ))
                        break
        return issues
