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
    analyze_function_summaries,
    analyze_ownership_summaries,
    ownership_effects_for_cfg,
    find_uses_after_free_effect,
)
from .helpers import (
    _brace_depths,
    _source_snippet,
    _ast_cfg_for_function,
)

logger = logging.getLogger(__name__)


class UseAfterFreeRule(BaseRule):
    rule_id = "CGULL-022"
    name = "Use-After-Free"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect dereferencing or reusing a pointer after the memory it points to has been released with free()."
    implementation_method = "AST dataflow analysis tracking allocation lifecycle across control flow joins (ALLOCATED, MAYBE_ALLOCATED, FREED, MAYBE_FREED)"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-416"
    remediation_suggestion = "Immediately set freed pointer to NULL (free(ptr); ptr = NULL;) and do not access freed memory."
    sample_vulnerable_code = "free(session);\nprintf(\"Session ID: %d\", session->id); // Use-After-Free"
    sample_remediated_code = "free(session);\nsession = NULL;"
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
                reported_uafs = set()
                for node in cfg.nodes.values():
                    node_effect = ownership_effects.get(node.node_id)
                    freed_ptrs = set(node.freed) | set(node.realloc_inputs)
                    if node_effect is not None:
                        freed_ptrs.update(node_effect.freed)
                        freed_ptrs.update(node_effect.maybe_freed)
                    for freed_ptr in freed_ptrs:
                        for use_node, accessed_var in find_uses_after_free_effect(
                            cfg, node.node_id, freed_ptr
                        ):
                            key = (use_node.line_number, accessed_var)
                            if key in reported_uafs:
                                continue
                            reported_uafs.add(key)
                            use_line = use_node.line_number
                            snippet = _source_snippet(ast_ctx, use_line, use_node.expr_str)
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=use_line,
                                code_snippet=snippet,
                                message=f"Potential Use-After-Free: pointer '{accessed_var}' was freed at line {node.line_number} and accessed here.",
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
                    if re.search(rf'\b{re.escape(freed_ptr)}\s*=', next_line):
                        break
                    if re.search(rf'(?:\*\s*{re.escape(freed_ptr)}\b|{re.escape(freed_ptr)}\s*->|{re.escape(freed_ptr)}\s*\[|\b\w+\s*\([^)]*?\b{re.escape(freed_ptr)}\b)', next_line):
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=next_line_no,
                            code_snippet=next_line,
                            message=f"Potential Use-After-Free: pointer '{freed_ptr}' was freed at line {line_no} and accessed here.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.MANUAL_REVIEW,
                        ))
                        break
        return issues
