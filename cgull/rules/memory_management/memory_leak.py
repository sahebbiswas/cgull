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
    filter_leak_exits_for_ownership,
    ownership_effects_for_cfg,
)
from .helpers import (
    _brace_depths,
    _source_snippet,
    _ast_cfg_for_function,
    _find_memory_leak_exits,
)

logger = logging.getLogger(__name__)


class MemoryLeakRule(BaseRule):
    rule_id = "CGULL-036"
    name = "Memory Leak"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect dynamically allocated memory (malloc, calloc, realloc, strdup, aligned_alloc) assigned to local pointers that is not freed or transferred before function exit paths."
    implementation_method = "AST parsing & CFG dataflow analysis tracking allocation lifecycles across exit paths"
    implementation_complexity = "High"
    chances_of_false_positives = "Medium"
    cwe_id = "CWE-401"
    remediation_suggestion = "Ensure all allocated memory blocks are freed with free() before scope exit, or transferred to the caller via return value or output parameter."
    sample_vulnerable_code = "void bad() {\n    char *data = (char *)malloc(100);\n    if (!data) return;\n    strcpy(data, \"hello\");\n    // POTENTIAL FLAW: data is never freed\n}"
    sample_remediated_code = "void good() {\n    char *data = (char *)malloc(100);\n    if (!data) return;\n    strcpy(data, \"hello\");\n    free(data);\n}"
    analysis_engine = AnalysisEngine.HYBRID

    DEFAULT_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "strdup", "strndup", "aligned_alloc", "valloc", "pvalloc", "memalign", "posix_memalign"}
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
        dealloc_pattern = "|".join(re.escape(f) for f in sorted(self.dealloc_funcs, key=len, reverse=True))
        summaries = analyze_function_summaries(ast_ctx, alloc_funcs=self.alloc_funcs, dealloc_funcs=self.dealloc_funcs)
        ownership_summaries = analyze_ownership_summaries(ast_ctx)

        for fn in ast_ctx.functions:
            cfg = _ast_cfg_for_function(ast_ctx, fn, alloc_funcs=self.alloc_funcs, dealloc_funcs=self.dealloc_funcs, summaries=summaries)
            if cfg is not None:
                ownership_effects = ownership_effects_for_cfg(cfg, ownership_summaries)
                reported_allocs = set()
                for node in cfg.nodes.values():
                    if not node.allocated:
                        continue
                    for ptr_name in node.allocated:
                        key = (node.line_number, ptr_name)
                        if key in reported_allocs:
                            continue
                        leak_nodes = _find_memory_leak_exits(ast_ctx, fn, cfg, node.node_id, ptr_name, self.dealloc_funcs)
                        leak_nodes = filter_leak_exits_for_ownership(
                            cfg,
                            node.node_id,
                            ptr_name,
                            leak_nodes,
                            ownership_effects,
                        )
                        if leak_nodes:
                            reported_allocs.add(key)
                            line_no = node.line_number
                            snippet = _source_snippet(ast_ctx, line_no, node.expr_str)
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Memory leak: memory allocated for '{ptr_name}' at line {line_no} is never freed or transferred before scope exit.",
                                column_number=1,
                                engine="AST",
                                fix_type=FixType.SUGGESTED_FIX,
                                suggested_fix_replacement=f"free({ptr_name});"
                            ))
                continue

            # Parser unavailable: fallback to lexical scope analysis
            body_lines = fn.body.splitlines()
            depths = _brace_depths(body_lines)
            alloc_regex = re.compile(rf'\b(\w+)\s*=\s*(?:\([^\)]+\)\s*)?(?:{alloc_pattern})\s*\(')
            body_start = getattr(fn, "body_start_line", fn.start_line + 1)

            for i, line in enumerate(body_lines):
                line_no = body_start + i
                m = alloc_regex.search(line)
                if not m:
                    continue
                ptr_name = m.group(1)
                base_depth = depths[i]

                has_dealloc_or_transfer = False
                for j in range(i + 1, len(body_lines)):
                    if depths[j] < base_depth:
                        break
                    sub_line = body_lines[j]
                    if re.search(rf'\b(?:{dealloc_pattern})\s*\(\s*{re.escape(ptr_name)}\s*\)', sub_line) or \
                       re.search(rf'\breturn\b.*?\b{re.escape(ptr_name)}\b', sub_line) or \
                       re.search(rf'\*\s*\w+\s*=\s*{re.escape(ptr_name)}\b', sub_line) or \
                       re.search(rf'{re.escape(ptr_name)}\s*->', sub_line):
                        has_dealloc_or_transfer = True
                        break
                if not has_dealloc_or_transfer:
                    snippet = _source_snippet(ast_ctx, line_no, line)
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet,
                        message=f"Memory leak: memory allocated for '{ptr_name}' at line {line_no} is never freed or transferred before scope exit.",
                        column_number=m.start() + 1,
                        engine="Regex",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=f"free({ptr_name});"
                    ))

        return issues
