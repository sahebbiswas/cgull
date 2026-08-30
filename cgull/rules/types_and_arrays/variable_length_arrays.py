"""
Rules for Arrays, Integer Overflows, VLAs, Bitwise Operations, and Magic Numbers.
"""

import re
import logging
from typing import Dict, List, Optional, Set, Tuple

from ..base import BaseRule
from ...models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ...ast_analyzer import CASTContext, is_unsigned_type

logger = logging.getLogger(__name__)
class VariableLengthArraysRule(BaseRule):
    rule_id = "CGULL-010"
    name = "Variable Length Arrays (VLAs)"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Forbid array declarations where size is determined by a runtime variable to prevent stack smashing and denial-of-service."
    implementation_method = "AST parsing to ensure array sizes are constant literals or compile-time constants"
    implementation_complexity = "Low"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-400 / CWE-787"
    remediation_suggestion = "Allocate variable sized buffers on the heap with malloc() and explicit size limits, or use fixed-size buffers with bounds validation."
    sample_vulnerable_code = "void process_packets(int len) {\n    char stack_buf[len]; // VLA stack exhaustion risk\n}"
    sample_remediated_code = "void process_packets(size_t len) {\n    if (len > MAX_PACKET_SIZE) return;\n    char *buf = (char *)malloc(len);\n    if (!buf) return;\n    /* ... */\n    free(buf);\n}"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            for v_name, var in fn.variables.items():
                if var.is_vla:
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=var.declaration_line,
                        code_snippet=f"{var.type_name} {var.name}[{var.array_size_expr}];",
                        message=f"Variable Length Array (VLA) '{var.name}[{var.array_size_expr}]' allocated on stack. Dynamic stack allocation causes stack smashing / exhaustion.",
                        column_number=1,
                        engine="AST",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=f"char *{var.name} = (char *)malloc({var.array_size_expr});"
                    ))
        return issues
