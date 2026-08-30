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
class BitwiseOperationsOnSignedIntegersRule(BaseRule):
    rule_id = "CGULL-015"
    name = "Bitwise Operations on Signed Integers"
    impact = Severity.MEDIUM
    category = RuleCategory.ARITHMETIC
    description = "Ensure bitwise operations (~, <<, >>, &, ^, |) are only performed on unsigned integer types (MISRA C:2012 Rule 10.1)."
    implementation_method = "AST parsing to evaluate underlying data types of bitwise operands"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-190 / CERT INT13-C"
    remediation_suggestion = "Cast operands to unsigned types (e.g. uint32_t, unsigned int) before performing bitwise operations."
    sample_vulnerable_code = "int mask = -1;\nint shifted = mask << 2; // Undefined behavior in C on signed negative integers"
    sample_remediated_code = "uint32_t mask = 0xFFFFFFFFU;\nuint32_t shifted = mask << 2U;"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Pattern matching signed shift: e.g. (int)x << n or int x = ...; x <<= 2
        m = re.search(r'\bint\s+(\w+)[^;]*;\s*.*?\b\1\s*(?:<<|>>|&=|\|=|\^=)', line_content)
        if not m:
            # Also catch literal negative shifts e.g. -1 << 4
            m = re.search(r'-\s*\d+\s*(?:<<|>>)', line_content)
        if m:
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message="Bitwise operation performed on signed/negative integer. In C, shifting signed negative numbers causes Undefined Behavior.",
                column_number=m.start() + 1,
                engine="Regex",
                fix_type=FixType.MANUAL_REVIEW,
            ))
        return issues
