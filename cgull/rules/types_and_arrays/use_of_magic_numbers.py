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
class UseOfMagicNumbersRule(BaseRule):
    rule_id = "CGULL-014"
    name = "Use of Magic Numbers"
    impact = Severity.MEDIUM
    category = RuleCategory.STYLE
    description = "Flag hardcoded numeric literals (other than 0, 1, or 2) in array sizes, allocations, bitwise masks, or comparisons."
    implementation_method = "AST parsing to identify hardcoded numeric literals"
    implementation_complexity = "Low"
    chances_of_false_positives = "High"
    cwe_id = "CWE-1094"
    remediation_suggestion = "Replace magic numbers with named #define constants or enumerated constants (enum)."
    sample_vulnerable_code = "char buffer[1024];\nfor (int i = 0; i < 256; i++) { ... }"
    sample_remediated_code = "#define BUFFER_SIZE 1024\n#define MAX_ENTRIES 256\nchar buffer[BUFFER_SIZE];"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Flag magic numbers in array bounds e.g. char buf[4096] or malloc(8192)
        m = re.search(r'\b(?:char|int|float|double|uint\w+_t)\s+\w+\[\s*([3-9]\d{1,5})\s*\]', line_content)
        if m:
            num = m.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Hardcoded magic number '{num}' in array declaration. Define a named constant (e.g. #define BUFFER_LEN {num}).",
                column_number=m.start() + 1,
                engine="Regex",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement=f"#define BUFFER_CAPACITY {num}"
            ))
        return issues
