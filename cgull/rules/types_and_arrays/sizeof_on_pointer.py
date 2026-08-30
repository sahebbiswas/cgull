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

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []

        for fn in ast_ctx.functions:
            for node in fn.cfg_nodes:
                if node.kind != "sizeof":
                    continue

                # node.expr_str will be "sizeof(...)"
                m = re.match(r'^sizeof\s*\(\s*([a-zA-Z_]\w*)\s*\)$', node.expr_str)
                if not m:
                    continue

                var_name = m.group(1)

                is_ptr = False
                if var_name in fn.variables:
                    if fn.variables[var_name].is_pointer or '*' in fn.variables[var_name].type_name or '*' in fn.variables[var_name].name:
                        is_ptr = True
                elif var_name in ast_ctx.global_variables:
                    if ast_ctx.global_variables[var_name].is_pointer or '*' in ast_ctx.global_variables[var_name].type_name or '*' in ast_ctx.global_variables[var_name].name:
                        is_ptr = True
                else:
                    for param in fn.parameters:
                        if param.name == var_name and (param.is_pointer or '*' in param.type_name or '*' in param.name):
                            is_ptr = True
                            break

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
