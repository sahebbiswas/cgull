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
class MissingNullCheckOnFunctionParametersRule(BaseRule):
    rule_id = "CGULL-004"
    name = "Missing Null Check on Function Parameters"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Ensure pointer arguments and local pointers are checked against NULL before being dereferenced inside function body."
    implementation_method = "AST parsing & CFG dataflow to track NULL pointer dereferences and unchecked parameters"
    implementation_complexity = "Medium"
    chances_of_false_positives = "High"
    cwe_id = "CWE-476"
    remediation_suggestion = "Add a guard clause before pointer dereference: if (param == NULL) { return ERROR_CODE; }"
    sample_vulnerable_code = "int process_data(int *data, char *tag) {\n    *data = 100; // Dereferenced without NULL check\n    return 0;\n}"
    sample_remediated_code = "int process_data(int *data, char *tag) {\n    if (data == NULL || tag == NULL) return -EINVAL;\n    *data = 100;\n    return 0;\n}"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        summaries = analyze_function_summaries(ast_ctx)
        for fn in ast_ctx.functions:
            ptr_params = [p for p in fn.parameters if p.is_pointer and p.name]
            cfg = _ast_cfg_for_function(ast_ctx, fn, summaries=summaries)

            if cfg is not None:
                reported_nodes = set()
                # 1. Direct NULL pointer dereferences (known to be NULL)
                sorted_nodes = sorted(cfg.nodes.values(), key=lambda n: n.node_id)
                for node in sorted_nodes:
                    if not node.derefs:
                        continue
                    for deref_var in sorted(node.derefs):
                        null_status = cfg.query_nullness(deref_var, node.node_id)
                        if null_status == Nullness.NULL:
                            deref_line = node.get_deref_line(deref_var)
                            key = (deref_line, deref_var, "null_deref")
                            if key not in reported_nodes:
                                reported_nodes.add(key)
                                snippet = _source_snippet(ast_ctx, deref_line, node.expr_str)
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=deref_line,
                                    code_snippet=snippet,
                                    message=f"Null pointer dereference: pointer '{deref_var}' is known to be NULL when dereferenced.",
                                    column_number=1,
                                    engine="AST",
                                    fix_type=FixType.SUGGESTED_FIX,
                                    suggested_fix_replacement=f"if ({deref_var} == NULL) return -1;"
                                ))

                # 2. Pointer parameters dereferenced without a preceding NULL check
                for param in ptr_params:
                    unsafe = _find_unsafe_param_deref(cfg, param.name)
                    if unsafe is None:
                        continue
                    null_status = cfg.query_nullness(param.name, unsafe.node_id)
                    if null_status == Nullness.NULL:
                        continue  # Already reported above under direct NULL dereference
                    deref_line = unsafe.get_deref_line(param.name)
                    key = (deref_line, param.name, "param_missing_check")
                    if key not in reported_nodes:
                        reported_nodes.add(key)
                        snippet = _source_snippet(ast_ctx, deref_line, unsafe.expr_str)
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=deref_line,
                            code_snippet=snippet,
                            message=f"Pointer parameter '{param.name}' in function '{fn.name}' is dereferenced without a preceding NULL check.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({param.name} == NULL) return -EINVAL;"
                        ))
                continue

            # Parser unavailable: preserve and extend lexical fallback.
            body_lines = fn.body.splitlines()
            body_start = getattr(fn, "body_start_line", fn.start_line + 1)
            depths = _brace_depths(body_lines)

            # 1. Parameter missing check fallback
            for param in ptr_params:
                p_name = param.name
                checked = any(
                    re.search(rf'\bif\s*\([^)]*?\b{re.escape(p_name)}\s*(?:==\s*NULL|!=\s*NULL|==\s*0|!=\s*0)\b', line) or
                    re.search(rf'\bif\s*\(\s*!{re.escape(p_name)}\b', line) or
                    re.search(rf'\bassert\s*\([^)]*?\b{re.escape(p_name)}\b', line)
                    for line in body_lines[:min(6, len(body_lines))]
                )
                if checked:
                    continue
                for i, line in enumerate(body_lines):
                    line_no = body_start + i
                    deref_match = re.search(rf'(?:\*\s*{re.escape(p_name)}\b|{re.escape(p_name)}\s*->|{re.escape(p_name)}\s*\[)', line)
                    if deref_match:
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=line,
                            message=f"Pointer parameter '{p_name}' in function '{fn.name}' is dereferenced without a preceding NULL check.",
                            column_number=deref_match.start() + 1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({p_name} == NULL) return -EINVAL;"
                        ))
                        break

            # 2. Local NULL assignment dereference fallback
            null_assign_regex = re.compile(r'(?<![\*->\.\w])\b([a-zA-Z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?(?:NULL|nullptr|0|0x0)\b')
            for i, line in enumerate(body_lines):
                m = null_assign_regex.search(line)
                if not m:
                    continue
                v_name = m.group(1)
                base_depth = depths[i]
                for j in range(i + 1, len(body_lines)):
                    if depths[j] < base_depth:
                        break
                    sub_line = body_lines[j]
                    sub_line_no = body_start + j
                    if re.search(rf'(?<![\*->\.\w])\b{re.escape(v_name)}\s*=', sub_line):
                        break
                    deref_match = re.search(rf'(?:\*\s*{re.escape(v_name)}\b|{re.escape(v_name)}\s*->|{re.escape(v_name)}\s*\[)', sub_line)
                    if deref_match:
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=sub_line_no,
                            code_snippet=sub_line,
                            message=f"Null pointer dereference: pointer '{v_name}' is known to be NULL when dereferenced.",
                            column_number=deref_match.start() + 1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({v_name} == NULL) return -1;"
                        ))
                        break

            # 3. Inverted condition `if (v == NULL)` or `if (!v)` dereference fallback
            inverted_check_regex = re.compile(r'\bif\s*\(\s*(?:([a-zA-Z_]\w*)\s*==\s*(?:NULL|nullptr|0|0x0)|!([a-zA-Z_]\w*))\s*\)')
            for i, line in enumerate(body_lines):
                m = inverted_check_regex.search(line)
                if not m:
                    continue
                v_name = m.group(1) or m.group(2)
                target_depth = depths[i] - 1 if '{' in line else depths[i]
                for j in range(i + 1, len(body_lines)):
                    if j > i + 1 and depths[j] <= target_depth:
                        break
                    sub_line = body_lines[j]
                    sub_line_no = body_start + j
                    if re.search(rf'(?<![\*->\.\w])\b{re.escape(v_name)}\s*=', sub_line):
                        break
                    deref_match = re.search(rf'(?:\*\s*{re.escape(v_name)}\b|{re.escape(v_name)}\s*->|{re.escape(v_name)}\s*\[)', sub_line)
                    if deref_match:
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=sub_line_no,
                            code_snippet=sub_line,
                            message=f"Null pointer dereference: pointer '{v_name}' is known to be NULL when dereferenced.",
                            column_number=deref_match.start() + 1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({v_name} == NULL) return -1;"
                        ))
                        break

        return issues
