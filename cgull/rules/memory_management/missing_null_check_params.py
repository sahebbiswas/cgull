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
    _null_unsafe_use_kind,
    _pointer_var_names,
    _unchecked_deref_vars,
    _find_uaf_uses,
    _find_memory_leak_exits,
)


logger = logging.getLogger(__name__)


def _lexical_additive_arith_match(var_name: str, text: str) -> Optional[re.Match]:
    """Match additive pointer arithmetic; exclude ++/-- and require an operand.

    Covers ``p + off``, ``off + p``, and ``p - off``. Postfix/prefix
    ``++``/``--`` and arrow ``p->`` must not match.
    """
    n = re.escape(var_name)
    # Operand after +/- : identifier, number, cast/paren, deref, or address-of.
    operand = r'(?:[0-9A-Za-z_(*&])'
    return re.search(
        rf'(?:'
        rf'{n}\s*\+(?!\+)\s*{operand}'
        rf'|(?:[0-9A-Za-z_)]\s*\+\s*{n}\b)'
        rf'|{n}\s*-(?![->])\s*{operand}'
        rf')',
        text,
    )


def _use_inside_same_line_truthy_guard(line: str, var_name: str, use_start: int) -> bool:
    """True when *use_start* lies inside ``if (var) <then>`` on *line*.

    ``if (p) return p + off;`` suppresses; ``if (p) foo(); return p + off;``
    does not, because the arithmetic sits after the guarded statement.
    """
    for guard in re.finditer(rf'\bif\s*\(\s*{re.escape(var_name)}\s*\)', line):
        after = guard.end()
        if use_start < after:
            continue
        k = after
        while k < len(line) and line[k] in ' \t':
            k += 1
        if k < len(line) and line[k] == '{':
            depth = 0
            end = len(line)
            for idx in range(k, len(line)):
                ch = line[idx]
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        end = idx
                        break
            if k <= use_start < end:
                return True
            continue
        semi = line.find(';', k)
        end = semi if semi >= 0 else len(line)
        if k <= use_start <= end:
            return True
    return False


def _lexical_null_pointer_assign_name(
    line: str,
    line_no: int,
    pointer_names: Set[str],
    fn,
) -> Optional[str]:
    """Name assigned NULL/0 on *line*, including ``char *p = 0;`` declarators."""
    m = re.search(
        r'(?<![\*->\.\w])\b([a-zA-Z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?(?:NULL|nullptr|0|0x0)\b',
        line,
    )
    if m:
        return m.group(1)
    # ``char *p = 0;`` — classical assign regex rejects ``*p`` via lookbehind;
    # only accept on the pointer variable's declaration line (not ``*p = 0`` stores).
    for pname in pointer_names:
        var = fn.variables.get(pname) if hasattr(fn, 'variables') else None
        if var is None or getattr(var, 'declaration_line', None) != line_no:
            continue
        if re.search(
            rf'\*\s*{re.escape(pname)}\s*=\s*(?:\([^)]+\)\s*)?(?:NULL|nullptr|0|0x0)\b',
            line,
        ):
            return pname
    return None


class MissingNullCheckOnFunctionParametersRule(BaseRule):

    rule_id = "CGULL-004"
    name = "Missing Null Check on Function Parameters"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Ensure pointer arguments and local pointers are checked against NULL before dereference or additive pointer arithmetic inside the function body."
    implementation_method = "AST parsing & CFG dataflow to track NULL pointer dereferences, additive pointer arithmetic, and unchecked parameters"
    implementation_complexity = "Medium"
    chances_of_false_positives = "High"
    cwe_id = "CWE-476"
    remediation_suggestion = "Add a guard clause before pointer dereference or pointer arithmetic: if (param == NULL) { return ERROR_CODE; }"
    sample_vulnerable_code = "int process_data(int *data, char *tag) {\n    *data = 100; // Dereferenced without NULL check\n    return 0;\n}"
    sample_remediated_code = "int process_data(int *data, char *tag) {\n    if (data == NULL || tag == NULL) return -EINVAL;\n    *data = 100;\n    return 0;\n}"
    analysis_engine = AnalysisEngine.AST

    def set_semantic_models(self, registry):
        self._semantic_models = registry

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        summaries = self.get_analysis_session(ast_ctx).function_summaries
        for fn in ast_ctx.functions:
            ptr_params = [p for p in fn.parameters if p.is_pointer and p.name]
            cfg = _ast_cfg_for_function(ast_ctx, fn, summaries=summaries)

            if cfg is not None:
                reported_nodes = set()
                pointer_names = _pointer_var_names(fn)
                # 1. Definite or possible NULL dereferences with known contracts.
                sorted_nodes = sorted(cfg.nodes.values(), key=lambda n: n.node_id)
                for node in sorted_nodes:
                    unchecked = _unchecked_deref_vars(node, summaries)
                    if not unchecked:
                        continue
                    for deref_var in sorted(unchecked):
                        null_status = cfg.query_nullness(deref_var, node.node_id)
                        if null_status in {Nullness.NULL, Nullness.MAYBE_NULL}:
                            use_kind = _null_unsafe_use_kind(node, deref_var, summaries)
                            # Additive forms only for pointer-typed names; integer
                            # zeros must not become null-pointer-arithmetic FPs.
                            if use_kind == "arith" and deref_var not in pointer_names:
                                continue
                            deref_line = node.get_deref_line(deref_var)
                            key = (deref_line, deref_var, "null_deref")
                            if key not in reported_nodes:
                                reported_nodes.add(key)
                                snippet = _source_snippet(ast_ctx, deref_line, node.expr_str)
                                null_phrase = (
                                    "is known to be NULL"
                                    if null_status == Nullness.NULL
                                    else "may be NULL"
                                )
                                if use_kind == "arith":
                                    message = (
                                        f"Null pointer arithmetic: pointer '{deref_var}' "
                                        f"{null_phrase} when used in additive pointer arithmetic."
                                    )
                                else:
                                    message = (
                                        f"Null pointer dereference: pointer '{deref_var}' "
                                        f"{null_phrase} when dereferenced."
                                    )
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=deref_line,
                                    code_snippet=snippet,
                                    message=message,
                                    column_number=1,
                                    engine="AST",
                                    fix_type=FixType.SUGGESTED_FIX,
                                    suggested_fix_replacement=f"if ({deref_var} == NULL) return -1;"
                                ))

                # 2. Pointer parameters dereferenced without a preceding NULL check
                for param in ptr_params:
                    unsafe = _find_unsafe_param_deref(cfg, param.name, summaries)
                    if unsafe is None:
                        continue
                    null_status = cfg.query_nullness(param.name, unsafe.node_id)
                    if null_status in {Nullness.NULL, Nullness.MAYBE_NULL}:
                        continue  # Already reported above
                    deref_line = unsafe.get_deref_line(param.name)
                    key = (deref_line, param.name, "param_missing_check")
                    if key not in reported_nodes:
                        reported_nodes.add(key)
                        snippet = _source_snippet(ast_ctx, deref_line, unsafe.expr_str)
                        use_kind = _null_unsafe_use_kind(unsafe, param.name, summaries)
                        if use_kind == "arith":
                            message = (
                                f"Pointer parameter '{param.name}' in function '{fn.name}' "
                                f"is used in additive pointer arithmetic without a preceding NULL check."
                            )
                        else:
                            message = (
                                f"Pointer parameter '{param.name}' in function '{fn.name}' "
                                f"is dereferenced without a preceding NULL check."
                            )
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=deref_line,
                            code_snippet=snippet,
                            message=message,
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
            pointer_names = _pointer_var_names(fn)

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
                    arith_match = _lexical_additive_arith_match(p_name, line)
                    deref_match = re.search(
                        rf'(?:\*\s*{re.escape(p_name)}\b|{re.escape(p_name)}\s*->|{re.escape(p_name)}\s*\[)',
                        line,
                    )
                    # Expression-local truthy guard: suppress only when the use
                    # is inside the guarded then-statement, not merely on the
                    # same line (``if (p) foo(); return p + off;`` must report).
                    if (
                        arith_match is not None
                        and deref_match is None
                        and _use_inside_same_line_truthy_guard(line, p_name, arith_match.start())
                    ):
                        continue
                    use_match = deref_match or arith_match
                    if use_match:
                        if deref_match is None and arith_match is not None:
                            message = (
                                f"Pointer parameter '{p_name}' in function '{fn.name}' "
                                f"is used in additive pointer arithmetic without a preceding NULL check."
                            )
                        else:
                            message = (
                                f"Pointer parameter '{p_name}' in function '{fn.name}' "
                                f"is dereferenced without a preceding NULL check."
                            )
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=line,
                            message=message,
                            column_number=use_match.start() + 1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({p_name} == NULL) return -EINVAL;"
                        ))
                        break

            # 2. Local NULL assignment / declarator-init fallback
            for i, line in enumerate(body_lines):
                line_no = body_start + i
                v_name = _lexical_null_pointer_assign_name(
                    line, line_no, pointer_names, fn
                )
                if not v_name:
                    continue
                base_depth = depths[i]
                for j in range(i + 1, len(body_lines)):
                    if depths[j] < base_depth:
                        break
                    sub_line = body_lines[j]
                    sub_line_no = body_start + j
                    if re.search(rf'(?<![\*->\.\w])\b{re.escape(v_name)}\s*=', sub_line):
                        break
                    # Prefer typed locals; keep a light declaration heuristic as backup.
                    looks_like_pointer = v_name in pointer_names or any(
                        re.search(
                            rf'(?:\*|\bchar\b|\bvoid\b).*\b{re.escape(v_name)}\b|\b{re.escape(v_name)}\s*=\s*\([^)]*\*[^)]*\)',
                            prev,
                        )
                        for prev in body_lines[: j + 1]
                    )
                    arith_match = (
                        _lexical_additive_arith_match(v_name, sub_line)
                        if looks_like_pointer
                        else None
                    )
                    deref_match = re.search(
                        rf'(?:\*\s*{re.escape(v_name)}\b|{re.escape(v_name)}\s*->|{re.escape(v_name)}\s*\[)',
                        sub_line,
                    )
                    use_match = deref_match or arith_match
                    if use_match:
                        if deref_match is None and arith_match is not None:
                            message = (
                                f"Null pointer arithmetic: pointer '{v_name}' "
                                f"is known to be NULL when used in additive pointer arithmetic."
                            )
                        else:
                            message = (
                                f"Null pointer dereference: pointer '{v_name}' "
                                f"is known to be NULL when dereferenced."
                            )
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=sub_line_no,
                            code_snippet=sub_line,
                            message=message,
                            column_number=use_match.start() + 1,
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
                    looks_like_pointer = v_name in pointer_names or any(
                        re.search(
                            rf'(?:\*|\bchar\b|\bvoid\b).*\b{re.escape(v_name)}\b|\b{re.escape(v_name)}\s*=\s*\([^)]*\*[^)]*\)',
                            prev,
                        )
                        for prev in body_lines[: j + 1]
                    )
                    arith_match = (
                        _lexical_additive_arith_match(v_name, sub_line)
                        if looks_like_pointer
                        else None
                    )
                    deref_match = re.search(
                        rf'(?:\*\s*{re.escape(v_name)}\b|{re.escape(v_name)}\s*->|{re.escape(v_name)}\s*\[)',
                        sub_line,
                    )
                    use_match = deref_match or arith_match
                    if use_match:
                        if deref_match is None and arith_match is not None:
                            message = (
                                f"Null pointer arithmetic: pointer '{v_name}' "
                                f"is known to be NULL when used in additive pointer arithmetic."
                            )
                        else:
                            message = (
                                f"Null pointer dereference: pointer '{v_name}' "
                                f"is known to be NULL when dereferenced."
                            )
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=sub_line_no,
                            code_snippet=sub_line,
                            message=message,
                            column_number=use_match.start() + 1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({v_name} == NULL) return -1;"
                        ))
                        break

        return issues
