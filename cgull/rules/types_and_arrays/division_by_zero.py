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
class DivisionByZeroRule(BaseRule):
    rule_id = "CGULL-034"
    name = "Division or Modulo by Zero"
    impact = Severity.HIGH
    category = RuleCategory.ARITHMETIC
    description = "Detect division (/) or modulo (%) operations where the divisor might be zero, causing a crash or undefined behavior."
    implementation_method = "AST parsing to check division operators and verify zero checks in CFG"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-369"
    remediation_suggestion = "Ensure divisors are checked against zero before performing division or modulo operations."
    sample_vulnerable_code = "int result = 100 / count;"
    sample_remediated_code = "if (count != 0) { result = 100 / count; }"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []

        def is_zero_check(expr_str: str, var_name: str) -> bool:
            import re
            v_esc = re.escape(var_name)
            return bool(
                re.search(r'\b' + v_esc + r'\s*!=\s*0\b', expr_str) or
                re.search(r'\b0\s*!=\s*' + v_esc + r'\b', expr_str) or
                re.search(r'\b' + v_esc + r'\s*>\s*0\b', expr_str) or
                re.search(r'\b0\s*<\s*' + v_esc + r'\b', expr_str) or
                re.search(r'^\s*' + v_esc + r'\s*$', expr_str) or
                re.search(r'\b' + v_esc + r'\s*<\s*0\b', expr_str) or
                re.search(r'\b0\s*>\s*' + v_esc + r'\b', expr_str)
            )

        def is_equal_zero_check(expr_str: str, var_name: str) -> bool:
            import re
            v_esc = re.escape(var_name)
            return bool(
                re.search(r'\b' + v_esc + r'\s*==\s*0\b', expr_str) or
                re.search(r'\b0\s*==\s*' + v_esc + r'\b', expr_str) or
                re.search(r'^\s*!\s*' + v_esc + r'\s*$', expr_str)
            )

        def is_guarded_on_all_cfg_paths(cfg, target_node_id: int, var_name: str) -> bool:
            if cfg.entry is None or target_node_id not in cfg.nodes:
                return False
            visited = set()
            import collections
            queue = collections.deque([(cfg.entry, False)])
            path_reached = False

            while queue:
                curr_id, guarded = queue.popleft()
                if (curr_id, guarded) in visited:
                    continue
                visited.add((curr_id, guarded))

                if curr_id == target_node_id:
                    path_reached = True
                    if not guarded:
                        return False
                    continue

                node = cfg.nodes[curr_id]
                new_guarded = guarded
                if var_name in node.writes:
                    new_guarded = False

                if node.kind == "if_cond":
                    if is_zero_check(node.expr_str, var_name):
                        if len(node.successors) > 0:
                            queue.append((node.successors[0], True))
                        if len(node.successors) > 1:
                            queue.append((node.successors[1], new_guarded))
                        continue
                    elif is_equal_zero_check(node.expr_str, var_name):
                        if len(node.successors) > 0:
                            queue.append((node.successors[0], new_guarded))
                        if len(node.successors) > 1:
                            queue.append((node.successors[1], True))
                        continue

                for succ_id in node.successors:
                    queue.append((succ_id, new_guarded))

            return path_reached

        from ...cfg import build_cfg, find_function_def, _PRELUDE_LINE_COUNT
        from pycparser import c_ast
        from ...ast_analyzer import _format_pycparser_expr, _extract_identifiers_from_ast

        reported_lines = set()

        for fn in ast_ctx.functions:
            funcdef = None
            cfg = None
            if ast_ctx.has_pycparser and ast_ctx.pycparser_ast is not None:
                funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
                if funcdef is not None:
                    cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, "line_map", None))

            if funcdef is not None and cfg is not None:
                class DivVisitor(c_ast.NodeVisitor):
                    def visit_BinaryOp(v_self, node):
                        if node.op in ('/', '%'):
                            line_no = (node.coord.line - _PRELUDE_LINE_COUNT) if node.coord else fn.start_line
                            divisor_str = _format_pycparser_expr(node.right)

                            # 1. Check for literal zero (e.g. 0, 0x0, 0U)
                            if type(node.right).__name__ == "Constant":
                                try:
                                    val_str = str(node.right.value).rstrip("ULul")
                                    val = int(val_str, 0)
                                    if val == 0:
                                        key = (line_no, "literal_0")
                                        if key not in reported_lines:
                                            reported_lines.add(key)
                                            issues.append(self.create_issue(
                                                file_path=file_path,
                                                line_number=line_no,
                                                code_snippet=ast_ctx.source_lines[line_no - 1] if line_no <= len(ast_ctx.source_lines) else "",
                                                message="Division/Modulo by literal zero is undefined behavior and will cause a crash.",
                                                column_number=1,
                                                engine="AST",
                                                fix_type=FixType.MANUAL_REVIEW
                                            ))
                                        v_self.generic_visit(node)
                                        return
                                    else:
                                        v_self.generic_visit(node)
                                        return
                                except ValueError:
                                    pass

                            # 2. CFG node matching
                            cfg_nodes_for_line = [nid for nid, cfg_n in cfg.nodes.items() if cfg_n.line_number == line_no]
                            target_node_id = None
                            if cfg_nodes_for_line:
                                # First try to find nodes that are NOT if_cond if there's multiple on the same line
                                non_if_nodes = [nid for nid in cfg_nodes_for_line if cfg.nodes[nid].kind != "if_cond"]
                                if non_if_nodes:
                                    # Then see if any exact match divisor
                                    exact_nodes = [nid for nid in non_if_nodes if divisor_str in cfg.nodes[nid].expr_str]
                                    if exact_nodes:
                                        target_node_id = max(exact_nodes)
                                    else:
                                        target_node_id = max(non_if_nodes)
                                else:
                                    target_node_id = max(cfg_nodes_for_line)

                            if target_node_id is not None:
                                # 3. Restrict CFG guard to simple variable names
                                if type(node.right).__name__ == "ID":
                                    div_var = str(node.right.name)
                                    key = (line_no, div_var)
                                    if key not in reported_lines:
                                        guarded = is_guarded_on_all_cfg_paths(cfg, target_node_id, div_var)
                                        if not guarded:
                                            reported_lines.add(key)
                                            issues.append(self.create_issue(
                                                file_path=file_path,
                                                line_number=line_no,
                                                code_snippet=ast_ctx.source_lines[line_no - 1] if line_no <= len(ast_ctx.source_lines) else "",
                                                message=f"Division/Modulo by zero risk: divisor '{div_var}' is not guaranteed to be non-zero on all paths to this operation.",
                                                column_number=1,
                                                engine="AST",
                                                fix_type=FixType.SUGGESTED_FIX,
                                                suggested_fix_replacement=f"if ({div_var} != 0) {{ ... }}"
                                            ))
                                else:
                                    # Compound expression (like y + 1). Conservatively report.
                                    key = (line_no, "compound_expr")
                                    if key not in reported_lines:
                                        reported_lines.add(key)
                                        issues.append(self.create_issue(
                                            file_path=file_path,
                                            line_number=line_no,
                                            code_snippet=ast_ctx.source_lines[line_no - 1] if line_no <= len(ast_ctx.source_lines) else "",
                                            message=f"Division/Modulo by zero risk: compound divisor '{divisor_str}' might evaluate to zero.",
                                            column_number=1,
                                            engine="AST",
                                            fix_type=FixType.MANUAL_REVIEW
                                        ))

                        v_self.generic_visit(node)
                DivVisitor().visit(funcdef.body)

        return issues
