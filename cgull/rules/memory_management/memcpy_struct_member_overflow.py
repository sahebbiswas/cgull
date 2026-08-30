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
class MemcpyStructMemberOverflowRule(BaseRule):
    rule_id = "CGULL-044"
    name = "Size-Aware Struct-Member / Array Buffer Overflow in Memory Copy Functions"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Detect memcpy(), memmove(), or memset() calls where the specified byte count provably exceeds the destination buffer's capacity (struct member or plain array) or is ungated by a preceding bounds check."
    implementation_method = "AST / CFG dataflow and bounds check analysis with regex fallback"
    implementation_complexity = "High"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-787 / CWE-120"
    remediation_suggestion = "Ensure memory copy/fill operations do not write past destination buffer capacity, and gate variable size arguments with explicit bounds checks: if (n <= capacity) memcpy(dest, src, n);"
    sample_vulnerable_code = "struct A { char array_a[100]; };\nvoid fun_c(struct A *a, const char *src, int n) {\n    memcpy(a->array_a, src, n); // n exceeds 100 or ungated!\n}"
    sample_remediated_code = "struct A { char array_a[100]; };\nvoid fun_c(struct A *a, const char *src, int n) {\n    if (n <= 100) {\n        memcpy(a->array_a, src, n);\n    }\n}"
    analysis_engine = AnalysisEngine.HYBRID

    TARGET_FUNCS = {"memcpy", "memmove", "memset"}

    def _resolve_dest_capacity(
        self,
        dest_expr: str,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Optional[int]:
        dest_clean = dest_expr.strip()
        dest_clean = re.sub(
            r'^\s*\(\s*(?:const\s+)?(?:char|int8_t|uint8_t|void|unsigned\s+char|signed\s+char|int)\s*\*+\s*\)\s*',
            '',
            dest_clean,
        ).strip()
        while dest_clean.startswith('(') and dest_clean.endswith(')'):
            dest_clean = dest_clean[1:-1].strip()

        is_address_of = dest_expr.strip().startswith('&')
        if dest_clean.startswith('&'):
            dest_clean = dest_clean[1:].strip()

        # 1. Struct member access chain resolution (V1-V7)
        if '->' in dest_clean or '.' in dest_clean:
            parts = re.split(r'->|\.', dest_clean)
            base_expr_str = parts[0].strip()
            fields = [p.strip() for p in parts[1:] if p.strip()]

            if base_expr_str and fields and ast_ctx:
                sdef = ast_ctx.resolve_struct_def(fn, base_expr_str)
                curr_sdef = sdef
                target_field = None
                for field_expr in fields:
                    if not curr_sdef:
                        target_field = None
                        break
                    f_name = re.sub(r'\[[^\]]*\]', '', field_expr).strip()
                    target_field = curr_sdef.get(f_name)
                    if not target_field:
                        break
                    if target_field.is_struct_or_union:
                        nested_tag = target_field.nested_tag or target_field.type_name
                        curr_sdef = ast_ctx.get_struct_def(nested_tag)
                    else:
                        curr_sdef = None

                if target_field and target_field.is_array:
                    elem_byte_size = get_type_byte_size(target_field.type_name, ast_ctx)
                    if elem_byte_size is None:
                        return None

                    dims = getattr(target_field, 'array_dims', None) or (
                        [target_field.array_size] if target_field.array_size is not None else []
                    )
                    last_field_expr = fields[-1]
                    subscripts = re.findall(r'\[\s*([^\]]+)\s*\]', last_field_expr)

                    if is_address_of and subscripts:
                        dim_subscripts = subscripts[:-1]
                        offset_str = subscripts[-1].strip()
                        try:
                            offset_val = int(offset_str)
                        except ValueError:
                            offset_val = 0
                    else:
                        dim_subscripts = subscripts
                        offset_val = 0

                    dim_idx = len(dim_subscripts)
                    if dims and dim_idx < len(dims):
                        selected_dim = dims[dim_idx]
                    elif target_field.array_size is not None and dim_idx == 0:
                        selected_dim = target_field.array_size
                    else:
                        selected_dim = None

                    if selected_dim is not None and isinstance(selected_dim, int):
                        remaining_elems = max(0, selected_dim - offset_val)
                        return remaining_elems * elem_byte_size

        # 2. Plain local or global array (with optional offset)
        elem_offset = 0
        m_idx = re.match(r'^(.*?)\s*\[\s*(\d+)\s*\]$', dest_clean)
        if m_idx:
            dest_clean_base = m_idx.group(1).strip()
            elem_offset = int(m_idx.group(2))
        else:
            dest_clean_base = dest_clean

        if re.match(r'^[a-zA-Z_]\w*$', dest_clean_base):
            var_name = dest_clean_base
            var_obj = fn.variables.get(var_name) or (ast_ctx.global_variables.get(var_name) if ast_ctx else None)
            if var_obj and var_obj.array_size_expr:
                elem_byte_size = get_type_byte_size(var_obj.type_name, ast_ctx)
                if elem_byte_size is None:
                    return None
                expr = var_obj.array_size_expr.strip()
                if expr.isdigit():
                    remaining_elems = max(0, int(expr) - elem_offset)
                    return remaining_elems * elem_byte_size
                m = re.search(r'\b(\d+)\b', expr)
                if m:
                    remaining_elems = max(0, int(m.group(1)) - elem_offset)
                    return remaining_elems * elem_byte_size

            # Check pointer aliasing or local array decl in source lines
            body_lines = fn.body.splitlines() if fn else []
            fn_start = getattr(fn, "body_start_line", fn.start_line) if fn else 1
            max_idx = min(len(body_lines), line_no - fn_start) if line_no >= fn_start else len(body_lines)

            assign_stmt_pattern = re.compile(
                rf'(?:^|[;{{}}\s])(?:(?:\w+\s+)*\*+\s*)?{re.escape(var_name)}\s*=(?!=)\s*(.+?)(?:;|$)'
            )
            for idx in range(max_idx - 1, -1, -1):
                line = body_lines[idx]
                m = assign_stmt_pattern.search(line)
                if m:
                    rhs = m.group(1).strip()
                    rhs_clean = re.sub(r'^(?:\([^\)]+\)\s*)+', '', rhs).strip()
                    alias_target = None
                    offset = 0
                    m_idx_rhs = re.match(r'^&\s*([a-zA-Z_]\w*)\s*\[\s*(\d+)\s*\]$', rhs_clean)
                    m_add1 = re.match(r'^([a-zA-Z_]\w*)\s*\+\s*(\d+)$', rhs_clean)
                    m_add2 = re.match(r'^(\d+)\s*\+\s*([a-zA-Z_]\w*)$', rhs_clean)
                    m_simple = re.match(r'^(?:&\s*)?([a-zA-Z_]\w*)(?:\s*\[\s*0\s*\])?$', rhs_clean)
                    if m_idx_rhs:
                        alias_target = m_idx_rhs.group(1)
                        offset = int(m_idx_rhs.group(2))
                    elif m_add1:
                        alias_target = m_add1.group(1)
                        offset = int(m_add1.group(2))
                    elif m_add2:
                        alias_target = m_add2.group(2)
                        offset = int(m_add2.group(1))
                    elif m_simple:
                        alias_target = m_simple.group(1)
                        offset = 0

                    if alias_target and alias_target != var_name:
                        t_var = fn.variables.get(alias_target) or (ast_ctx.global_variables.get(alias_target) if ast_ctx else None)
                        if t_var and t_var.array_size_expr and t_var.array_size_expr.isdigit():
                            elem_byte_size = get_type_byte_size(t_var.type_name, ast_ctx)
                            if elem_byte_size is None:
                                return None
                            remaining_elems = max(0, int(t_var.array_size_expr) - offset - elem_offset)
                            return remaining_elems * elem_byte_size

        return None

    @staticmethod
    def _eval_const_arithmetic(expr_str: str) -> Optional[int]:
        import ast
        try:
            tree = ast.parse(expr_str, mode='eval')
        except Exception:
            return None

        def _eval_node(node):
            if isinstance(node, ast.Expression):
                return _eval_node(node.body)
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return int(node.value)
            if isinstance(node, ast.UnaryOp):
                val = _eval_node(node.operand)
                if val is None:
                    return None
                if isinstance(node.op, ast.USub):
                    return -val
                if isinstance(node.op, ast.UAdd):
                    return +val
            if isinstance(node, ast.BinOp):
                left = _eval_node(node.left)
                right = _eval_node(node.right)
                if left is None or right is None:
                    return None
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if isinstance(node.op, (ast.FloorDiv, ast.Div)):
                    return left // right if right != 0 else None
                if isinstance(node.op, ast.LShift):
                    return left << right if 0 <= right <= 63 else None
                if isinstance(node.op, ast.RShift):
                    return left >> right if 0 <= right <= 63 else None
            return None

        return _eval_node(tree)

    def _resolve_size_arg(
        self,
        size_expr: str,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Tuple[Optional[int], Optional[str]]:
        """
        Returns (const_value, var_name).
        If const_value is not None, size is a static constant.
        If var_name is not None, size is a dynamic variable identifier or expression.
        """
        expr = size_expr.strip()
        s_sub = expr

        # 1. Substitute all sizeof(...) occurrences with resolved integer sizes
        sizeof_matches = list(re.finditer(r'sizeof\s*\(\s*(.+?)\s*\)', expr)) or list(re.finditer(r'sizeof\s*([a-zA-Z_]\w*)', expr))
        if sizeof_matches:
            offset_shift = 0
            for m in sizeof_matches:
                so_arg = m.group(1).strip()
                so_val = get_type_byte_size(so_arg, ast_ctx)
                if so_val is None and fn and ast_ctx:
                    var_obj = fn.variables.get(so_arg) or ast_ctx.global_variables.get(so_arg)
                    if var_obj:
                        so_val = self._resolve_dest_capacity(so_arg, fn, line_no, ast_ctx) or get_type_byte_size(var_obj.type_name, ast_ctx)
                if so_val is None and ast_ctx:
                    sdef = ast_ctx.get_struct_def(so_arg)
                    if sdef and sdef.fields:
                        fb = 0
                        for f in sdef.fields.values():
                            fe = get_type_byte_size(f.type_name, ast_ctx)
                            if fe is None:
                                fb = None
                                break
                            fc = f.array_size if (f.is_array and f.array_size is not None) else 1
                            fb += fc * fe
                        if fb is not None and fb > 0:
                            so_val = fb

                if so_val is None:
                    # An unresolvable sizeof term makes the full expression unresolved
                    return None, expr

                start = m.start() + offset_shift
                end = m.end() + offset_shift
                rep = str(so_val)
                s_sub = s_sub[:start] + rep + s_sub[end:]
                offset_shift += len(rep) - (m.end() - m.start())

        # 2. Substitute macro constants
        if ast_ctx and ast_ctx.clean_source:
            for macro_m in re.finditer(r'\b([a-zA-Z_]\w*)\b', s_sub):
                m_name = macro_m.group(1)
                if m_name.isdigit():
                    continue
                def_m = re.search(rf'#\s*define\s+{re.escape(m_name)}\s+(\d+|0x[0-9a-fA-F]+)\b', ast_ctx.clean_source)
                if def_m:
                    v_str = def_m.group(1)
                    val = int(v_str, 16) if v_str.startswith(('0x', '0X')) else int(v_str)
                    s_sub = re.sub(rf'\b{re.escape(m_name)}\b', str(val), s_sub)

        # 3. Try evaluating complete constant arithmetic expression
        const_val = self._eval_const_arithmetic(s_sub)
        if const_val is not None:
            return const_val, None

        # 4. Expression is dynamic / variable
        return None, expr

    def _resolve_upper_bound(
        self,
        limit_expr: str,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Optional[int]:
        s = limit_expr.strip()
        s = re.sub(r'^\s*\(\s*(?:[a-zA-Z_]\w*\s*\*+|\w+)\s*\)\s*', '', s).strip()
        while s.startswith('(') and s.endswith(')'):
            s = s[1:-1].strip()

        const_v = self._eval_const_arithmetic(s)
        if const_v is not None:
            return const_v

        m_op = re.match(r'^([a-zA-Z_]\w*(?:\s*->\s*\w+|\s*\.\s*\w+)?)\s*([\+\-])\s*(\d+)$', s)
        if m_op:
            base_str = m_op.group(1)
            op = m_op.group(2)
            val = int(m_op.group(3))
            base_bound = self._resolve_upper_bound(base_str, fn, line_no, ast_ctx)
            if base_bound is not None:
                return base_bound + val if op == '+' else base_bound - val

        if 'sizeof' in s:
            const_val, _ = self._resolve_size_arg(s, fn, line_no, ast_ctx)
            if const_val is not None:
                return const_val

        if ast_ctx and ast_ctx.clean_source:
            def_m = re.search(rf'#\s*define\s+{re.escape(s)}\s+(\d+|0x[0-9a-fA-F]+)\b', ast_ctx.clean_source)
            if def_m:
                val_str = def_m.group(1)
                return int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)

        cap = self._resolve_dest_capacity(s, fn, line_no, ast_ctx)
        if cap is not None:
            return cap

        body_lines = fn.body.splitlines() if fn else []
        fn_start = getattr(fn, "body_start_line", fn.start_line) if fn else 1
        max_idx = min(len(body_lines), line_no - fn_start) if line_no >= fn_start else len(body_lines)
        assign_pat = re.compile(rf'(?:^|[;{{}}\s]){re.escape(s)}\s*=(?!=)\s*(.+?)(?:;|$)')
        for idx in range(max_idx - 1, -1, -1):
            line = body_lines[idx]
            m = assign_pat.search(line)
            if m:
                rhs = m.group(1).strip()
                return self._resolve_upper_bound(rhs, fn, fn_start + idx, ast_ctx)

        return None

    @staticmethod
    def _is_signed_var(var_name: str, fn: CFunction, ast_ctx: CASTContext) -> bool:
        if not fn:
            return True
        var_obj = fn.variables.get(var_name) or (ast_ctx.global_variables.get(var_name) if ast_ctx else None)
        if var_obj:
            return var_obj.is_signed
        param = next((p for p in fn.parameters if p.name == var_name), None)
        if param:
            from ...ast_analyzer import is_unsigned_type
            return not is_unsigned_type(param.type_name, getattr(ast_ctx, "unsigned_typedefs", None))
        return True

    def _eval_branch_bounds(
        self,
        cond_str: str,
        var_name: str,
        dest_capacity: int,
        curr_upper: bool,
        curr_lower: bool,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Tuple[Tuple[bool, bool], Tuple[bool, bool]]:
        v_esc = re.escape(var_name)
        if not re.search(r'\b' + v_esc + r'\b', cond_str):
            return (curr_upper, curr_lower), (curr_upper, curr_lower)

        true_upper, true_lower = curr_upper, curr_lower
        false_upper, false_lower = curr_upper, curr_lower

        # Upper bound checks
        for m in re.finditer(r'\b' + v_esc + r'\s*(<=|>=|<|>|==)\s*([^&|;)]+)', cond_str):
            op, rhs = m.group(1), m.group(2).strip()
            ub = self._resolve_upper_bound(rhs, fn, line_no, ast_ctx)
            if ub is not None:
                if op in ('<=', '=='):
                    if ub <= dest_capacity:
                        true_upper = True
                elif op == '<':
                    if ub - 1 <= dest_capacity:
                        true_upper = True
                elif op == '>=':
                    if ub - 1 <= dest_capacity:
                        false_upper = True
                elif op == '>':
                    if ub <= dest_capacity:
                        false_upper = True

        for m in re.finditer(r'([^&|;(]+)\s*(<=|>=|<|>|==)\s*\b' + v_esc + r'\b', cond_str):
            lhs, op = m.group(1).strip(), m.group(2)
            ub = self._resolve_upper_bound(lhs, fn, line_no, ast_ctx)
            if ub is not None:
                if op in ('>=', '=='):
                    if ub <= dest_capacity:
                        true_upper = True
                elif op == '>':
                    if ub - 1 <= dest_capacity:
                        true_upper = True
                elif op == '<=':
                    if ub - 1 <= dest_capacity:
                        false_upper = True
                elif op == '<':
                    if ub <= dest_capacity:
                        false_upper = True

        # Non-negative lower bound checks (var >= 0, var > -1)
        for m in re.finditer(r'\b' + v_esc + r'\s*(>=|>|<|<=|==)\s*(-?\d+)\b', cond_str):
            op, val = m.group(1), int(m.group(2))
            if op in ('>=', '==') and val >= 0:
                true_lower = True
            elif op == '>' and val >= -1:
                true_lower = True
            elif op in ('<', '<=') and val <= 0:
                false_lower = True

        for m in re.finditer(r'(-?\d+)\s*(<=|<|>|>=|==)\s*\b' + v_esc + r'\b', cond_str):
            val, op = int(m.group(1)), m.group(2)
            if op in ('<=', '==') and val >= 0:
                true_lower = True
            elif op == '<' and val >= -1:
                true_lower = True
            elif op in ('>', '>=') and val <= 0:
                false_lower = True

        return (true_upper, true_lower), (false_upper, false_lower)

    def _is_min_clamp_bound(
        self,
        expr_str: Optional[str],
        var_name: str,
        dest_capacity: int,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> Tuple[bool, bool]:
        if not expr_str:
            return False, False
        v_esc = re.escape(var_name)
        if not re.search(r'\b' + v_esc + r'\b', expr_str):
            return False, False

        upper = False
        lower = False

        m_clamp = re.search(r'\bclamp\s*\(', expr_str)
        if m_clamp:
            inner, _ = extract_balanced_parens(expr_str, m_clamp.end() - 1)
            if inner is not None:
                clamp_args = split_call_args(inner)
                if len(clamp_args) == 3:
                    min_v = int(clamp_args[1]) if clamp_args[1].lstrip('-').isdigit() else 0
                    max_expr = clamp_args[2]
                    ub = self._resolve_upper_bound(max_expr, fn, line_no, ast_ctx)
                    if min_v >= 0:
                        lower = True
                    if ub is not None and ub <= dest_capacity:
                        upper = True
                    return upper, lower

        m_call = re.search(r'\bmin\s*\(', expr_str)
        if m_call:
            inner, _ = extract_balanced_parens(expr_str, m_call.end() - 1)
            if inner is not None:
                args = split_call_args(inner)
                for arg in args:
                    if arg == var_name:
                        continue
                    ub = self._resolve_upper_bound(arg, fn, line_no, ast_ctx)
                    if ub is not None and ub <= dest_capacity:
                        upper = True

        return upper, lower

    def _is_size_var_gated(
        self,
        var_name: str,
        dest_capacity: int,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> bool:
        if not fn or not ast_ctx:
            return False

        is_signed = self._is_signed_var(var_name, fn, ast_ctx)
        init_lower = not is_signed

        cfg = _ast_cfg_for_function(ast_ctx, fn)
        if cfg is not None and cfg.entry is not None:
            target_node_ids = [nid for nid, node in cfg.nodes.items() if node.line_number == line_no and any(tf in (node.expr_str or '') for tf in self.TARGET_FUNCS)]
            if not target_node_ids:
                target_node_ids = [nid for nid, node in cfg.nodes.items() if node.line_number == line_no]

            if target_node_ids:
                target_node_id = target_node_ids[0]
                import collections
                queue = collections.deque([(cfg.entry, False, init_lower)])
                visited = set()
                path_reached = False

                while queue:
                    curr_id, upper_b, lower_b = queue.popleft()
                    state_key = (curr_id, upper_b, lower_b)
                    if state_key in visited:
                        continue
                    visited.add(state_key)

                    if curr_id == target_node_id:
                        path_reached = True
                        if not (upper_b and lower_b):
                            return False
                        continue

                    node = cfg.nodes[curr_id]
                    new_upper, new_lower = upper_b, lower_b

                    if var_name in node.writes:
                        u_bound, l_bound = self._is_min_clamp_bound(node.expr_str, var_name, dest_capacity, fn, node.line_number, ast_ctx)
                        new_upper = u_bound
                        new_lower = l_bound or (not is_signed)

                    if node.kind in ("if_cond", "while_cond", "do_cond") and node.expr_str:
                        true_st, false_st = self._eval_branch_bounds(
                            node.expr_str, var_name, dest_capacity, new_upper, new_lower, fn, node.line_number, ast_ctx
                        )
                        if len(node.successors) >= 2:
                            queue.append((node.successors[0], true_st[0], true_st[1]))
                            queue.append((node.successors[1], false_st[0], false_st[1]))
                        elif len(node.successors) == 1:
                            succ_node = cfg.nodes[node.successors[0]]
                            if_ast = getattr(node, '_ast_node', None)
                            is_inside_if = False
                            if if_ast and getattr(if_ast, 'iftrue', None):
                                def _is_ast_child(child, parent):
                                    if parent is None or child is None:
                                        return False
                                    if parent is child:
                                        return True
                                    for _, c in getattr(parent, 'children', lambda: [])():
                                        if _is_ast_child(child, c):
                                            return True
                                    return False
                                is_inside_if = _is_ast_child(getattr(succ_node, '_ast_node', None), if_ast.iftrue)

                            if is_inside_if:
                                queue.append((node.successors[0], true_st[0], true_st[1]))
                            else:
                                queue.append((node.successors[0], false_st[0], false_st[1]))
                        continue

                    for succ_id in node.successors:
                        queue.append((succ_id, new_upper, new_lower))

                if path_reached:
                    return True

        return self._is_size_var_gated_lexical(var_name, dest_capacity, fn, line_no, ast_ctx)

    def _is_size_var_gated_lexical(
        self,
        var_name: str,
        dest_capacity: int,
        fn: CFunction,
        line_no: int,
        ast_ctx: CASTContext,
    ) -> bool:
        is_signed = self._is_signed_var(var_name, fn, ast_ctx)
        v_esc = re.escape(var_name)
        body_lines = fn.body.splitlines() if fn else []
        fn_start = getattr(fn, "body_start_line", fn.start_line) if fn else 1
        line_idx = line_no - fn_start

        start_idx = max(0, line_idx - 15)
        preceding_lines = body_lines[start_idx:line_idx]

        curr_u = False
        curr_l = not is_signed

        for idx, p_line in enumerate(preceding_lines):
            if not re.search(r'\b' + v_esc + r'\b', p_line):
                continue

            u_m, l_m = self._is_min_clamp_bound(p_line, var_name, dest_capacity, fn, fn_start + start_idx + idx, ast_ctx)
            if u_m:
                curr_u = True
            if l_m:
                curr_l = True

            if re.search(r'\b(?:if|assert|ASSERT|while)\b', p_line):
                (t_u, t_l), _ = self._eval_branch_bounds(p_line, var_name, dest_capacity, curr_u, curr_l, fn, fn_start + start_idx + idx, ast_ctx)
                curr_u, curr_l = t_u, t_l

            if curr_u and curr_l:
                subsequent = preceding_lines[idx + 1:]
                if not any(re.search(rf'(?:^|[;{{}}\s]){v_esc}\s*=(?!=)', l) for l in subsequent):
                    return True

        return False

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        target = masked_line_content or line_content
        if target.lstrip().startswith('#'):
            return issues

        for callee in self.TARGET_FUNCS:
            for m in re.finditer(rf'\b{re.escape(callee)}\s*\(', target):
                call_args = BannedFunctionsRule._extract_call_args(line_content, m.end() - 1)
                if not call_args or len(call_args) < 3:
                    continue

                if callee in ("memcpy", "memmove"):
                    dest_arg, src_arg, size_arg = call_args[0], call_args[1], call_args[2]
                else:  # memset
                    dest_arg, val_arg, size_arg = call_args[0], call_args[1], call_args[2]

                dest_clean = dest_arg.strip()
                dest_clean = re.sub(
                    r'^\s*\(\s*(?:const\s+)?(?:char|int8_t|uint8_t|void|unsigned\s+char|signed\s+char|int)\s*\*+\s*\)\s*',
                    '',
                    dest_clean,
                ).strip()
                if dest_clean.startswith('&'):
                    dest_clean = dest_clean[1:].strip()

                m_decl = re.search(rf'\b(?:char|int|float|double|uint\w+_t|size_t|struct\s+\w+|\w+)\s+(?:\*|\s)*\b{re.escape(dest_clean)}\s*\[\s*(\d+)\s*\]', full_code)
                dest_cap = int(m_decl.group(1)) if m_decl else None

                if dest_cap is None:
                    continue

                const_size = int(size_arg) if size_arg.isdigit() else None
                if const_size is not None and const_size > dest_cap:
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=f"Buffer Overflow in '{callee}': size argument ({const_size} bytes) provably exceeds destination buffer capacity ({dest_cap} bytes for '{dest_arg}'). Provable out-of-bounds write.",
                        column_number=m.start() + 1,
                        engine="Regex",
                        fix_type=FixType.SUGGESTED_FIX,
                        suggested_fix_replacement=f"{callee}({dest_arg}, ..., {dest_cap});"
                    ))

        return issues

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        reported_calls = set()

        for fn in ast_ctx.functions:
            for call in fn.calls:
                callee, line_no, raw_args = call[0], call[1], call[2]
                if callee not in self.TARGET_FUNCS:
                    continue

                args = None
                snippet = _source_snippet(ast_ctx, line_no, "")
                if snippet:
                    paren_pos = snippet.find('(')
                    if paren_pos != -1:
                        args = BannedFunctionsRule._extract_call_args(snippet, paren_pos)

                req_args = 3
                if not args or len(args) < req_args:
                    multiline_code = "\n".join(ast_ctx.source_lines[line_no - 1 : line_no + 10]) if (ast_ctx and ast_ctx.source_lines) else ""
                    paren_pos = multiline_code.find('(') if multiline_code else -1
                    if paren_pos != -1:
                        args = BannedFunctionsRule._extract_call_args(multiline_code, paren_pos)

                if not args or len(args) < req_args:
                    if raw_args:
                        args = BannedFunctionsRule._extract_call_args(f"{callee}({raw_args})", len(callee))
                if not args or len(args) < req_args:
                    args = split_call_args(raw_args) if raw_args else []

                if callee in ("memcpy", "memmove") and len(args) >= 3:
                    dest_arg, src_arg, size_arg = args[0], args[1], args[2]
                elif callee == "memset" and len(args) >= 3:
                    dest_arg, val_arg, size_arg = args[0], args[1], args[2]
                else:
                    continue

                dest_cap = self._resolve_dest_capacity(dest_arg, fn, line_no, ast_ctx)
                if dest_cap is None:
                    continue

                const_size, var_size = self._resolve_size_arg(size_arg, fn, line_no, ast_ctx)

                key = (line_no, callee, dest_arg)
                if key in reported_calls:
                    continue

                if const_size is not None:
                    if const_size > dest_cap:
                        reported_calls.add(key)
                        snippet = _source_snippet(ast_ctx, line_no, f"{callee}({raw_args})")
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Buffer Overflow in '{callee}': size argument ({const_size} bytes) provably exceeds destination buffer capacity ({dest_cap} bytes for '{dest_arg}'). Provable out-of-bounds write.",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"{callee}({dest_arg}, ..., {dest_cap});"
                        ))
                elif var_size is not None:
                    if not self._is_size_var_gated(var_size, dest_cap, fn, line_no, ast_ctx):
                        reported_calls.add(key)
                        snippet = _source_snippet(ast_ctx, line_no, f"{callee}({raw_args})")
                        issues.append(self.create_issue(
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet,
                            message=f"Potentially Unchecked Buffer Overflow in '{callee}': variable size argument '{var_size}' is not gated by a bounds check against destination capacity ({dest_cap} bytes for '{dest_arg}').",
                            column_number=1,
                            engine="AST",
                            fix_type=FixType.SUGGESTED_FIX,
                            suggested_fix_replacement=f"if ({var_size} <= {dest_cap}) {{\n    {snippet}\n}}"
                        ))

        return issues
