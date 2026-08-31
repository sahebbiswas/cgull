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
class ArrayIndexOutOfBoundsRule(BaseRule):
    rule_id = "CGULL-007"
    name = "Array Index Out of Bounds"
    impact = Severity.HIGH
    category = RuleCategory.MEMORY
    description = "Flag array indexing operations where index expression lacks explicit boundary constraints or exceeds constant bounds."
    implementation_method = "AST parsing to track index variables against array dimensions"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-129 / CWE-125"
    remediation_suggestion = "Ensure every array access is gated by an explicit bounds check: if (idx >= 0 && idx < ARRAY_SIZE) { arr[idx] = val; }"
    sample_vulnerable_code = "int table[10];\ntable[idx] = 42; // idx can be negative or >= 10"
    sample_remediated_code = "int table[10];\nif (idx >= 0 && idx < 10) {\n    table[idx] = 42;\n}"
    analysis_engine = AnalysisEngine.HYBRID

    @staticmethod
    def _split_call_args(args: str) -> List[str]:
        """Split a simple C call argument list without being confused by casts."""
        result, start, depth = [], 0, 0
        for pos, char in enumerate(args):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            elif char == ',' and depth == 0:
                result.append(args[start:pos].strip())
                start = pos + 1
        result.append(args[start:].strip())
        return result

    @staticmethod
    def _element_size(type_name: str) -> Optional[int]:
        """Return conservative sizes for the builtin element types we can prove."""
        normalized = re.sub(r'\b(?:const|volatile|signed)\b', '', type_name.lower())
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        if 'char' in normalized:
            return 1
        if normalized in {'short', 'short int', 'unsigned short', 'unsigned short int'}:
            return 2
        if normalized in {'int', 'unsigned', 'unsigned int', 'float'}:
            return 4
        if normalized in {'long', 'long int', 'unsigned long', 'unsigned long int', 'double', 'long long', 'long long int'}:
            return 8
        return None

    @classmethod
    def _allocation_capacity(cls, rhs: str, element_size: Optional[int]) -> Optional[int]:
        """Recover a constant element capacity from a direct allocation expression.

        Allocation APIs report bytes, while an ArrayRef is measured in elements.
        Unknown expressions deliberately stay unknown: this rule only reports a
        heap access when it can establish the allocation capacity.
        """
        rhs = re.sub(r'^(?:\([^()]+\)\s*)+', '', rhs.strip())
        call = re.match(r'^(malloc|calloc|realloc)\s*\((.*)\)$', rhs, re.DOTALL)
        if not call or element_size is None:
            return None
        args = cls._split_call_args(call.group(2))
        callee = call.group(1)
        if (callee == 'malloc' and len(args) != 1) or (callee == 'calloc' and len(args) != 2) or (callee == 'realloc' and len(args) != 2):
            return None

        sizeof_values = {
            'char': 1, 'signed char': 1, 'unsigned char': 1,
            'short': 2, 'short int': 2, 'unsigned short': 2, 'unsigned short int': 2,
            'int': 4, 'unsigned': 4, 'unsigned int': 4, 'float': 4,
            'long': 8, 'long int': 8, 'unsigned long': 8, 'unsigned long int': 8,
            'double': 8, 'long long': 8, 'long long int': 8,
        }

        def constant(expr: str) -> Optional[int]:
            expr = expr.strip()
            # sizeof(*ptr) and sizeof(ptr[0]) have the allocated pointer's element size.
            expr = re.sub(r'sizeof\s*\(\s*\*\s*\w+\s*\)', str(element_size), expr)
            expr = re.sub(r'sizeof\s*\(\s*\w+\s*\[\s*0\s*\]\s*\)', str(element_size), expr)
            def replace_sizeof(match):
                return str(sizeof_values.get(re.sub(r'\s+', ' ', match.group(1).strip().lower()), -1))
            expr = re.sub(r'sizeof\s*\(\s*([\w\s]+?)\s*\)', replace_sizeof, expr)
            expr = re.sub(r'\b(\d+)[uUlL]*\b', r'\1', expr)
            if '-1' in expr or not re.fullmatch(r'[\d\s+*/()]+', expr):
                return None
            try:
                value = eval(expr, {'__builtins__': {}}, {})
            except (ArithmeticError, SyntaxError):
                return None
            return value if isinstance(value, int) and value >= 0 else None

        if callee == 'malloc':
            byte_count = constant(args[0])
        elif callee == 'calloc':
            count, size = constant(args[0]), constant(args[1])
            byte_count = count * size if count is not None and size is not None else None
        else:
            byte_count = constant(args[1])
        if byte_count is None or byte_count % element_size:
            return None
        return byte_count // element_size

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []

        def get_array_declared_size(arr_name: str, fn, line_no: Optional[int] = None, visited: Optional[set] = None, node=None) -> Optional[int]:
            if visited is None:
                visited = set()
            if arr_name in visited:
                return None
            visited.add(arr_name)

            # Check for struct member access chains (e.g. a->array_a, a.array_a, a->in.inner_buf, arr[k].array_a)
            base_expr_str = None
            fields = []

            if node is not None:
                from pycparser import c_ast
                from ...ast_analyzer import _format_pycparser_expr

                def decompose_access(n):
                    if isinstance(n, c_ast.ArrayRef):
                        base, chain = decompose_access(n.name)
                        chain.append(('array_subscript', n.subscript))
                        return base, chain
                    elif isinstance(n, c_ast.StructRef):
                        base, chain = decompose_access(n.name)
                        chain.append(('member_access', n.type, n.field.name))
                        return base, chain
                    else:
                        return n, []

                base_node, access_chain = decompose_access(node)
                if access_chain:
                    base_expr_str = _format_pycparser_expr(base_node)
                    curr_sdef = ast_ctx.resolve_struct_def(fn, base_expr_str)

                    if curr_sdef:
                        idx = 0
                        N = len(access_chain)
                        while idx < N and curr_sdef:
                            elem_kind, *elem_data = access_chain[idx]
                            if elem_kind != 'member_access':
                                break
                            _, f_name = elem_data
                            field = curr_sdef.get(f_name)
                            if not field:
                                break
                            idx += 1

                            num_consumed = 0
                            while idx < N and access_chain[idx][0] == 'array_subscript':
                                num_consumed += 1
                                idx += 1

                            if idx == N:
                                if field.is_array:
                                    dims = field.array_dims if getattr(field, 'array_dims', None) else ([field.array_size] if field.array_size is not None else [])
                                    if 1 <= num_consumed <= len(dims):
                                        return dims[num_consumed - 1]
                                return None
                            else:
                                if field.is_struct_or_union:
                                    nested_tag = field.nested_tag or field.type_name
                                    curr_sdef = ast_ctx.get_struct_def(nested_tag)
                                else:
                                    curr_sdef = None

            if not fields and ('->' in arr_name or '.' in arr_name):
                parts = re.split(r'->|\.', arr_name)
                base_expr_str = parts[0].strip()
                fields = [p.strip() for p in parts[1:] if p.strip()]

            if base_expr_str and fields:
                sdef = ast_ctx.resolve_struct_def(fn, base_expr_str)
                curr_sdef = sdef
                target_field = None
                for f_name in fields:
                    if not curr_sdef:
                        target_field = None
                        break
                    target_field = curr_sdef.get(f_name)
                    if not target_field:
                        break
                    if target_field.is_struct_or_union:
                        nested_tag = target_field.nested_tag or target_field.type_name
                        curr_sdef = ast_ctx.get_struct_def(nested_tag)
                    else:
                        curr_sdef = None
                if target_field and target_field.is_array and target_field.array_size is not None:
                    return target_field.array_size

            var_obj = fn.variables.get(arr_name) or ast_ctx.global_variables.get(arr_name)
            if var_obj and var_obj.array_size_expr:
                expr = var_obj.array_size_expr.strip()
                if expr.isdigit():
                    return int(expr)
                def_m = re.search(rf'#\s*define\s+{re.escape(expr)}\s+(\d+|0x[0-9a-fA-F]+)\b', ast_ctx.clean_source)
                if def_m:
                    val_str = def_m.group(1)
                    return int(val_str, 16) if val_str.startswith(('0x', '0X')) else int(val_str)
                m = re.search(r'\b(\d+)\b', expr)
                if m:
                    return int(m.group(1))

            element_size = self._element_size(var_obj.type_name) if var_obj else None

            # If arr_name is not directly an array with declared dimension, check for pointer aliasing
            body_lines = fn.body.splitlines()
            fn_start = getattr(fn, "body_start_line", fn.start_line)

            max_idx = len(body_lines)
            if line_no is not None and line_no >= fn_start:
                max_idx = min(len(body_lines), line_no - fn_start)

            assign_stmt_pattern = re.compile(
                rf'(?:^|[;{{}}\s])(?:(?:\w+\s+)*\*+\s*)?{re.escape(arr_name)}\s*=(?!=)\s*(.+?)(?:;|$)'
            )

            for idx in range(max_idx - 1, -1, -1):
                line = body_lines[idx]
                m = assign_stmt_pattern.search(line)
                if m:
                    rhs = m.group(1).strip()
                    allocation_size = self._allocation_capacity(rhs, element_size)
                    if allocation_size is not None:
                        return allocation_size
                    # Strip leading casts e.g. (int *) or (char *)
                    rhs_clean = re.sub(r'^(?:\([^\)]+\)\s*)+', '', rhs).strip()

                    alias_target = None
                    offset = 0
                    valid_match = False

                    # Case 1: &arr[K] or &arr[0]
                    m_idx = re.match(r'^&\s*([a-zA-Z_]\w*)\s*\[\s*(\d+)\s*\]$', rhs_clean)
                    if m_idx:
                        alias_target = m_idx.group(1)
                        offset = int(m_idx.group(2))
                        valid_match = True
                    else:
                        # Case 2: arr + K or K + arr
                        m_add1 = re.match(r'^([a-zA-Z_]\w*)\s*\+\s*(\d+)$', rhs_clean)
                        m_add2 = re.match(r'^(\d+)\s*\+\s*([a-zA-Z_]\w*)$', rhs_clean)
                        if m_add1:
                            alias_target = m_add1.group(1)
                            offset = int(m_add1.group(2))
                            valid_match = True
                        elif m_add2:
                            alias_target = m_add2.group(2)
                            offset = int(m_add2.group(1))
                            valid_match = True
                        else:
                            # Case 3: arr or &arr or &arr[0]
                            m_simple = re.match(r'^(?:&\s*)?([a-zA-Z_]\w*)(?:\s*\[\s*0\s*\])?$', rhs_clean)
                            if m_simple:
                                alias_target = m_simple.group(1)
                                offset = 0
                                valid_match = True

                    if valid_match and alias_target and alias_target != arr_name and alias_target not in ('NULL', 'nullptr'):
                        target_size = get_array_declared_size(alias_target, fn, line_no=fn_start + idx, visited=visited)
                        if target_size is not None:
                            return max(0, target_size - offset)

            return None

        def is_index_var_signed(idx_var: str, fn) -> bool:
            var_obj = fn.variables.get(idx_var) or ast_ctx.global_variables.get(idx_var)
            if var_obj:
                return var_obj.is_signed
            for param in fn.parameters:
                if param.name == idx_var:
                    return not is_unsigned_type(param.type_name, getattr(ast_ctx, "unsigned_typedefs", None))
            return True

        def is_bounds_check_for_var(expr_str: str, var_name: str, arr_size: Optional[int] = None, is_signed: bool = True) -> bool:
            v_esc = re.escape(var_name)
            if not re.search(r'\b' + v_esc + r'\b', expr_str):
                return False

            has_lower = not is_signed
            has_upper = False

            if not has_lower:
                if re.search(r'\b' + v_esc + r'\s*>=\s*0\b', expr_str) or \
                   re.search(r'\b' + v_esc + r'\s*>\s*-1\b', expr_str) or \
                   re.search(r'\b0\s*<=\s*' + v_esc + r'\b', expr_str) or \
                   re.search(r'\b-1\s*<\s*' + v_esc + r'\b', expr_str):
                    has_lower = True
                elif re.search(r'\b' + v_esc + r'\s*<\s*0\b', expr_str) or \
                     re.search(r'\b0\s*>\s*' + v_esc + r'\b', expr_str):
                    has_lower = True

            if re.search(r'\bmin\s*\(', expr_str):
                nums = [int(n) for n in re.findall(r'\b\d+\b', expr_str)]
                if arr_size is not None and nums:
                    if any(n <= arr_size for n in nums):
                        has_upper = True
                else:
                    has_upper = True

            if re.search(r'\bclamp\s*\(', expr_str):
                nums = [int(n) for n in re.findall(r'\b\d+\b', expr_str)]
                if arr_size is not None and nums:
                    if any(n <= arr_size for n in nums):
                        has_upper = True
                else:
                    has_upper = True
                has_lower = True

            for m in re.finditer(r'\b' + v_esc + r'\s*(<|<=|>|>=)\s*([a-zA-Z0-9_]+)\b', expr_str):
                op, val_str = m.group(1), m.group(2)

                is_upper = False
                is_lower = False
                limit_val = None

                if val_str.isdigit():
                    limit_val = int(val_str)
                    if op == '<':
                        is_upper = True
                    elif op == '<=':
                        is_upper = True
                        limit_val += 1
                    elif op == '>':
                        is_lower = True
                    elif op == '>=':
                        is_lower = True
                        limit_val -= 1
                else:
                    if op in ('<', '<='):
                        is_upper = True
                    elif op in ('>', '>='):
                        is_lower = True

                if is_upper:
                    if arr_size is not None and limit_val is not None:
                        if limit_val <= arr_size:
                            has_upper = True
                    else:
                        has_upper = True
                if is_lower:
                    if limit_val is not None:
                        if limit_val >= -1:
                            has_lower = True
                    else:
                        has_lower = True

            for m in re.finditer(r'\b([a-zA-Z0-9_]+)\s*(<|<=|>|>=)\s*' + v_esc + r'\b', expr_str):
                val_str, op = m.group(1), m.group(2)

                is_upper = False
                is_lower = False
                limit_val = None

                if val_str.isdigit():
                    limit_val = int(val_str)
                    if op == '>':
                        is_upper = True
                    elif op == '>=':
                        is_upper = True
                        limit_val += 1
                    elif op == '<':
                        is_lower = True
                    elif op == '<=':
                        is_lower = True
                        limit_val -= 1
                else:
                    if op in ('>', '>='):
                        is_upper = True
                    elif op in ('<', '<='):
                        is_lower = True

                if is_upper:
                    if arr_size is not None and limit_val is not None:
                        if limit_val <= arr_size:
                            has_upper = True
                    else:
                        has_upper = True
                if is_lower:
                    if limit_val is not None:
                        if limit_val >= -1:
                            has_lower = True
                    else:
                        has_lower = True

            return has_lower and has_upper

        def is_guarded_on_all_cfg_paths(cfg, target_node_id: int, idx_var: str, arr_size: Optional[int], is_signed: bool) -> bool:
            if cfg.entry is None or target_node_id not in cfg.nodes:
                return False
            visited = set()
            queue = [(cfg.entry, False)]
            path_reached = False

            while queue:
                curr_id, guarded = queue.pop(0)
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
                if idx_var in node.writes:
                    new_guarded = False
                elif is_bounds_check_for_var(node.expr_str, idx_var, arr_size, is_signed):
                    new_guarded = True

                for succ_id in node.successors:
                    queue.append((succ_id, new_guarded))

            return path_reached

        for fn in ast_ctx.functions:
            funcdef = None
            cfg = None
            if ast_ctx.has_pycparser and ast_ctx.pycparser_ast is not None:
                from ...cfg import build_cfg, find_function_def, _PRELUDE_LINE_COUNT
                from pycparser import c_ast
                funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
                if funcdef is not None:
                    cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, "line_map", None))

            if funcdef is not None and cfg is not None:
                from ...ast_analyzer import _extract_identifiers_from_ast, _format_pycparser_expr
                reported_lines = set()

                class ArrayCheckVisitor(c_ast.NodeVisitor):
                    def visit_ArrayRef(v_self, node):
                        line_no = (node.coord.line - _PRELUDE_LINE_COUNT) if node.coord else fn.start_line
                        arr_name = _format_pycparser_expr(node.name)
                        sub_expr = _format_pycparser_expr(node.subscript)
                        sub_ids = _extract_identifiers_from_ast(node.subscript, ignore_callees=True)

                        arr_size = get_array_declared_size(arr_name, fn, line_no=line_no, node=node)

                        # Find corresponding CFG node
                        cfg_nodes_for_line = [nid for nid, cfg_n in cfg.nodes.items() if cfg_n.line_number == line_no]
                        target_node_id = cfg_nodes_for_line[0] if cfg_nodes_for_line else None

                        for idx_var in sub_ids:
                            key = (line_no, arr_name, idx_var)
                            if key in reported_lines:
                                continue

                            is_signed = is_index_var_signed(idx_var, fn)

                            if target_node_id is not None:
                                guarded = is_guarded_on_all_cfg_paths(cfg, target_node_id, idx_var, arr_size, is_signed)
                            else:
                                guarded = False
                                for nid, cfg_node in cfg.nodes.items():
                                    if cfg_node.line_number <= line_no:
                                        if is_bounds_check_for_var(cfg_node.expr_str, idx_var, arr_size, is_signed):
                                            guarded = True
                                            break

                            if not guarded:
                                snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else f"{arr_name}[{sub_expr}]"
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=line_no,
                                    code_snippet=snippet,
                                    message=f"Unchecked Array Indexing: variable '{idx_var}' is used as an index for '{arr_name}' without preceding bounds validation.",
                                    column_number=1,
                                    engine="AST",
                                    fix_type=FixType.SUGGESTED_FIX,
                                    suggested_fix_replacement=f"if ({idx_var} >= 0 && {idx_var} < ARRAY_SIZE) {{\n    {snippet}\n}}"
                                ))
                                reported_lines.add(key)

                        v_self.generic_visit(node)

                ArrayCheckVisitor().visit(funcdef)
            else:
                from ...utils import mask_string_and_char_literals
                body_lines = fn.body.splitlines()
                body_start = getattr(fn, "body_start_line", fn.start_line)
                for i, line in enumerate(body_lines):
                    line_no = body_start + i
                    masked_line = mask_string_and_char_literals(line)

                    for m in re.finditer(r'\b([a-zA-Z_]\w*)\[\s*([a-zA-Z_]\w*)\s*\]', masked_line):
                        arr_name = m.group(1)
                        idx_var = m.group(2)

                        prefix = masked_line[:m.start()]
                        stmt_prefix = re.split(r'[;{}]', prefix)[-1]
                        if re.search(r'\b(?:const\s+|static\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*|\s)*$', stmt_prefix):
                            continue

                        arr_size = get_array_declared_size(arr_name, fn, line_no=line_no)
                        is_signed = is_index_var_signed(idx_var, fn)

                        guarded = False
                        # Check same-line prefix before match
                        if is_bounds_check_for_var(stmt_prefix, idx_var, arr_size, is_signed):
                            guarded = True
                        else:
                            # Check preceding lines
                            for prev_l in body_lines[:i]:
                                if is_bounds_check_for_var(prev_l, idx_var, arr_size, is_signed):
                                    guarded = True
                                    break

                        if not guarded:
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                            issues.append(self.create_issue(
                                file_path=file_path,
                                line_number=line_no,
                                code_snippet=snippet,
                                message=f"Unchecked Array Indexing: variable '{idx_var}' is used as an index for '{arr_name}' without preceding bounds validation.",
                                column_number=m.start() + 1,
                                engine="AST",
                                fix_type=FixType.SUGGESTED_FIX,
                                suggested_fix_replacement=f"if ({idx_var} >= 0 && {idx_var} < ARRAY_SIZE) {{\n    {snippet}\n}}"
                            ))

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Detect constant out-of-bounds e.g. arr[10] when declared arr[10]
        for m in re.finditer(r'\b([a-zA-Z_]\w*)\[\s*(\d+)\s*\]', line_content):
            arr_name = m.group(1)
            idx_val = int(m.group(2))

            # Skip array size declarator e.g. char username[32]; or int table[10]; or char dataBuffer[100] = "";
            prefix = line_content[:m.start()]
            stmt_prefix = re.split(r'[;{}]', prefix)[-1]
            if re.search(r'\b(?:const\s+|static\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*|\s)*$', stmt_prefix):
                continue

            # Determine function start boundary for current line to prevent scanning across function boundaries
            fn_header_re = re.compile(
                r'^[ \t]*(?:(?:static|inline|extern|const|unsigned|signed|struct\s+\w+|\w+)\s+)+(\*?\s*[\w_]+)\s*\([^)]*\)\s*\{?'
            )
            fn_start_idx = 0
            for idx in range(line_number - 1, -1, -1):
                line_str = source_lines[idx]
                if fn_header_re.match(line_str):
                    fn_start_idx = idx
                    break

            alias_assign_pattern = re.compile(
                rf'(?:^|[;{{}}\s])(?:(?:\w+\s+)*\*+\s*)?{re.escape(arr_name)}\s*=(?!=)\s*(.+?)(?:;|$)'
            )
            target_name = arr_name
            declared_size = None
            offset = 0

            for prev_idx in range(line_number - 1, fn_start_idx - 1, -1):
                prev_line = line_content[:m.start()] if prev_idx == line_number - 1 else source_lines[prev_idx]
                decl_m = re.search(rf'\b(?:char|int|float|double|uint\w+_t|size_t|struct\s+\w+|\w+)\s+(?:\*|\s)*\b{re.escape(target_name)}\s*\[\s*(\d+)\s*\]', prev_line)
                if decl_m:
                    declared_size = max(0, int(decl_m.group(1)) - offset)
                    break

                target_assign_pattern = re.compile(
                    rf'(?:^|[;{{}}\s])(?:(?:\w+\s+)*\*+\s*)?{re.escape(target_name)}\s*=(?!=)\s*(.+?)(?:;|$)'
                )
                alias_m = target_assign_pattern.search(prev_line)
                if alias_m:
                    rhs = alias_m.group(1).strip()
                    ptr_decl = re.search(
                        rf'\b([a-zA-Z_]\w*(?:\s+[a-zA-Z_]\w*)*)\s*\*+\s*{re.escape(target_name)}\s*=',
                        prev_line,
                    )
                    element_size = self._element_size(ptr_decl.group(1)) if ptr_decl else None
                    allocation_size = self._allocation_capacity(rhs, element_size)
                    if allocation_size is not None:
                        declared_size = max(0, allocation_size - offset)
                        break

                    rhs_clean = re.sub(r'^(?:\([^\)]+\)\s*)+', '', rhs).strip()
                    m_idx = re.match(r'^&\s*([a-zA-Z_]\w*)\s*\[\s*(\d+)\s*\]$', rhs_clean)
                    m_add1 = re.match(r'^([a-zA-Z_]\w*)\s*\+\s*(\d+)$', rhs_clean)
                    m_add2 = re.match(r'^(\d+)\s*\+\s*([a-zA-Z_]\w*)$', rhs_clean)
                    m_simple = re.match(r'^(?:&\s*)?([a-zA-Z_]\w*)(?:\s*\[\s*0\s*\])?$', rhs_clean)

                    if m_idx:
                        target_name = m_idx.group(1)
                        offset = int(m_idx.group(2))
                    elif m_add1:
                        target_name = m_add1.group(1)
                        offset = int(m_add1.group(2))
                    elif m_add2:
                        target_name = m_add2.group(2)
                        offset = int(m_add2.group(1))
                    elif m_simple:
                        target_name = m_simple.group(1)
                        offset = 0

            if declared_size is not None and idx_val >= declared_size:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Static Array Out-of-Bounds: index [{idx_val}] exceeds declared dimension of '{arr_name}[{declared_size}]'.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"{arr_name}[{declared_size - 1}]"
                ))
        return issues
