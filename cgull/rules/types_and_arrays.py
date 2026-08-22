"""
Rules for Arrays, Integer Overflows, VLAs, Bitwise Operations, and Magic Numbers.
"""

import re
from typing import List, Optional
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ..ast_analyzer import CASTContext, is_unsigned_type


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

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []

        def get_array_declared_size(arr_name: str, fn) -> Optional[int]:
            var_obj = fn.variables.get(arr_name) or ast_ctx.global_variables.get(arr_name)
            if var_obj and var_obj.array_size_expr:
                expr = var_obj.array_size_expr.strip()
                if expr.isdigit():
                    return int(expr)
                m = re.search(r'\b(\d+)\b', expr)
                if m:
                    return int(m.group(1))
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
                from ..cfg import build_cfg, find_function_def, _PRELUDE_LINE_COUNT
                from pycparser import c_ast
                funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
                if funcdef is not None:
                    cfg = build_cfg(funcdef)

            if funcdef is not None and cfg is not None:
                from ..ast_analyzer import _extract_identifiers_from_ast, _format_pycparser_expr
                reported_lines = set()

                class ArrayCheckVisitor(c_ast.NodeVisitor):
                    def visit_ArrayRef(v_self, node):
                        line_no = (node.coord.line - _PRELUDE_LINE_COUNT) if node.coord else fn.start_line
                        arr_name = _format_pycparser_expr(node.name)
                        sub_expr = _format_pycparser_expr(node.subscript)
                        sub_ids = _extract_identifiers_from_ast(node.subscript, ignore_callees=True)

                        arr_size = get_array_declared_size(arr_name, fn)

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
                from ..utils import mask_string_and_char_literals
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

                        arr_size = get_array_declared_size(arr_name, fn)
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

            # Look for declaration in earlier lines or earlier on current line
            decl_pattern = rf'\b(?:char|int|float|double|uint\w+_t|size_t|struct\s+\w+|\w+)\s+(?:\*|\s)*\b{re.escape(arr_name)}\s*\[\s*(\d+)\s*\]'
            for prev_idx in range(0, line_number):
                prev_line = line_content[:m.start()] if prev_idx == line_number - 1 else source_lines[prev_idx]
                decl_m = re.search(decl_pattern, prev_line)
                if decl_m:
                    declared_size = int(decl_m.group(1))
                    if idx_val >= declared_size:
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
                    break
        return issues


class ArithmeticIntegerOverflowRule(BaseRule):
    rule_id = "CGULL-006"
    name = "Arithmetic Integer Overflow"
    impact = Severity.HIGH
    category = RuleCategory.ARITHMETIC
    description = "Detect arithmetic operations (+, -, *, <<) on integers that lack preceding bounds checks, especially in allocation sizes or offsets."
    implementation_method = "AST parsing to find arithmetic expressions and verify bounds validation"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-190 / CWE-680"
    remediation_suggestion = "Validate arithmetic operands before multiplication or addition: if (count > SIZE_MAX / sizeof(type)) return -EOVERFLOW;"
    sample_vulnerable_code = "size_t total = count * sizeof(int);\nint *buf = malloc(total); // Integer multiplication overflow"
    sample_remediated_code = "if (count > SIZE_MAX / sizeof(int)) return -EINVAL;\nint *buf = malloc(count * sizeof(int));"
    analysis_engine = AnalysisEngine.HYBRID

    MAX_CONSTANTS_PATTERN = re.compile(
        r'\b(?:INT_MAX|UINT_MAX|SIZE_MAX|SHRT_MAX|USHRT_MAX|LONG_MAX|ULONG_MAX|LLONG_MAX|ULLONG_MAX|INT32_MAX|UINT32_MAX|INT64_MAX|UINT64_MAX|CHAR_MAX|UCHAR_MAX|2147483647|4294967295|0x7f[fF]{6,14}|0x7[fF]{7}|0x[fF]{8,16})\b'
    )

    def _has_preceding_overflow_check(self, source_lines: List[str], line_no: int, var_names: List[str]) -> bool:
        """
        Check if any preceding lines within a window (or function body) contain bounds/overflow checks
        for the given variable(s).
        """
        if line_no < 1 or line_no > len(source_lines):
            return False

        from ..utils import strip_comments_keep_lines

        start_line = max(0, line_no - 16)
        preceding_slice = source_lines[start_line:line_no - 1]

        for prev_l in reversed(preceding_slice):
            _, clean_single = strip_comments_keep_lines(prev_l)
            p_strip = clean_single.strip()
            if not p_strip or p_strip.startswith('#'):
                continue

            # Check if this line is an actual conditional/assert guard statement
            is_guard_stmt = bool(re.search(r'\b(?:if|while|assert|ASSERT)\b', p_strip))
            if not is_guard_stmt:
                continue

            # Ensure the guard statement references at least one variable involved in the arithmetic
            refs_var = any(
                bool(re.search(r'\b' + re.escape(v) + r'\b', p_strip))
                for v in var_names if v and not v.isdigit()
            )

            # Look for explicit bounds checks involving MAX/MIN constants in guard expressions for the variable(s)
            if refs_var and any(m_const in p_strip for m_const in ("SIZE_MAX", "INT_MAX", "UINT_MAX", "MAX_", "MIN_")):
                return True

            for v_name in var_names:
                if not v_name or v_name.isdigit():
                    continue
                v_esc = re.escape(v_name)
                if re.search(r'\b' + v_esc + r'\b\s*(?:<|<=|>|>=)', p_strip) or \
                   re.search(r'(?:<|<=|>|>=)\s*\b' + v_esc + r'\b', p_strip) or \
                   re.search(r'\bassert\s*\([^)]*?\b' + v_esc + r'\b', p_strip):
                    return True

        return False

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        reported_lines = set()

        for fn in ast_ctx.functions:
            body_lines = fn.body.splitlines()
            body_start = getattr(fn, "body_start_line", fn.start_line)

            # Track variables initialized or assigned from MAX constants
            max_assigned_vars = set()

            # 1. First pass over function body: identify variables holding max constants
            for i, line in enumerate(body_lines):
                # Check variable declarations or assignments: var = INT_MAX (excluding ==, !=, <=, >=, +=, etc.)
                m_assign = re.search(r'(?<![!=<>\+\-\*\/%&|^])\b([a-zA-Z_]\w*)\s*=\s*([^;=]+)', line)
                if m_assign:
                    v_name = m_assign.group(1).strip()
                    val_expr = m_assign.group(2).strip()
                    if self.MAX_CONSTANTS_PATTERN.search(val_expr):
                        max_assigned_vars.add(v_name)

            # 2. Check for malloc/calloc/realloc allocation arithmetic
            alloc_pattern = re.compile(
                r'\b(?:malloc|calloc|realloc|aligned_alloc)\s*\(\s*([^)]+)\)'
            )
            for i, line in enumerate(body_lines):
                line_no = body_start + i
                for m_alloc in alloc_pattern.finditer(line):
                    arg_str = m_alloc.group(1).strip()
                    # Check if argument contains arithmetic (+, *, <<) with non-constant identifiers
                    m_arith = re.search(r'\b([a-zA-Z_]\w*)\s*([\*\+])\s*([^,;)]+)', arg_str)
                    if m_arith:
                        var1 = m_arith.group(1)
                        op = m_arith.group(2)
                        var2 = m_arith.group(3).strip()

                        # Skip if pure numbers e.g. 1024
                        if var1.isdigit() and var2.isdigit():
                            continue

                        if not self._has_preceding_overflow_check(ast_ctx.source_lines, line_no, [var1, var2]):
                            key = (line_no, var1, op, var2)
                            if key not in reported_lines:
                                reported_lines.add(key)
                                snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                                guard_expr = f"{var1} > SIZE_MAX - ({var2})" if op == '+' else f"{var1} > SIZE_MAX / ({var2})"
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=line_no,
                                    code_snippet=snippet,
                                    message=f"Unchecked integer arithmetic '{var1} {op} {var2}' in memory allocation argument. May wrap around to small buffer causing heap corruption.",
                                    column_number=m_alloc.start() + 1,
                                    engine="AST",
                                    fix_type=FixType.SUGGESTED_FIX,
                                    suggested_fix_replacement=f"if ({guard_expr}) return -EOVERFLOW;\n{snippet}"
                                ))

            # 3. Check for general CWE-190 arithmetic integer overflow
            # Patterns like: result = data + 1; or data += 1; or data + INT_MAX;
            arith_expr_pattern = re.compile(
                r'\b([a-zA-Z_]\w*)\s*([\+\-\*]|<<|\+=|-=|\*=|\<<=)\s*([a-zA-Z_]\w*|\d+|INT_MAX|UINT_MAX|SIZE_MAX)\b'
            )

            for i, line in enumerate(body_lines):
                line_no = body_start + i
                # Skip for-loop headers (e.g. for (int i = 0; i < n; i++))
                if line.lstrip().startswith("for ") or line.lstrip().startswith("for("):
                    continue

                for m_arith in arith_expr_pattern.finditer(line):
                    lhs = m_arith.group(1)
                    op = m_arith.group(2)
                    rhs = m_arith.group(3)

                    # Determine if this arithmetic operation involves a MAX assigned variable or MAX constant directly
                    is_max_op = (
                        lhs in max_assigned_vars or
                        rhs in max_assigned_vars or
                        self.MAX_CONSTANTS_PATTERN.search(lhs) or
                        self.MAX_CONSTANTS_PATTERN.search(rhs)
                    )

                    if is_max_op:
                        if not self._has_preceding_overflow_check(ast_ctx.source_lines, line_no, [lhs, rhs]):
                            key = (line_no, lhs, op, rhs)
                            if key not in reported_lines:
                                reported_lines.add(key)
                                snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                                issues.append(self.create_issue(
                                    file_path=file_path,
                                    line_number=line_no,
                                    code_snippet=snippet,
                                    message=f"Potential Integer Overflow (CWE-190): unchecked arithmetic '{lhs} {op} {rhs}' on variable or constant assigned near maximum integer value.",
                                    column_number=m_arith.start() + 1,
                                    engine="AST",
                                    fix_type=FixType.MANUAL_REVIEW,
                                ))

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        target_line = masked_line_content or line_content

        # Look for malloc(n * m) or malloc(n + m) or calloc expressions without bounds check
        m = re.search(r'\b(?:malloc|calloc|realloc|aligned_alloc)\s*\(\s*(\w+)\s*([\*\+])\s*([^)]+)\)', target_line)
        if m:
            var1 = m.group(1)
            op = m.group(2)
            var2 = m.group(3).strip()
            # Check if previous lines contained overflow checks
            has_overflow_check = self._has_preceding_overflow_check(source_lines, line_number, [var1, var2])

            if not has_overflow_check:
                guard_expr = f"{var1} > SIZE_MAX - ({var2})" if op == '+' else f"{var1} > SIZE_MAX / ({var2})"
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Unchecked integer arithmetic '{var1} {op} {var2}' in memory allocation argument. May wrap around to small buffer causing heap corruption.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"if ({guard_expr}) return -EOVERFLOW;\n{line_content.strip()}"
                ))

        # Also regex check for direct arithmetic on MAX constants in scan_line if scan_ast isn't run
        if self.MAX_CONSTANTS_PATTERN.search(target_line) and not target_line.lstrip().startswith('#'):
            m_arith = re.search(r'\b([a-zA-Z_]\w*)\s*([\+\-\*]|<<|\+=|-=|\*=|\<<=)\s*(INT_MAX|UINT_MAX|SIZE_MAX|SHRT_MAX|LONG_MAX|LLONG_MAX)\b', target_line)
            if not m_arith:
                m_arith = re.search(r'\b(INT_MAX|UINT_MAX|SIZE_MAX|SHRT_MAX|LONG_MAX|LLONG_MAX)\s*([\+\-\*]|<<|\+=|-=|\*=|\<<=)\s*([a-zA-Z_]\w*|\d+)\b', target_line)
            if m_arith:
                lhs = m_arith.group(1)
                op = m_arith.group(2)
                rhs = m_arith.group(3)
                if not self._has_preceding_overflow_check(source_lines, line_number, [lhs, rhs]):
                    issues.append(self.create_issue(
                        file_path=file_path,
                        line_number=line_number,
                        code_snippet=line_content,
                        message=f"Potential Integer Overflow (CWE-190): unchecked arithmetic '{lhs} {op} {rhs}' on variable or constant assigned near maximum integer value.",
                        column_number=m_arith.start() + 1,
                        engine="Regex",
                        fix_type=FixType.MANUAL_REVIEW,
                    ))

        return issues


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


class SignedUnsignedComparisonRule(BaseRule):
    rule_id = "CGULL-033"
    name = "Signed/Unsigned Comparison and Loop-Bound Mismatch"
    impact = Severity.MEDIUM
    category = RuleCategory.ARITHMETIC
    description = "Detect comparisons between signed and unsigned integer types or loop bounds where implicit promotion causes infinite loops or unexpected comparison results."
    implementation_method = "AST parsing to evaluate underlying data types of comparison operands"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-195 / CERT INT02-C"
    remediation_suggestion = "Ensure loop variables and bounds share the same signedness, cast explicitly after verifying bounds, or use unsigned loop counters with condition (i > 0) or (i-- > 0)."
    sample_vulnerable_code = "size_t len = get_len();\nfor (int i = len; i >= 0; i--) {\n    /* ... */\n}\nif (signed_var < unsigned_var) { ... }"
    sample_remediated_code = "size_t len = get_len();\nfor (size_t i = len; i > 0; i--) {\n    use(i - 1);\n}"
    analysis_engine = AnalysisEngine.HYBRID

    @staticmethod
    def _is_unsigned_type(type_name: str, custom_typedefs: Optional[set] = None) -> bool:
        return is_unsigned_type(type_name, custom_typedefs)

    @staticmethod
    def _is_signed_type(type_name: str) -> bool:
        tn = type_name.lower()
        if "unsigned" in tn:
            return False
        for s_type in ("int", "short", "long", "char", "ssize_t", "int8_t", "int16_t", "int32_t", "int64_t", "intptr_t", "ptrdiff_t"):
            if re.search(r'\b' + re.escape(s_type) + r'\b', tn):
                return True
        return False

    def _get_var_signedness(self, var_expr: str, fn, ast_ctx) -> Optional[bool]:
        """
        Returns True if unsigned, False if signed, or None if unknown/literal.
        var_expr can be a variable identifier, param name, or 'sizeof(...)'.
        """
        expr_clean = var_expr.strip()
        if expr_clean.startswith("sizeof") or "sizeof(" in expr_clean:
            return True

        m = re.match(r'^[a-zA-Z_]\w*$', expr_clean)
        if not m:
            return None
        var_name = expr_clean

        custom_typedefs = getattr(ast_ctx, "unsigned_typedefs", None)
        if fn:
            var_obj = fn.variables.get(var_name)
            if var_obj:
                if self._is_unsigned_type(var_obj.type_name, custom_typedefs) or not var_obj.is_signed:
                    return True
                if self._is_signed_type(var_obj.type_name) or var_obj.is_signed:
                    return False

            for param in fn.parameters:
                if param.name == var_name:
                    if self._is_unsigned_type(param.type_name, custom_typedefs):
                        return True
                    if self._is_signed_type(param.type_name):
                        return False

        if ast_ctx and var_name in ast_ctx.global_variables:
            var_obj = ast_ctx.global_variables[var_name]
            if self._is_unsigned_type(var_obj.type_name, custom_typedefs) or not var_obj.is_signed:
                return True
            if self._is_signed_type(var_obj.type_name) or var_obj.is_signed:
                return False

        return None

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        reported_lines = set()

        def add_issue(line_no, snippet, msg, col=1):
            key = (line_no, msg)
            if key in reported_lines:
                return
            reported_lines.add(key)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_no,
                code_snippet=snippet,
                message=msg,
                column_number=col,
                engine="AST",
                fix_type=FixType.SUGGESTED_FIX,
                suggested_fix_replacement="Ensure loop counter and bound share the same type/signedness, or use explicit bounds validation."
            ))

        for fn in ast_ctx.functions:
            body_lines = fn.body.splitlines()
            body_start = getattr(fn, "body_start_line", fn.start_line)

            # 1. Reverse loops and loop bound mismatches
            for_pattern = re.compile(
                r'\bfor\s*\(\s*(?:([a-zA-Z_]\w*(?:\s*\*)*)\s+)?([a-zA-Z_]\w*)\s*=\s*([^;]+);\s*([^;]+);\s*([^)]+)\)'
            )
            for i, line in enumerate(body_lines):
                line_no = body_start + i
                for m in for_pattern.finditer(line):
                    decl_type = m.group(1)
                    var_name = m.group(2)
                    init_expr = m.group(3).strip()
                    cond_expr = m.group(4).strip()
                    step_expr = m.group(5).strip()

                    var_is_unsigned = None
                    if decl_type:
                        var_is_unsigned = self._is_unsigned_type(decl_type, getattr(ast_ctx, "unsigned_typedefs", None))
                    else:
                        var_is_unsigned = self._get_var_signedness(var_name, fn, ast_ctx)

                    is_decrement_cond = bool(
                        re.search(r'\b' + re.escape(var_name) + r'\s*>=\s*0\b', cond_expr) or
                        re.search(r'\b' + re.escape(var_name) + r'\s*>\s*-1\b', cond_expr) or
                        re.search(r'\b0\s*<=\s*' + re.escape(var_name) + r'\b', cond_expr)
                    )
                    is_decrement_step = '--' in step_expr or '-=' in step_expr or f'{var_name} -' in step_expr

                    if is_decrement_cond and is_decrement_step:
                        if var_is_unsigned is True:
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                            add_issue(
                                line_no, snippet,
                                f"Infinite Loop Risk: unsigned loop variable '{var_name}' compared with '{var_name} >= 0' will always evaluate to true as unsigned types cannot be negative.",
                                col=m.start() + 1
                            )
                        elif var_is_unsigned is False:
                            init_signedness = self._get_var_signedness(init_expr, fn, ast_ctx)
                            if init_signedness is True:
                                snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                                add_issue(
                                    line_no, snippet,
                                    f"Loop Bound Mismatch: signed loop counter '{var_name}' initialized from unsigned bound '{init_expr}'. If '{init_expr}' exceeds INT_MAX, initialization wraps to negative.",
                                    col=m.start() + 1
                                )

            # 2. Signed vs Unsigned comparisons in conditionals/statements
            comp_pattern = re.compile(
                r'\b([a-zA-Z_]\w*|sizeof\s*\([^)]*\))\s*(<|<=|>|>=|==|!=)\s*([a-zA-Z_]\w*|sizeof\s*\([^)]*\)|-\d+)\b'
            )
            for i, line in enumerate(body_lines):
                line_no = body_start + i
                for m in comp_pattern.finditer(line):
                    left_expr = m.group(1).strip()
                    op = m.group(2)
                    right_expr = m.group(3).strip()

                    if ("for " in line or "while " in line) and (
                        re.search(r'\b' + re.escape(left_expr) + r'\s*>=\s*0\b', line) or
                        re.search(r'\b' + re.escape(left_expr) + r'\s*>\s*-1\b', line) or
                        re.search(r'\b0\s*<=\s*' + re.escape(left_expr) + r'\b', line)
                    ):
                        continue

                    left_signedness = self._get_var_signedness(left_expr, fn, ast_ctx)

                    if right_expr.startswith("-") and right_expr[1:].isdigit():
                        if left_signedness is True:
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                            add_issue(
                                line_no, snippet,
                                f"Signed/Unsigned Comparison: comparing unsigned operand '{left_expr}' with negative literal '{right_expr}' causes implicit promotion and logic errors.",
                                col=m.start() + 1
                            )
                        continue

                    right_signedness = self._get_var_signedness(right_expr, fn, ast_ctx)

                    if left_signedness is not None and right_signedness is not None:
                        if left_signedness != right_signedness:
                            signed_op = left_expr if left_signedness is False else right_expr
                            unsigned_op = left_expr if left_signedness is True else right_expr
                            snippet = ast_ctx.source_lines[line_no - 1].strip() if line_no <= len(ast_ctx.source_lines) else line.strip()
                            add_issue(
                                line_no, snippet,
                                f"Signed/Unsigned Comparison: comparing signed operand '{signed_op}' with unsigned operand '{unsigned_op}' causes implicit promotion and potential logic errors.",
                                col=m.start() + 1
                            )

        return issues

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        target_line = masked_line_content or line_content

        m = re.search(
            r'\bfor\s*\(\s*(size_t|uint\w+_t|unsigned(?:\s+int)?)\s+([a-zA-Z_]\w*)\s*=\s*([^;]+);\s*\2\s*>=\s*0\s*;\s*([^)]+)\)',
            target_line
        )
        if m:
            var_type = m.group(1)
            var_name = m.group(2)
            init_expr = m.group(3).strip()
            step_expr = m.group(4).strip()
            is_decrement = '--' in step_expr or '-=' in step_expr or f'{var_name} -' in step_expr
            if is_decrement:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Infinite Loop Risk: unsigned loop variable '{var_name}' compared with '{var_name} >= 0' will always evaluate to true as unsigned types cannot be negative.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"for ({var_type} {var_name} = {init_expr}; {var_name} > 0; {var_name}--)"
                ))

        m = re.search(
            r'\bfor\s*\(\s*int\s+([a-zA-Z_]\w*)\s*=\s*([a-zA-Z_]\w*)\s*;\s*\1\s*>=\s*0\s*;\s*([^)]+)\)',
            target_line
        )
        if m:
            i_var = m.group(1)
            len_var = m.group(2)
            step_expr = m.group(3).strip()
            is_decrement = '--' in step_expr or '-=' in step_expr or f'{i_var} -' in step_expr
            if is_decrement and re.search(rf'\b(?:size_t|uint\w+_t|unsigned)\s+{re.escape(len_var)}\b', full_code):
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Loop Bound Mismatch: signed loop counter '{i_var}' initialized from unsigned bound '{len_var}'. If '{len_var}' exceeds INT_MAX, initialization wraps to negative.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"for (size_t {i_var} = {len_var}; {i_var} > 0; {i_var}--)"
                ))

        return issues



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

        from ..cfg import build_cfg, find_function_def, _PRELUDE_LINE_COUNT
        from pycparser import c_ast
        from ..ast_analyzer import _format_pycparser_expr, _extract_identifiers_from_ast

        reported_lines = set()

        for fn in ast_ctx.functions:
            funcdef = None
            cfg = None
            if ast_ctx.has_pycparser and ast_ctx.pycparser_ast is not None:
                funcdef = find_function_def(ast_ctx.pycparser_ast, fn.name)
                if funcdef is not None:
                    cfg = build_cfg(funcdef)

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
