"""
Rules for Arrays, Integer Overflows, VLAs, Bitwise Operations, and Magic Numbers.
"""

import re
from typing import List, Optional
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine, FixType
from ..ast_analyzer import CASTContext


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
            return None

        def is_index_var_signed(idx_var: str, fn) -> bool:
            var_obj = fn.variables.get(idx_var) or ast_ctx.global_variables.get(idx_var)
            if var_obj:
                return var_obj.is_signed
            for param in fn.parameters:
                if param.name == idx_var:
                    return 'unsigned' not in param.type_name
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
                   re.search(r'\b-1\s*<\s*' + v_esc + r'\b', expr_str) or \
                   re.search(r'\b' + v_esc + r'\s*<\s*0\b', expr_str) or \
                   re.search(r'\b0\s*>\s*' + v_esc + r'\b', expr_str):
                    has_lower = True

            if re.search(r'\b(assert|ASSERT|assert_param)\b', expr_str):
                has_upper = True
                has_lower = True

            if re.search(r'\b(ARRAY_SIZE|sizeof)\b', expr_str) or \
               re.search(r'\b[A-Z_]*(?:MAX|LEN|SIZE|CAP|LIMIT|END)\b', expr_str):
                has_upper = True

            if re.search(r'\bmin\s*\(', expr_str):
                nums = [int(n) for n in re.findall(r'\b\d+\b', expr_str)]
                if arr_size is not None and nums:
                    if all(n < arr_size for n in nums):
                        has_upper = True
                else:
                    has_upper = True

            if re.search(r'\bclamp\s*\(', expr_str):
                nums = [int(n) for n in re.findall(r'\b\d+\b', expr_str)]
                if arr_size is not None and nums:
                    if all(n < arr_size for n in nums):
                        has_upper = True
                        has_lower = True
                else:
                    has_upper = True
                    has_lower = True

            for m in re.finditer(r'\b' + v_esc + r'\s*(<|<=|>|>=)\s*(\d+)\b', expr_str):
                op, num_val = m.group(1), int(m.group(2))
                if op == '<':
                    limit = num_val
                elif op == '<=':
                    limit = num_val + 1
                elif op in ('>', '>='):
                    limit = num_val
                if arr_size is not None:
                    if limit <= arr_size:
                        has_upper = True
                else:
                    has_upper = True

            for m in re.finditer(r'\b(\d+)\s*(<|<=|>|>=)\s*' + v_esc + r'\b', expr_str):
                num_val, op = int(m.group(1)), m.group(2)
                if op == '>':
                    limit = num_val
                elif op == '>=':
                    limit = num_val + 1
                elif op in ('<', '<='):
                    limit = num_val
                if arr_size is not None:
                    if limit <= arr_size:
                        has_upper = True
                else:
                    has_upper = True

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

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Look for malloc(n * m) or malloc(n + m) or calloc expressions without bounds check
        m = re.search(r'\bmalloc\s*\(\s*(\w+)\s*([\*\+])\s*([^)]+)\)', line_content)
        if m:
            var1 = m.group(1)
            op = m.group(2)
            var2 = m.group(3).strip()
            # Check if previous lines contained overflow checks
            has_overflow_check = False
            for offset in range(1, 5):
                if line_number - 1 - offset >= 0:
                    prev_l = source_lines[line_number - 1 - offset]
                    if not prev_l.strip().startswith('#'):
                        if "SIZE_MAX" in prev_l or "MAX_" in prev_l or ">" in prev_l:
                            has_overflow_check = True
                            break

            if not has_overflow_check:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Unchecked integer arithmetic '{var1} {op} {var2}' in memory allocation argument. May wrap around to small buffer causing heap corruption.",
                    column_number=m.start() + 1,
                    engine="Regex",
                    fix_type=FixType.SUGGESTED_FIX,
                    suggested_fix_replacement=f"if ({var1} > SIZE_MAX / ({var2})) return -EOVERFLOW;\n{line_content.strip()}"
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
