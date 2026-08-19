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
