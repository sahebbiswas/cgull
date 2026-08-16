"""
Rules for Cryptography, Timing Attack Prevention, Type Qualifiers, and Fault Injection.
"""

import re
from typing import List, Optional
from .base import BaseRule
from ..models import Severity, RuleCategory, Issue, AnalysisEngine
from ..ast_analyzer import CASTContext


class NonConstantTimeMemoryComparisonRule(BaseRule):
    rule_id = "CGULL-005"
    name = "Non-Constant Time Memory Comparison"
    impact = Severity.HIGH
    category = RuleCategory.CRYPTO
    description = "Flag standard memcmp(), strcmp(), or strncmp() in crypto, token, or security checks that leak execution timing information."
    implementation_method = "Regex or AST to flag standard comparisons and suggest constant-time alternatives"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-208 / CWE-385"
    remediation_suggestion = "Use constant-time comparison routines like CRYPTO_memcmp(), sodium_memcmp(), or timingsafe_bcmp() for secrets and authentication tokens."
    sample_vulnerable_code = "if (memcmp(calculated_hash, expected_hash, 32) == 0) {\n    grant_admin_access();\n}"
    sample_remediated_code = "if (CRYPTO_memcmp(calculated_hash, expected_hash, 32) == 0) {\n    grant_admin_access();\n}"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Check memcmp, strcmp, strncmp, bcmp on sensitive tokens or inside auth functions
        m = re.search(r'\b(memcmp|strcmp|strncmp|bcmp)\s*\(([^)]+)\)', line_content)
        if m:
            func_name = m.group(1)
            args = m.group(2)
            # Check if arguments or nearby context refer to secrets/keys/hashes/tokens/passwords/auth/signatures
            is_crypto_context = any(w in args.lower() for w in [
                'hash', 'token', 'key', 'secret', 'pass', 'auth', 'sign', 'mac', 'digest', 'pin', 'cert', 'crypto', 'session'
            ])
            if is_crypto_context or func_name == "bcmp":
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=line_content,
                    message=f"Standard comparison '{func_name}()' on security-sensitive values ({args.strip()}) is vulnerable to timing side-channel attacks (CWE-208).",
                    column_number=m.start() + 1,
                    engine="Regex",
                    auto_fix_replacement=f"CRYPTO_memcmp({args})"
                ))
        return issues


class StrippingVolatileQualifiersRule(BaseRule):
    rule_id = "CGULL-009"
    name = "Stripping Volatile Qualifiers"
    impact = Severity.HIGH
    category = RuleCategory.CONTROL_FLOW
    description = "Prevent casts or function calls that silently remove volatile from hardware/registers or shared memory pointers."
    implementation_method = "AST parsing to track type qualifiers across assignments/calls"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-562 / CWE-704"
    remediation_suggestion = "Maintain volatile qualifiers on all pointers referencing hardware registers, MMIO, or multithreaded shared state."
    sample_vulnerable_code = "volatile uint32_t *reg = (volatile uint32_t *)0x4000;\nuint32_t *p = (uint32_t *)reg; // Strips volatile"
    sample_remediated_code = "volatile uint32_t *reg = (volatile uint32_t *)0x4000;\nvolatile uint32_t *p = reg; // Preserves volatile"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Pattern: (type *) non-volatile cast of volatile pointer or cast removing volatile
        # e.g. (int *)reg or (char *)hw_reg
        m = re.search(r'\(\s*(?!volatile\b)(?:unsigned\s+|signed\s+|struct\s+\w+|\w+)\s*\*+\s*\)\s*(\w*(?:reg|mmio|hw|io|port|shared|vol)\w*)', line_content, re.IGNORECASE)
        if m:
            var_name = m.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Explicit type cast potentially strips 'volatile' qualifier from hardware/MMIO variable '{var_name}', allowing unsafe compiler register caching.",
                column_number=m.start() + 1,
                engine="Regex",
            ))
        return issues


class IllegalFunctionPointerConversionsRule(BaseRule):
    rule_id = "CGULL-011"
    name = "Illegal Function Pointer Conversions"
    impact = Severity.HIGH
    category = RuleCategory.CONTROL_FLOW
    description = "Prevent conversions between function pointers and data pointers (void *) or integers to mitigate Return-Oriented Programming (ROP) and CFI violations."
    implementation_method = "AST parsing to examine type casts involving FuncPtr nodes"
    implementation_complexity = "Medium"
    chances_of_false_positives = "Low"
    cwe_id = "CWE-843 / CWE-588"
    remediation_suggestion = "Store and cast function pointers only using matching function pointer typedefs, never void* or integer types."
    sample_vulnerable_code = "void *callback = (void *)my_handler; // Illegal func ptr to object ptr conversion\nint addr = (int)my_handler;"
    sample_remediated_code = "typedef void (*handler_fn)(int);\nhandler_fn callback = my_handler;"
    analysis_engine = AnalysisEngine.HYBRID

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Cast to (void *) or (int) / (long) on function names or func ptrs
        m = re.search(r'\(\s*(?:void\s*\*|int|long|uint32_t|unsigned\s+int)\s*\)\s*([a-zA-Z_]\w*(?:_handler|_fn|_callback|_hook|func))\b', line_content)
        if m:
            target = m.group(1)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Dangerous function pointer conversion for '{target}' (cast between function pointer and data pointer/integer violates ISO C and Control Flow Integrity).",
                column_number=m.start() + 1,
                engine="Regex",
                auto_fix_replacement="Use dedicated function pointer typedef instead of void* / int"
            ))
        return issues


class SinglePointOfFailureControlFlowRule(BaseRule):
    rule_id = "CGULL-016"
    name = "Single-Point-of-Failure Control Flow"
    impact = Severity.MEDIUM
    category = RuleCategory.CONTROL_FLOW
    description = "Flag simple boolean return checks (1/0 or true/false) in critical security, auth, or secure boot functions vulnerable to fault injection glitching."
    implementation_method = "AST parsing to check return types and state macros in security/auth functions"
    implementation_complexity = "Medium"
    chances_of_false_positives = "High"
    cwe_id = "CWE-1240"
    remediation_suggestion = "Use multi-bit hamming-distance status words (e.g. AUTH_SUCCESS = 0x5A5A5A5A, AUTH_FAILED = 0xA5A5A5A5) to protect against single-bit clock/voltage glitching."
    sample_vulnerable_code = "int verify_boot_signature(void) {\n    if (check_keys()) return 1;\n    return 0; // A 1-bit CPU fault can bypass security\n}"
    sample_remediated_code = "#define SECURE_OK 0x5A5A5A5AU\n#define SECURE_FAIL 0xA5A5A5A5U\nuint32_t verify_boot_signature(void) {\n    if (check_keys()) return SECURE_OK;\n    return SECURE_FAIL;\n}"
    analysis_engine = AnalysisEngine.AST

    def scan_ast(self, file_path: str, ast_ctx: CASTContext) -> List[Issue]:
        issues = []
        for fn in ast_ctx.functions:
            if fn.returns_boolean:
                issues.append(self.create_issue(
                    file_path=file_path,
                    line_number=fn.start_line,
                    code_snippet=f"{fn.return_type} {fn.name}(...)",
                    message=f"Security function '{fn.name}' returns simple binary 0/1 boolean. Hardware glitch or single-bit flip can bypass authorization.",
                    column_number=1,
                    engine="AST",
                    auto_fix_replacement="Use multi-bit status constants (e.g. 0x5A5A5A5A) instead of 1/0"
                ))
        return issues


class InsecureDataStorageRule(BaseRule):
    rule_id = "CGULL-024"
    name = "Insecure Data Storage"
    impact = Severity.MEDIUM
    category = RuleCategory.CRYPTO
    description = "Flag storage of sensitive data (passwords, encryption keys, auth tokens) in plaintext static buffers or unencrypted memory."
    implementation_method = "AST parsing and lexical matching to track sensitive variable names and plaintext string literals"
    implementation_complexity = "High"
    chances_of_false_positives = "High"
    cwe_id = "CWE-312 / CWE-798"
    remediation_suggestion = "Do not hardcode secrets or store credentials in static plaintext memory. Use hardware keystores (TPM/HSM) or secure enclave storage."
    sample_vulnerable_code = "const char *admin_password = \"SuperSecret123!\";\nchar api_key[64] = \"AIzaSyD-secret-key\";"
    sample_remediated_code = "// Load credentials dynamically from secure vault/environment\nchar *api_key = getenv(\"API_KEY\");"
    analysis_engine = AnalysisEngine.REGEX

    def scan_line(self, file_path: str, line_number: int, line_content: str, full_code: str, source_lines: List[str], masked_line_content: str = "") -> List[Issue]:
        issues = []
        # Match hardcoded password/key/secret strings
        m = re.search(r'(?:char\s*\*|char\s+\w+\[\]|string)\s*(\w*(?:password|secret|apikey|api_key|private_key|auth_token)\w*)\s*=\s*"([^"]+)"', line_content, re.IGNORECASE)
        if m:
            var_name = m.group(1)
            val = m.group(2)
            issues.append(self.create_issue(
                file_path=file_path,
                line_number=line_number,
                code_snippet=line_content,
                message=f"Hardcoded sensitive credential/key in plaintext variable '{var_name}' (CWE-312/CWE-798).",
                column_number=m.start() + 1,
                engine="Regex",
                auto_fix_replacement=f"const char *{var_name} = getenv(\"{var_name.upper()}\");"
            ))
        return issues
