"""
Comprehensive per-rule coverage for C-GULL's 25 security rules.

Each rule gets:
  - a "detects" test: a minimal snippet that should trigger it
  - a "clean" test: a minimal snippet demonstrating the remediated
    pattern, which should NOT trigger it

Rules are scanned in isolation (via get_rule_by_id) so a failure always
points at exactly one rule's logic, not at cross-rule interference.
"""

import unittest

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine, FixType
from cgull.rules import get_rule_by_id, get_all_rules, ALL_RULES, RULE_REGISTRY


def scan_with_rule(rule_id: str, code: str):
    rule = get_rule_by_id(rule_id)
    scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
    return scanner.scan_text(code, f"{rule_id}.c").issues


class TestRuleRegistry(unittest.TestCase):

    def test_all_rules_have_unique_ids(self):
        ids = [r.rule_id for r in ALL_RULES]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate rule_id found in ALL_RULES")

    def test_get_rule_by_id_returns_matching_instance(self):
        rule = get_rule_by_id("CGULL-001")
        self.assertEqual(rule.rule_id, "CGULL-001")

    def test_get_rule_by_id_unknown_raises_keyerror(self):
        with self.assertRaises(KeyError):
            get_rule_by_id("CGULL-999")

    def test_get_all_rules_returns_fresh_instances(self):
        a = get_all_rules()
        b = get_all_rules()
        self.assertIsNot(a[0], b[0])
        self.assertEqual(len(a), len(ALL_RULES))

    def test_every_rule_has_required_metadata(self):
        for rule in get_all_rules():
            self.assertTrue(rule.rule_id.startswith("CGULL-"))
            self.assertTrue(rule.name)
            self.assertTrue(rule.description)
            self.assertTrue(rule.cwe_id)
            self.assertTrue(rule.remediation_suggestion)


class TestBannedFunctions(unittest.TestCase):
    def test_detects_gets(self):
        code = "void f(char *b) {\n    gets(b);\n}"
        issues = scan_with_rule("CGULL-001", code)
        self.assertEqual(len(issues), 1)

    def test_clean_fgets(self):
        code = "void f(char *b) {\n    fgets(b, 64, stdin);\n}"
        issues = scan_with_rule("CGULL-001", code)
        self.assertEqual(len(issues), 0)


class TestFormatString(unittest.TestCase):
    def test_detects_non_literal_format(self):
        code = "void f(char *user_input) {\n    printf(user_input);\n}"
        issues = scan_with_rule("CGULL-002", code)
        self.assertEqual(len(issues), 1)

    def test_clean_literal_format(self):
        code = "void f(char *user_input) {\n    printf(\"%s\", user_input);\n}"
        issues = scan_with_rule("CGULL-002", code)
        self.assertEqual(len(issues), 0)

    def test_string_literal_containing_printf_pattern_not_flagged(self):
        code = 'void f(void) {\n    log_debug("call printf(user_input) -- insecure pattern, do not do this");\n}'
        issues = scan_with_rule("CGULL-002", code)
        self.assertEqual(len(issues), 0)


class TestUncheckedDynamicAllocations(unittest.TestCase):
    def test_detects_unchecked_malloc(self):
        code = "void f(void) {\n    char *buf = (char *)malloc(1024);\n    buf[0] = 'A';\n}"
        issues = scan_with_rule("CGULL-003", code)
        self.assertEqual(len(issues), 1)

    def test_clean_checked_malloc(self):
        code = "void f(void) {\n    char *buf = (char *)malloc(1024);\n    if (buf == NULL) {\n        return;\n    }\n    buf[0] = 'A';\n}"
        issues = scan_with_rule("CGULL-003", code)
        self.assertEqual(len(issues), 0)


class TestMissingNullCheckOnParameters(unittest.TestCase):
    def test_detects_unchecked_pointer_deref(self):
        code = "int process_data(int *data) {\n    *data = 100;\n    return 0;\n}"
        issues = scan_with_rule("CGULL-004", code)
        self.assertEqual(len(issues), 1)

    def test_clean_checked_pointer(self):
        code = "int process_data(int *data) {\n    if (data == NULL) return -1;\n    *data = 100;\n    return 0;\n}"
        issues = scan_with_rule("CGULL-004", code)
        self.assertEqual(len(issues), 0)


class TestNonConstantTimeMemoryComparison(unittest.TestCase):
    def test_detects_memcmp_on_secret(self):
        code = "int check(char *token, char *expected_token) {\n    if (memcmp(token, expected_token, 32) == 0) return 1;\n    return 0;\n}"
        issues = scan_with_rule("CGULL-005", code)
        self.assertEqual(len(issues), 1)

    def test_clean_memcmp_on_non_secret(self):
        code = "int compare_lengths(char *a, char *b) {\n    if (memcmp(a, b, 4) == 0) return 1;\n    return 0;\n}"
        issues = scan_with_rule("CGULL-005", code)
        self.assertEqual(len(issues), 0)

    def test_detects_type_based_sensitive_memcmp_neutral_names(self):
        # Sensitive types (crypto_key_t) in sensitive check context with neutral names
        code = "typedef unsigned char crypto_key_t;\nint check_signature(const crypto_key_t *a, const crypto_key_t *b) {\n    int res = memcmp(a, b, 32);\n    return res == 0;\n}"
        issues = scan_with_rule("CGULL-005", code)
        self.assertEqual(len(issues), 1)

    def test_ignores_misleading_name_non_crypto(self):
        # Misleading variable name (key_count) on non-sensitive operation
        code = "int get_config(int key_count, int max_keys) {\n    if (memcmp(&key_count, &max_keys, sizeof(int)) == 0) return 1;\n    return 0;\n}"
        issues = scan_with_rule("CGULL-005", code)
        self.assertEqual(len(issues), 0)

    def test_generic_buffer_not_treated_as_secret(self):
        code = "int process_data(char *buf, char *data, int len) {\n    if (memcmp(buf, data, len) == 0) return 1;\n    return 0;\n}"
        issues = scan_with_rule("CGULL-005", code)
        self.assertEqual(len(issues), 0)


class TestArithmeticIntegerOverflow(unittest.TestCase):
    def test_detects_unchecked_multiplication_in_malloc(self):
        code = "void f(int count) {\n    int *buf = malloc(count * sizeof(int));\n}"
        issues = scan_with_rule("CGULL-006", code)
        self.assertEqual(len(issues), 1)

    def test_clean_checked_multiplication(self):
        code = "void f(int count) {\n    if (count > SIZE_MAX / sizeof(int)) return;\n    int *buf = malloc(count * sizeof(int));\n}"
        issues = scan_with_rule("CGULL-006", code)
        self.assertEqual(len(issues), 0)


class TestArrayIndexOutOfBounds(unittest.TestCase):
    def test_detects_constant_out_of_bounds_index(self):
        code = "void f(void) {\n    int table[10];\n    table[10] = 42;\n}"
        issues = scan_with_rule("CGULL-007", code)
        self.assertEqual(len(issues), 1)

    def test_clean_in_bounds_index(self):
        code = "void f(void) {\n    int table[10];\n    table[9] = 42;\n}"
        issues = scan_with_rule("CGULL-007", code)
        self.assertEqual(len(issues), 0)

    def test_detects_out_of_bounds_index_on_same_line_as_initialized_declaration(self):
        code = 'void f(void) {\n    char dataBuffer[100] = ""; dataBuffer[100] = \'a\';\n}'
        issues = scan_with_rule("CGULL-007", code)
        self.assertEqual(len(issues), 1)


class TestUnsafeSensitiveMemoryClearing(unittest.TestCase):
    def test_detects_memset_before_return(self):
        code = "int f(void) {\n    char password[64];\n    memset(password, 0, sizeof(password));\n    return 0;\n}"
        issues = scan_with_rule("CGULL-008", code)
        self.assertEqual(len(issues), 1)

    def test_clean_explicit_bzero(self):
        code = "int f(void) {\n    char password[64];\n    explicit_bzero(password, sizeof(password));\n    return 0;\n}"
        issues = scan_with_rule("CGULL-008", code)
        self.assertEqual(len(issues), 0)

    def test_clean_memset_generic_buffer(self):
        # Generic buffer (e.g. buf1) in non-security function should not be flagged as sensitive secret wipe
        code = "int process_data(void) {\n    char buf1[128];\n    memset(buf1, 0, sizeof(buf1));\n    return 0;\n}"
        issues = scan_with_rule("CGULL-008", code)
        self.assertEqual(len(issues), 0)

    def test_detects_memset_sensitive_key_buffer_before_return(self):
        code = "int process_data(void) {\n    char secret_key[128];\n    memset(secret_key, 0, sizeof(secret_key));\n    return 0;\n}"
        issues = scan_with_rule("CGULL-008", code)
        self.assertEqual(len(issues), 1)


class TestStrippingVolatileQualifiers(unittest.TestCase):
    def test_detects_volatile_stripped_by_cast(self):
        code = "void f(volatile uint32_t *hw_reg) {\n    uint32_t *p = (uint32_t *)hw_reg;\n}"
        issues = scan_with_rule("CGULL-009", code)
        self.assertEqual(len(issues), 1)

    def test_clean_volatile_preserved(self):
        code = "void f(volatile uint32_t *hw_reg) {\n    volatile uint32_t *p = hw_reg;\n}"
        issues = scan_with_rule("CGULL-009", code)
        self.assertEqual(len(issues), 0)

    def test_detects_volatile_stripped_neutral_var_name(self):
        # Neutral variable name (v1) declared volatile and stripped by cast
        code = "typedef unsigned int uint32_t;\nvoid process_state(volatile uint32_t *v1) {\n    uint32_t *ptr = (uint32_t *)v1;\n}"
        issues = scan_with_rule("CGULL-009", code)
        self.assertEqual(len(issues), 1)


class TestVariableLengthArrays(unittest.TestCase):
    def test_detects_vla(self):
        code = "void f(int len) {\n    char buf[len];\n}"
        issues = scan_with_rule("CGULL-010", code)
        self.assertEqual(len(issues), 1)

    def test_clean_fixed_size_array(self):
        code = "void f(int len) {\n    char buf[64];\n}"
        issues = scan_with_rule("CGULL-010", code)
        self.assertEqual(len(issues), 0)


class TestIllegalFunctionPointerConversions(unittest.TestCase):
    def test_detects_func_ptr_to_void_ptr(self):
        code = "void f(void) {\n    void *callback = (void *)my_handler;\n}"
        issues = scan_with_rule("CGULL-011", code)
        self.assertEqual(len(issues), 1)

    def test_clean_typed_function_pointer(self):
        code = "typedef void (*handler_fn)(int);\nvoid f(void) {\n    handler_fn callback = my_handler;\n}"
        issues = scan_with_rule("CGULL-011", code)
        self.assertEqual(len(issues), 0)

    def test_detects_func_ptr_conversion_neutral_name(self):
        # Function with neutral name (do_step) cast to void* or int
        code = "void do_step(int x) {}\nvoid run_step(void) {\n    void *p = (void *)do_step;\n}"
        issues = scan_with_rule("CGULL-011", code)
        self.assertEqual(len(issues), 1)


class TestUnsafeIntegerConversions(unittest.TestCase):
    def test_detects_atoi(self):
        code = "int f(char *s) {\n    return atoi(s);\n}"
        issues = scan_with_rule("CGULL-012", code)
        self.assertEqual(len(issues), 1)

    def test_clean_strtol(self):
        code = "long f(char *s) {\n    char *endptr;\n    return strtol(s, &endptr, 10);\n}"
        issues = scan_with_rule("CGULL-012", code)
        self.assertEqual(len(issues), 0)


class TestNakedControlFlowStatements(unittest.TestCase):
    def test_detects_naked_if(self):
        code = "void f(int err) {\n    if (err)\n        goto fail;\n}"
        issues = scan_with_rule("CGULL-013", code)
        self.assertGreaterEqual(len(issues), 1)

    def test_clean_braced_if(self):
        code = "void f(int err) {\n    if (err) {\n        return;\n    }\n}"
        issues = scan_with_rule("CGULL-013", code)
        self.assertEqual(len(issues), 0)


class TestUseOfMagicNumbers(unittest.TestCase):
    def test_detects_magic_array_size(self):
        code = "void f(void) {\n    char buffer[4096];\n}"
        issues = scan_with_rule("CGULL-014", code)
        self.assertEqual(len(issues), 1)

    def test_clean_named_constant_style_small_size(self):
        code = "void f(void) {\n    char buffer[2];\n}"
        issues = scan_with_rule("CGULL-014", code)
        self.assertEqual(len(issues), 0)


class TestBitwiseOperationsOnSignedIntegers(unittest.TestCase):
    def test_detects_signed_shift(self):
        code = "void f(void) {\n    int shifted = -1 << 4;\n}"
        issues = scan_with_rule("CGULL-015", code)
        self.assertEqual(len(issues), 1)

    def test_clean_unsigned_shift(self):
        code = "void f(void) {\n    uint32_t mask = 0xFFFFFFFFU;\n    mask <<= 2U;\n}"
        issues = scan_with_rule("CGULL-015", code)
        self.assertEqual(len(issues), 0)


class TestSinglePointOfFailureControlFlow(unittest.TestCase):
    def test_detects_boolean_return_in_auth_function(self):
        code = "int verify_auth_token(char *token) {\n    if (check(token)) return 1;\n    return 0;\n}"
        issues = scan_with_rule("CGULL-016", code)
        self.assertEqual(len(issues), 1)

    def test_clean_non_security_function_boolean_return(self):
        code = "int is_even(int x) {\n    if (x % 2 == 0) return 1;\n    return 0;\n}"
        issues = scan_with_rule("CGULL-016", code)
        self.assertEqual(len(issues), 0)


class TestMissingDefaultCaseInSwitch(unittest.TestCase):
    def test_detects_missing_default(self):
        code = "void f(int t) {\n    switch (t) {\n        case 1: break;\n        case 2: break;\n    }\n}"
        issues = scan_with_rule("CGULL-017", code)
        self.assertEqual(len(issues), 1)

    def test_clean_has_default(self):
        code = "void f(int t) {\n    switch (t) {\n        case 1: break;\n        default: break;\n    }\n}"
        issues = scan_with_rule("CGULL-017", code)
        self.assertEqual(len(issues), 0)


class TestUseOfGotoStatements(unittest.TestCase):
    def test_detects_goto(self):
        code = "void f(int error) {\n    if (error) goto cleanup;\n    cleanup:\n    return;\n}"
        issues = scan_with_rule("CGULL-018", code)
        self.assertEqual(len(issues), 1)

    def test_clean_no_goto(self):
        code = "void f(int error) {\n    if (error) {\n        return;\n    }\n}"
        issues = scan_with_rule("CGULL-018", code)
        self.assertEqual(len(issues), 0)


class TestParameterVoid(unittest.TestCase):
    def test_detects_empty_param_list(self):
        code = "int initialize_hardware() {\n    return 0;\n}"
        issues = scan_with_rule("CGULL-019", code)
        self.assertEqual(len(issues), 1)

    def test_clean_explicit_void(self):
        code = "int initialize_hardware(void) {\n    return 0;\n}"
        issues = scan_with_rule("CGULL-019", code)
        self.assertEqual(len(issues), 0)


class TestUnusedArguments(unittest.TestCase):
    def test_detects_unused_parameter(self):
        code = "int handle_event(int event_id, void *extra_data) {\n    return event_id;\n}"
        issues = scan_with_rule("CGULL-020", code)
        self.assertEqual(len(issues), 1)
        self.assertIn("extra_data", issues[0].message)

    def test_clean_all_parameters_used(self):
        code = "int handle_event(int event_id, void *extra_data) {\n    process(extra_data);\n    return event_id;\n}"
        issues = scan_with_rule("CGULL-020", code)
        self.assertEqual(len(issues), 0)

    def test_clean_underscore_prefixed_param_not_flagged(self):
        code = "int handle_event(int event_id, void *__reserved) {\n    return event_id;\n}"
        issues = scan_with_rule("CGULL-020", code)
        self.assertEqual(len(issues), 0)


class TestUninitializedPointers(unittest.TestCase):
    def test_detects_uninitialized_pointer(self):
        code = "void f(void) {\n    char *secret_key;\n    use(secret_key);\n}"
        issues = scan_with_rule("CGULL-021", code)
        self.assertEqual(len(issues), 1)

    def test_clean_initialized_to_null(self):
        code = "void f(void) {\n    char *secret_key = NULL;\n    use(secret_key);\n}"
        issues = scan_with_rule("CGULL-021", code)
        self.assertEqual(len(issues), 0)


class TestUseAfterFree(unittest.TestCase):
    def test_detects_use_after_free(self):
        code = "void f(struct Session *s) {\n    free(s);\n    printf(\"%d\", s->id);\n}"
        issues = scan_with_rule("CGULL-022", code)
        self.assertEqual(len(issues), 1)

    def test_clean_pointer_nulled_after_free(self):
        code = "void f(struct Session *s) {\n    free(s);\n    s = NULL;\n}"
        issues = scan_with_rule("CGULL-022", code)
        self.assertEqual(len(issues), 0)


class TestUninitializedMemoryUse(unittest.TestCase):
    def test_detects_uninitialized_scalar(self):
        code = "int f(int flag) {\n    int status;\n    if (flag) { status = 1; }\n    return status;\n}"
        issues = scan_with_rule("CGULL-023", code)
        self.assertEqual(len(issues), 1)

    def test_clean_initialized_at_declaration(self):
        code = "int f(int flag) {\n    int status = 0;\n    if (flag) { status = 1; }\n    return status;\n}"
        issues = scan_with_rule("CGULL-023", code)
        self.assertEqual(len(issues), 0)


class TestInsecureDataStorage(unittest.TestCase):
    def test_detects_hardcoded_password(self):
        code = 'void f(void) {\n    char *admin_password = "SuperSecret123!";\n}'
        issues = scan_with_rule("CGULL-024", code)
        self.assertEqual(len(issues), 1)

    def test_detects_sized_array_secret(self):
        code = 'void f(void) {\n    char api_key[64] = "AIzaSyD-secret-key";\n}'
        issues = scan_with_rule("CGULL-024", code)
        self.assertEqual(len(issues), 1)

    def test_detects_macro_sized_array_secret(self):
        code = 'void f(void) {\n    char api_key[SIZE] = "AIzaSyD-secret-key";\n}'
        issues = scan_with_rule("CGULL-024", code)
        self.assertEqual(len(issues), 1)

    def test_detects_const_sized_array_secret(self):
        code = 'void f(void) {\n    const char api_key[64] = "AIzaSyD-secret-key";\n}'
        issues = scan_with_rule("CGULL-024", code)
        self.assertEqual(len(issues), 1)

    def test_clean_env_var_loaded_secret(self):
        code = 'void f(void) {\n    char *api_key = getenv("API_KEY");\n}'
        issues = scan_with_rule("CGULL-024", code)
        self.assertEqual(len(issues), 0)


class TestFixMetadata(unittest.TestCase):
    def test_unsafe_secret_transformation_has_no_autofix(self):
        code = 'void f(void) {\n    char *admin_password = "SuperSecret123!";\n}'
        issues = scan_with_rule("CGULL-024", code)
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue.fix_type, FixType.MANUAL_REVIEW)
        self.assertIsNone(issue.auto_fix_replacement)

    def test_mechanically_safe_fix_populates_autofix(self):
        code = 'void f(char *user_input) {\n    printf(user_input);\n}'
        issues = scan_with_rule("CGULL-002", code)
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue.fix_type, FixType.SAFE_FIX)
        self.assertEqual(issue.auto_fix_replacement, 'printf("%s", user_input)')
        self.assertIsNone(issue.suggested_fix_replacement)

    def test_suggested_fix_populates_suggested_replacement_not_autofix(self):
        code = 'void f(char *b) {\n    gets(b);\n}'
        issues = scan_with_rule("CGULL-001", code)
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue.fix_type, FixType.SUGGESTED_FIX)
        self.assertIsNone(issue.auto_fix_replacement)
        self.assertIsNotNone(issue.suggested_fix_replacement)


class TestMissingAssertions(unittest.TestCase):
    def test_detects_long_function_without_assertions(self):
        body_lines = "\n".join(f"    x += {i};" for i in range(20))
        code = f"void compute_hash(uint8_t *in, size_t len) {{\n{body_lines}\n}}"
        issues = scan_with_rule("CGULL-025", code)
        self.assertEqual(len(issues), 1)

    def test_clean_function_with_assertions(self):
        body_lines = "\n".join(f"    x += {i};" for i in range(20))
        code = f"void compute_hash(uint8_t *in, size_t len) {{\n    assert(in != NULL && len > 0);\n{body_lines}\n}}"
        issues = scan_with_rule("CGULL-025", code)
        self.assertEqual(len(issues), 0)


class TestInsecurePRNG(unittest.TestCase):
    def test_detects_rand_for_token(self):
        code = "void f(void) {\n    int token = rand();\n}"
        issues = scan_with_rule("CGULL-028", code)
        self.assertEqual(len(issues), 1)

    def test_detects_multiline_rand_assignment(self):
        code = "void f(void) {\n    uint32_t session_token =\n        rand();\n}"
        issues = scan_with_rule("CGULL-028", code)
        self.assertEqual(len(issues), 1)

    def test_detects_srand_time(self):
        code = "void f(void) {\n    srand(time(NULL));\n}"
        issues = scan_with_rule("CGULL-028", code)
        self.assertEqual(len(issues), 1)

    def test_detects_constant_seed_srand(self):
        code = "void f(void) {\n    srand(1);\n}"
        issues = scan_with_rule("CGULL-028", code)
        self.assertEqual(len(issues), 1)

    def test_ignores_string_literal_rand(self):
        code = "void f(void) {\n    char *msg = \"don't use rand()\";\n}"
        issues = scan_with_rule("CGULL-028", code)
        self.assertEqual(len(issues), 0)

    def test_ignores_driver_variable_name(self):
        code = "void f(void) {\n    int driver_id = rand() % 10;\n}"
        issues = scan_with_rule("CGULL-028", code)
        self.assertEqual(len(issues), 0)

    def test_detects_init_iv_function_context(self):
        code = "void init_iv(unsigned char *out) {\n    int byte = rand();\n}"
        issues = scan_with_rule("CGULL-028", code)
        self.assertEqual(len(issues), 1)

    def test_clean_arc4random(self):
        code = "void f(uint32_t *token) {\n    *token = arc4random();\n}"
        issues = scan_with_rule("CGULL-028", code)
        self.assertEqual(len(issues), 0)


if __name__ == "__main__":
    unittest.main()

class TestMemoryRulesStructuredCFG(unittest.TestCase):
    """Regression coverage for branch-, loop-, and switch-sensitive memory flow."""

    def _scan(self, rule_id, code):
        return scan_with_rule(rule_id, code)

    def test_alloc_check_in_else_does_not_guard_if_branch(self):
        code = "void f(int ok) {\n    char *p = malloc(16);\n    if (ok) {\n        p[0] = 'x';\n    } else {\n        if (p == NULL) return;\n    }\n}"
        self.assertEqual(len(self._scan("CGULL-003", code)), 1)

    def test_alloc_check_inside_loop_does_not_guard_post_loop_use(self):
        code = "void f(int n) {\n    char *p = malloc(16);\n    while (n--) {\n        if (p == NULL) continue;\n    }\n    p[0] = 'x';\n}"
        self.assertEqual(len(self._scan("CGULL-003", code)), 1)

    def test_alloc_check_early_return_is_safe(self):
        code = "void f(size_t size) {\n    char *p = malloc(size);\n    if (p == NULL)\n        return;\n    p[0] = 'a';\n}"
        self.assertEqual(len(self._scan("CGULL-003", code)), 0)

    def test_alloc_check_logging_without_return_is_unsafe(self):
        code = "void f(size_t size) {\n    char *p = malloc(size);\n    if (p == NULL)\n        log_error();\n    p[0] = 'a';\n}"
        self.assertEqual(len(self._scan("CGULL-003", code)), 1)

    def test_null_check_guard_return_dominates_later_deref(self):
        code = "int f(int *p) {\n    if (p == NULL) return -1;\n    *p = 1;\n    return 0;\n}"
        self.assertEqual(len(self._scan("CGULL-004", code)), 0)

    def test_null_check_only_inside_loop_does_not_guard_after_loop(self):
        code = "int f(int *p, int n) {\n    while (n--) {\n        if (p == NULL) continue;\n    }\n    *p = 1;\n    return 0;\n}"
        self.assertEqual(len(self._scan("CGULL-004", code)), 1)

    def test_reassignment_after_free_is_not_uaf(self):
        code = "void f(char *p) {\n    free(p);\n    p = malloc(32);\n    if (p == NULL) return;\n    p[0] = 'a';\n}"
        self.assertEqual(len(self._scan("CGULL-022", code)), 0)

    def test_uaf_in_exclusive_else_branch_is_not_reported(self):
        code = "void f(int cond, char *p) {\n    if (cond) {\n        free(p);\n    } else {\n        p[0] = 'x';\n    }\n}"
        self.assertEqual(len(self._scan("CGULL-022", code)), 0)

    def test_uaf_after_if_is_reported(self):
        code = "void f(int cond, char *p) {\n    if (cond) free(p);\n    p[0] = 'x';\n}"
        self.assertEqual(len(self._scan("CGULL-022", code)), 1)

    def test_uaf_follows_switch_fallthrough(self):
        code = "void f(int which, char *p) {\n    switch (which) {\n    case 1:\n        free(p);\n    case 2:\n        p[0] = 'x';\n        break;\n    default:\n        break;\n    }\n}"
        self.assertEqual(len(self._scan("CGULL-022", code)), 1)

    def test_switch_break_does_not_reach_later_use_for_uaf(self):
        code = "void f(int which, char *p) {\n    switch (which) {\n    case 1:\n        free(p);\n        break;\n    case 2:\n        p[0] = 'x';\n        break;\n    default:\n        break;\n    }\n}"
        self.assertEqual(len(self._scan("CGULL-022", code)), 0)

    def test_uninitialized_pointer_conditional_assignment_reported(self):
        code = "void f(int cond) {\n    char *p;\n    if (cond) {\n        p = malloc(16);\n    }\n    p[0] = 'x';\n}"
        self.assertEqual(len(self._scan("CGULL-021", code)), 1)

    def test_uninitialized_pointer_all_branches_assigned_is_safe(self):
        code = "void f(int cond) {\n    char *p;\n    if (cond) {\n        p = malloc(16);\n    } else {\n        p = NULL;\n    }\n    p[0] = 'x';\n}"
        self.assertEqual(len(self._scan("CGULL-021", code)), 0)

    def test_uninitialized_scalar_conditional_assignment_reported(self):
        code = "int f(int cond) {\n    int status;\n    if (cond) {\n        status = 1;\n    }\n    return status;\n}"
        self.assertEqual(len(self._scan("CGULL-023", code)), 1)

    def test_uninitialized_scalar_all_branches_assigned_is_safe(self):
        code = "int f(int cond) {\n    int status;\n    if (cond) {\n        status = 1;\n    } else {\n        status = 0;\n    }\n    return status;\n}"
        self.assertEqual(len(self._scan("CGULL-023", code)), 0)
