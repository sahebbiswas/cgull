from cgull.engine import CGullScanner
from cgull.rules.memory_management import BufferCopyOverflowRule


def _scan(source: str):
    scanner = CGullScanner(rules=[BufferCopyOverflowRule()])
    return scanner.scan_text(source, file_path="issue_325.c").issues


def _messages(source: str):
    return [issue.message for issue in _scan(source)]


def test_strcpy_unknown_source_is_flagged_but_bounded_literal_is_safe():
    vulnerable = """
void bad(char *src) {
    char dst[8];
    strcpy(dst, src);
}
"""
    safe = """
void good(void) {
    char dst[8];
    strcpy(dst, "hello");
}
"""
    assert any("'strcpy'" in message for message in _messages(vulnerable))
    assert _scan(safe) == []


def test_strcat_accounts_for_known_existing_string_length():
    vulnerable = """
void bad(char *src) {
    char dst[8] = "abc";
    strcat(dst, src);
}
"""
    safe = """
void good(void) {
    char dst[8] = "abc";
    strcat(dst, "xy");
}
"""
    assert any("'strcat'" in message for message in _messages(vulnerable))
    assert _scan(safe) == []


def test_sprintf_unknown_formatted_extent_is_flagged_and_literal_output_is_safe():
    vulnerable = """
void bad(char *src) {
    char dst[8];
    sprintf(dst, "%s", src);
}
"""
    safe = """
void good(void) {
    char dst[8];
    sprintf(dst, "ok");
}
"""
    assert any("'sprintf'" in message for message in _messages(vulnerable))
    assert _scan(safe) == []


def test_gets_is_flagged_for_known_destination_capacity():
    source = """
void bad(void) {
    char dst[8];
    gets(dst);
}
"""
    assert any("'gets'" in message for message in _messages(source))


def test_memcpy_and_memmove_use_cfg_bounds_gates():
    for callee in ("memcpy", "memmove"):
        vulnerable = f"""
void bad(char *src, unsigned n) {{
    char dst[8];
    {callee}(dst, src, n);
}}
"""
        safe = f"""
void good(char *src, unsigned n) {{
    char dst[8];
    if (n <= 8) {{
        {callee}(dst, src, n);
    }}
}}
"""
        assert any(f"'{callee}'" in message for message in _messages(vulnerable))
        assert _scan(safe) == []


def test_scanf_percent_s_requires_width_that_includes_space_for_nul():
    vulnerable = """
void bad(void) {
    char dst[8];
    scanf("%s", dst);
}
"""
    safe = """
void good(void) {
    char dst[8];
    scanf("%7s", dst);
}
"""
    too_wide = """
void bad_width(void) {
    char dst[8];
    scanf("%8s", dst);
}
"""
    assert any("%s conversion is unbounded" in message for message in _messages(vulnerable))
    assert _scan(safe) == []
    assert any("%8s conversion" in message for message in _messages(too_wide))


def test_rule_metadata_targets_stack_and_heap_buffer_overflow_cwes():
    rule = BufferCopyOverflowRule()
    assert rule.rule_id == "CGULL-048"
    assert "CWE-121" in rule.cwe_id
    assert "CWE-122" in rule.cwe_id
    assert "strcpy" in rule.sample_vulnerable_code
    assert "snprintf" in rule.sample_remediated_code
