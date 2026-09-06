from cgull.engine import CGullScanner
from cgull.rules.memory_management import (
    BufferCopyOverflowRule,
    MemcpyStructMemberOverflowRule,
)


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


def test_memcpy_and_memmove_remain_owned_by_cgull_044_without_duplicate_048_findings():
    for callee in ("memcpy", "memmove"):
        source = f"""
void bad(char *src, unsigned n) {{
    char dst[8];
    {callee}(dst, src, n);
}}
"""
        assert _scan(source) == []

        scanner = CGullScanner(
            rules=[MemcpyStructMemberOverflowRule(), BufferCopyOverflowRule()]
        )
        issues = scanner.scan_text(source, file_path="issue_325.c").issues
        assert [issue.rule_id for issue in issues].count("CGULL-044") == 1
        assert all(issue.rule_id != "CGULL-048" for issue in issues)


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


def test_scanf_assignment_suppression_does_not_shift_later_string_destination():
    source = """
void bad(void) {
    char dst[8];
    scanf("%*s %s", dst);
}
"""
    issues = _scan(source)
    assert len(issues) == 1
    assert "%s conversion is unbounded" in issues[0].message


def test_scanf_suppressed_numeric_conversion_preserves_argument_alignment():
    source = """
void bad(void) {
    int value;
    char dst[8];
    scanf("%*d %d %s", &value, dst);
}
"""
    issues = _scan(source)
    assert len(issues) == 1
    assert "8-byte destination" in issues[0].message
    assert "%s conversion is unbounded" in issues[0].message


def test_scanf_scanset_is_checked_like_percent_s():
    vulnerable = r'''
void bad(void) {
    char dst[8];
    scanf("%[^\n]", dst);
}
'''
    safe = r'''
void good(void) {
    char dst[8];
    scanf("%7[^\n]", dst);
}
'''
    too_wide = r'''
void bad_width(void) {
    char dst[8];
    scanf("%8[^\n]", dst);
}
'''
    assert any("%[ conversion is unbounded" in message for message in _messages(vulnerable))
    assert _scan(safe) == []
    assert any("%8[ conversion" in message for message in _messages(too_wide))


def test_scanf_consecutive_scansets_keep_destinations_aligned():
    source = """
void bad(void) {
    char first[16];
    char second[4];
    scanf("%15[a-z]%[0-9]", first, second);
}
"""
    issues = _scan(source)
    assert len(issues) == 1
    assert "4-byte destination" in issues[0].message
    assert "%[ conversion is unbounded" in issues[0].message


def test_scanf_scanset_allows_literal_closing_bracket_first():
    source = """
void bad(void) {
    char first[8];
    char second[4];
    scanf("%7[]]%[^]]", first, second);
}
"""
    issues = _scan(source)
    assert len(issues) == 1
    assert "4-byte destination" in issues[0].message


def test_rule_metadata_targets_stack_and_heap_buffer_overflow_cwes():
    rule = BufferCopyOverflowRule()
    assert rule.rule_id == "CGULL-048"
    assert "CWE-121" in rule.cwe_id
    assert "CWE-122" in rule.cwe_id
    assert "strcpy" in rule.sample_vulnerable_code
    assert "snprintf" in rule.sample_remediated_code
    assert "memcpy" not in rule.TARGET_FUNCS
    assert "memmove" not in rule.TARGET_FUNCS
