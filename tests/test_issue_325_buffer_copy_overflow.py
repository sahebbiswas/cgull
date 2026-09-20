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


def test_sprintf_post_length_capacity_reject_is_not_reported():
    """cJSON print_number-style fail-closed length check (#562)."""
    source = """
int print_number(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    puts(number_buffer);
    return length;
}
"""
    assert _scan(source) == []


def test_sprintf_post_length_reject_with_intermediate_sscanf_is_not_reported():
    source = """
int print_number(double d) {
    unsigned char number_buffer[26];
    int length;
    double test;
    length = sprintf((char*)number_buffer, "%1.15g", d);
    if ((sscanf((char*)number_buffer, "%lg", &test) != 1)) {
        length = sprintf((char*)number_buffer, "%1.17g", d);
    }
    if ((length < 0) || (length > (int)(sizeof(number_buffer) - 1))) {
        return 0;
    }
    char *out = ensure(length + 1);
    memcpy(out, number_buffer, (size_t)length + 1);
    return 1;
}
char *ensure(int n);
"""
    assert _scan(source) == []


def test_sprintf_without_post_length_check_remains_reported():
    source = """
void bad(double d) {
    char number_buffer[26];
    sprintf(number_buffer, "%1.15g", d);
    puts(number_buffer);
}
"""
    assert any("'sprintf'" in message for message in _messages(source))


def test_sprintf_use_before_length_check_remains_reported():
    source = """
int bad(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    puts(number_buffer);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return 0;
}
"""
    assert any("'sprintf'" in message for message in _messages(source))

def test_sprintf_source_escape_via_formatter_before_reject_remains_reported():
    """sprintf(out, "%s", number_buffer) is an escape, not local inspection (#571)."""
    source = """
int bad(double d, char *out) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    sprintf(out, "%s", number_buffer);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return 0;
}
"""
    assert any("'sprintf'" in message for message in _messages(source))


def test_sprintf_reject_goto_into_buffer_use_remains_reported():
    """goto on the overflow path that later uses the buffer is not a bail (#571)."""
    source = """
int bad(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        goto use_buf;
    }
    return 0;
use_buf:
    puts(number_buffer);
    return -1;
}
"""
    assert any("'sprintf'" in message for message in _messages(source))


def test_sprintf_length_gt_sizeof_alone_is_not_credited():
    """length > sizeof(dest) accepts length == sizeof(dest), which still overflows by NUL."""
    source = """
int bad(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    if ((length < 0) || ((size_t)length > sizeof(number_buffer))) {
        return -1;
    }
    puts(number_buffer);
    return length;
}
"""
    assert any("'sprintf'" in message for message in _messages(source))


def test_sprintf_sscanf_string_copy_escape_before_reject_remains_reported():
    """sscanf(buf, "%s", out) copies defended buffer to an external sink (#571)."""
    source = """
int bad(double d, char *out) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    sscanf(number_buffer, "%s", out);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return 0;
}
"""
    assert any("'sprintf'" in message for message in _messages(source))


def test_sprintf_formatter_self_copy_before_reject_remains_reported():
    """sprintf(buf, "%s", buf) is not local inspection (#571)."""
    source = """
int bad(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    sprintf(number_buffer, "%s", number_buffer);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return 0;
}
"""
    assert any("'sprintf'" in message for message in _messages(source))


def test_sprintf_alias_escape_before_reject_remains_reported():
    """Alias then external use before the capacity reject must still report (#571)."""
    source = """
int bad(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    char *p = number_buffer;
    puts(p);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return length;
}
"""
    assert any("'sprintf'" in message for message in _messages(source))


def test_sprintf_address_alias_escape_before_reject_remains_reported():
    """&buf[0] alias then puts(alias) before reject must still report (#571)."""
    source = """
int bad(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    char *p = &number_buffer[0];
    puts(p);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    return length;
}
"""
    assert any("'sprintf'" in message for message in _messages(source))


def test_sprintf_alias_then_reject_then_use_is_credited():
    """Mere alias creation is not escape; use after reject may suppress (#571)."""
    source = """
int print_number(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    char *p = number_buffer;
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    puts(p);
    return length;
}
"""
    assert _scan(source) == []


def test_sprintf_address_alias_then_reject_then_use_is_credited():
    """&buf[0] alias alone is not escape; post-reject use may suppress (#571)."""
    source = """
int print_number(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    char *p = &number_buffer[0];
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    puts(p);
    return length;
}
"""
    assert _scan(source) == []


def test_sprintf_length_overwrite_before_reject_remains_reported():
    """Overwriting sprintf result before capacity compare must not suppress (#571)."""
    source = """
int bad(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    length = 0;
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        return -1;
    }
    puts(number_buffer);
    return length;
}
"""
    assert any("'sprintf'" in message for message in _messages(source))


def test_sprintf_reject_via_fatal_is_credited():
    """fatal/panic/err/errx align with CFG terminators as overflow bails (#571)."""
    source = """
void fatal(const char *msg);
int print_number(double d) {
    char number_buffer[26];
    int length = sprintf(number_buffer, "%1.15g", d);
    if ((length < 0) || ((size_t)length >= sizeof(number_buffer))) {
        fatal("overflow");
    }
    puts(number_buffer);
    return length;
}
"""
    assert _scan(source) == []
