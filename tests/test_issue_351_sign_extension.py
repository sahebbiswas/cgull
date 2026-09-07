import pytest

from cgull.ast_analyzer import CASTParser
from cgull.models import Confidence, FixType
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def scan(body, source_type="signed char", destination_type="int"):
    code = f"""
void sink({destination_type} value) {{ (void)value; }}
void f({source_type} byte) {{
    {body}
}}
"""
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue351.c", ctx)


@pytest.mark.parametrize("body", [
    "int value = byte;",
    "int value = (int)byte;",
    "int value; value = byte;",
    "sink(byte);",
    "sink((int)byte);",
    "byte = -1; int value = byte;",
])
def test_detects_each_conversion_site_without_duplicates(body):
    findings = scan(body)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-194"
    assert findings[0].fix_type == FixType.MANUAL_REVIEW
    assert "sign-extend" in findings[0].message
    assert "byte or protocol" in findings[0].remediation


@pytest.mark.parametrize("source_type", ["signed char", "short", "int8_t", "int16_t", "const signed char"])
def test_narrow_signed_types_are_candidates(source_type):
    assert [finding.cwe_id for finding in scan("int value = byte;", source_type)] == ["CWE-194"]


@pytest.mark.parametrize("source_type,destination_type", [
    ("unsigned char", "int"), ("uint8_t", "int"),
    ("unsigned short", "int"), ("uint16_t", "int"),
    ("int", "long"), ("int32_t", "long long"),
    ("signed char", "signed char"), ("long", "long long"),
])
def test_unsigned_widening_and_ordinary_signed_widening_remain_clean(source_type, destination_type):
    assert scan(f"{destination_type} value = byte;", source_type, destination_type) == []


@pytest.mark.parametrize("body", [
    "byte = 0; int value = byte;",
    "byte = 127; int value = byte;",
    "if (byte >= 0) { int value = byte; }",
    "if (byte < 0) return; int value = byte;",
    "if (0 <= byte) sink(byte);",
    "if (byte >= 0 && byte <= 100) { int value = byte; }",
])
def test_proven_nonnegative_ranges_are_clean(body):
    assert scan(body) == []


@pytest.mark.parametrize("body", [
    "if (byte >= 0) {} int value = byte;",
    "if (byte >= 0) { byte = -1; int value = byte; }",
    "if (byte >= 0) { mutate(&byte); int value = byte; }",
    "if (byte <= 100) { int value = byte; }",
])
def test_partial_and_stale_guards_do_not_suppress(body):
    assert any(finding.cwe_id == "CWE-194" for finding in scan(body))


@pytest.mark.parametrize("source_type", ["char", "const char"])
def test_plain_char_reports_target_uncertainty(source_type):
    findings = scan("int value = byte;", source_type)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-194"
    assert findings[0].confidence == Confidence.LIMITED
    assert "signedness is unknown" in findings[0].message
    assert findings[0].fix_type == FixType.MANUAL_REVIEW


@pytest.mark.parametrize("body", [
    "byte = 42; int value = byte;",
    "if (byte >= 0) { int value = byte; }",
    "if (byte < 0) return; int value = byte;",
    "int value = (unsigned char)byte;",
])
def test_plain_char_portable_values_and_guards_are_clean(body):
    assert scan(body, "char") == []


def test_plain_char_high_bit_constant_is_not_assumed_nonnegative():
    findings = scan("char high = 255; int value = high;", "char")
    assert any(finding.cwe_id == "CWE-194" for finding in findings)


def test_typedefs_preserve_explicit_or_unknown_signedness():
    ctx = CASTParser().parse("""
typedef signed char signed_byte;
typedef unsigned char unsigned_byte;
typedef char plain_byte;
void f(signed_byte a, unsigned_byte b, plain_byte c) {
    int x = a;
    int y = b;
    int z = c;
}
""")
    findings = IntegerNarrowingCastRule().scan_ast("aliases.c", ctx)
    assert [finding.line_number for finding in findings] == [6, 8]
    assert findings[-1].confidence == Confidence.LIMITED


def test_widening_to_unsigned_has_one_sign_extension_finding():
    findings = scan("unsigned int value = byte;")
    assert [finding.cwe_id for finding in findings] == ["CWE-194"]


def test_unknown_and_non_integer_types_are_not_speculated_about():
    assert scan("double value = byte;") == []
    assert scan("int value = byte;", "float") == []


def test_explicit_unsigned_byte_cast_prevents_sign_extension():
    # The separate same-width signedness conversion remains a CWE-195 review.
    findings = scan("int value = (unsigned char)byte;")
    assert [finding.cwe_id for finding in findings] == ["CWE-195"]


@pytest.mark.parametrize("source_type", ["char", "signed char"])
def test_unsigned_zero_guard_does_not_prove_nonnegative_byte(source_type):
    assert any(finding.cwe_id == "CWE-194" for finding in scan(
        "if (byte >= 0U) { int value = byte; }", source_type
    ))


def test_portable_plain_char_cast_constant_is_clean():
    assert scan("int value = (char)42;", "char") == []



def test_plain_char_full_nonnegative_guard_suppresses():
    assert scan("if (byte >= 0 && byte <= 255) { int value = byte; }", "char") == []


def test_plain_char_high_bit_write_discards_preconversion_fact():
    findings = scan("byte = 255; int value = byte;", "char")
    assert any(finding.cwe_id == "CWE-194" for finding in findings)


def test_plain_char_guard_after_high_bit_write_is_respected():
    findings = scan("byte = 255; if (byte >= 0) { int value = byte; }", "char")
    assert all(finding.cwe_id != "CWE-194" for finding in findings)


@pytest.mark.parametrize("body", [
    "int value = 'A';", "int value = '\\n';",
    "char value = 'A'; int wide = value;",
    "signed char value = '\\0'; int wide = value;",
])
def test_c_character_constants_are_int_and_portable_values_are_clean(body):
    assert scan(body) == []
