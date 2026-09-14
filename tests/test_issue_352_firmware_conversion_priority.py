from cgull.ast_analyzer import CASTParser
from cgull.models import Confidence, Severity
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def _scan(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue_352.c", ctx)


def test_volatile_register_destination_is_high_priority():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
volatile uint8_t REGISTER;
void write_register(uint32_t value) {
    REGISTER = value;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.rule_id == "CGULL-049"
    assert issue.cwe_id == "CWE-197"
    assert issue.impact == Severity.HIGH
    assert issue.confidence == Confidence.FULL
    assert "Firmware priority" in issue.message
    assert "volatile destination" in issue.message


def test_volatile_aggregate_destination_is_high_priority():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
struct Registers { uint8_t value; };
void write_register(uint32_t value) {
    volatile struct Registers regs;
    regs.value = value;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].impact == Severity.HIGH
    assert issues[0].confidence == Confidence.FULL
    assert "volatile destination" in issues[0].message


def test_bitfield_destination_is_high_priority():
    code = """
typedef unsigned int uint32_t;
struct Registers { unsigned char mode : 4; };
void write_mode(struct Registers *regs, uint32_t value) {
    regs->mode = value;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.cwe_id == "CWE-197"
    assert issue.impact == Severity.HIGH
    assert issue.confidence == Confidence.FULL
    assert "bitfield destination" in issue.message


def test_plain_fixed_width_destination_is_not_treated_as_mmio():
    code = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
void store_byte(uint32_t value) {
    uint8_t byte;
    byte = value;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.impact == Severity.MEDIUM
    assert issue.confidence is None
    assert "Firmware priority" not in issue.message


def test_hardware_like_typedef_name_alone_does_not_raise_priority():
    code = """
typedef unsigned char mmio_register8_t;
typedef unsigned int uint32_t;
void store_byte(uint32_t value) {
    mmio_register8_t local_register;
    local_register = value;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    assert issues[0].impact == Severity.MEDIUM
    assert issues[0].confidence is None
    assert "Firmware priority" not in issues[0].message


def test_plain_char_limited_confidence_is_not_overwritten_by_priority():
    code = """
volatile int REGISTER;
void write_register(char value) {
    REGISTER = value;
}
"""
    issues = _scan(code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.cwe_id == "CWE-194"
    assert issue.impact == Severity.HIGH
    assert issue.confidence == Confidence.LIMITED
    assert "Firmware priority" in issue.message
