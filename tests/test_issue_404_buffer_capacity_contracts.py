"""Focused regressions for issue #404 / CGULL-007 buffer capacities."""

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import ArrayIndexOutOfBoundsRule
from cgull.semantic_models import parse_semantic_models


def _scan(code: str, capacities=None):
    rule = ArrayIndexOutOfBoundsRule()
    if capacities is not None:
        rule._semantic_models = parse_semantic_models({
            "effects": [{
                "function": "f",
                "buffer_capacities": capacities,
            }]
        })
    return rule.scan_ast("issue_404.c", CASTParser().parse(code))


def _elements(buffer=0, size=1):
    return [{"buffer": buffer, "size": size, "unit": "elements"}]


def test_pointer_length_names_alone_do_not_prove_capacity():
    code = """
    void f(unsigned char *data, unsigned long length) {
        for (unsigned long i = 0; i < length; ++i) {
            data[i] = 0;
        }
    }
    """
    issues = _scan(code)
    assert any("Unchecked Array Indexing" in issue.message for issue in issues)


def test_element_count_contract_proves_for_loop_access():
    code = """
    void f(unsigned char *data, unsigned long length) {
        for (unsigned long i = 0; i < length; ++i) {
            data[i] = 0;
        }
    }
    """
    assert _scan(code, _elements()) == []


def test_element_count_contract_proves_while_loop_access():
    code = """
    void f(unsigned char *data, unsigned long length) {
        unsigned long i = 0;
        while (i < length) {
            data[i] = 0;
            ++i;
        }
    }
    """
    assert _scan(code, _elements()) == []


def test_less_equal_length_is_not_safe_for_exact_capacity():
    code = """
    void f(unsigned char *data, unsigned long length) {
        for (unsigned long i = 0; i <= length; ++i) {
            data[i] = 0;
        }
    }
    """
    issues = _scan(code, _elements())
    assert any("Unchecked Array Indexing" in issue.message for issue in issues)


def test_reassigning_length_invalidates_contract():
    code = """
    void f(unsigned char *data, unsigned long length) {
        length = length + 1;
        for (unsigned long i = 0; i < length; ++i) {
            data[i] = 0;
        }
    }
    """
    issues = _scan(code, _elements())
    assert any("Unchecked Array Indexing" in issue.message for issue in issues)


def test_local_pointer_alias_preserves_contract():
    code = """
    void f(unsigned char *data, unsigned long length) {
        unsigned char *alias = data;
        for (unsigned long i = 0; i < length; ++i) {
            alias[i] = 0;
        }
    }
    """
    assert _scan(code, _elements()) == []


def test_byte_contract_only_proves_one_byte_elements():
    byte_contract = [{"buffer": 0, "size": 1, "unit": "bytes"}]
    byte_code = """
    void f(unsigned char *data, unsigned long length) {
        for (unsigned long i = 0; i < length; ++i) data[i] = 0;
    }
    """
    assert _scan(byte_code, byte_contract) == []

    wide_code = """
    void f(unsigned int *data, unsigned long length) {
        for (unsigned long i = 0; i < length; ++i) data[i] = 0;
    }
    """
    issues = _scan(wide_code, byte_contract)
    assert any("Unchecked Array Indexing" in issue.message for issue in issues)


def test_static_vla_parameter_encodes_capacity_without_config():
    code = """
    void f(unsigned long length, unsigned char data[static length]) {
        for (unsigned long i = 0; i < length; ++i) {
            data[i] = 0;
        }
    }
    """
    assert _scan(code) == []


def test_capacity_configuration_validation():
    registry = parse_semantic_models({
        "effects": [{
            "function": "f",
            "buffer_capacities": [{"buffer": 0, "size": 1, "unit": "elements"}],
        }]
    })
    assert registry.call_effects.for_function("f").buffer_capacities == ((0, 1, "elements"),)
