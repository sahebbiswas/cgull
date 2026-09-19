"""Nullable return contracts must not imply allocation or ownership."""

import pytest

from cgull.ast_analyzer import CASTParser
from cgull.call_effects import CallEffectConfigError, parse_call_effects
from cgull.cfg import Nullness, analyze_function_summaries
from cgull.cfg.summaries import _get_builtin_summaries
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


def scan(code, rule_id="CGULL-004"):
    scanner = CGullScanner(rules=[get_rule_by_id(rule_id)], engine_mode=AnalysisEngine.AST)
    return scanner.scan_text(code, "nullable.c").issues


@pytest.mark.parametrize("source,use", [
    ('crypt("password", "salt")', 'strcmp(p, "hash")'),
    ('getenv("HOME")', '*p'),
    ('strchr("abc", 120)', 'p[0]'),
    ('strrchr("abc", 120)', '*p'),
])
@pytest.mark.parametrize("guard", ["", "if (!p) return 0;", "if (p == 0) return 0;"])
def test_nullable_sources_and_dominating_guards(source, use, guard):
    issues = scan(f'int f(void) {{ char *p = {source}; {guard} return {use}; }}')
    assert len(issues) == (0 if guard else 1)
    if issues:
        assert issues[0].cwe_id == "CWE-476"
        assert "may be NULL" in issues[0].message


@pytest.mark.parametrize("use", ['p && *p', 'p ? p[0] : 0', 'p && strcmp(p, "x")', '!p || strcmp(p, "x")'])
def test_expression_local_guards(use):
    assert not scan(f'int f(void) {{ char *p = getenv("X"); return {use}; }}')


def test_same_tu_nullable_helper_and_struct_member():
    code = '''
        struct S { int value; };
        struct S *maybe(int flag) {
            static struct S s;
            if (flag) return &s;
            return 0;
        }
        int f(void) { struct S *p = maybe(1); return p->value; }
    '''
    summaries = analyze_function_summaries(CASTParser().parse(code))
    assert summaries["maybe"].return_nullness == Nullness.MAYBE_NULL
    assert len(scan(code)) == 1
    assert not scan(code.replace('return p->value;', 'if (!p) return 0; return p->value;'))


def test_nullable_contract_is_not_allocation():
    registry = parse_call_effects([
        {"function": "lookup", "returns": "nullable"},
        {"function": "consume", "nonnull": [0, 2]},
    ])
    summaries = _get_builtin_summaries(call_effects=registry)
    for name in ("lookup", "crypt", "getenv", "strchr", "strrchr", "fopen"):
        assert summaries[name].return_nullness == Nullness.MAYBE_NULL
        assert not summaries[name].returns_allocation
    assert summaries["consume"].unsafe_deref_params == {0, 2}
    assert summaries["strcmp"].unsafe_deref_params == {0, 1}
    assert summaries["malloc"].returns_allocation
    assert not scan('int f(void) { char *p = getenv("X"); return *p; }', "CGULL-003")
    assert scan('int f(void) { char *p = malloc(8); return *p; }', "CGULL-003")


@pytest.mark.parametrize("positions", [[-1], [True], [0, 0], "0"])
def test_invalid_nonnull_contract(positions):
    with pytest.raises(CallEffectConfigError):
        parse_call_effects([{"function": "consume", "nonnull": positions}])


def test_unknown_return_is_not_nullable_evidence():
    assert not scan('int f(void) { char *p = unknown(); return *p; }')


def test_definite_null_at_consumer_and_same_tu_wrapper():
    assert scan('int f(void) { char *p = 0; return strcmp(p, "x"); }')
    code = '''
        int consume(char *p) { return strcmp(p, "x"); }
        int f(void) { char *p = getenv("X"); return consume(p); }
    '''
    issues = scan(code)
    assert any("may be NULL" in issue.message for issue in issues)


def test_custom_contracts_reach_rule_through_config():
    from cgull.config import CGullConfig
    from cgull.semantic_models import parse_semantic_models

    config = CGullConfig(semantic_models=parse_semantic_models({"effects": [
        {"function": "lookup", "returns": "nullable"},
        {"function": "consume", "nonnull": [0]},
    ]}))
    rule = get_rule_by_id("CGULL-004")
    scanner = CGullScanner(rules=config.apply_to_rules([rule]),
                           engine_mode=AnalysisEngine.AST)
    code = 'int f(void) { char *p = lookup(); return consume(p); }'
    assert len(scanner.scan_text(code, "custom.c").issues) == 1
    assert not scanner.scan_text(code.replace('return consume', 'if (!p) return 0; return consume'), "custom.c").issues


def test_null_guard_does_not_hide_use_after_free():
    code = '''
        int f(void) {
            char *p = malloc(8);
            if (!p) return 0;
            free(p);
            return p ? *p : 0;
        }
    '''
    assert scan(code, "CGULL-022")
