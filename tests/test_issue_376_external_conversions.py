"""Exact-CWE pipeline coverage; manifest is the bounded handoff to #352."""
import pytest

from cgull import CGullScanner
from cgull.models import AnalysisEngine, ScanMode
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule

if __package__:
    from .run_external_conversion_corpus import CASES, scan_case
else:
    from run_external_conversion_corpus import CASES, scan_case


@pytest.mark.parametrize('case', CASES, ids=lambda c: c['id'])
@pytest.mark.parametrize('mode,engine', [
    (ScanMode.FILE, AnalysisEngine.AST),
    (ScanMode.TU, AnalysisEngine.HYBRID),
])
def test_manifest(case, mode, engine):
    assert scan_case(case, mode, engine) == sorted(
        (e['line'], e['column'], e['cwe']) for e in case['expected']
    )


def test_matrix_covers_every_required_integer_parameter():
    from cgull.ast_analyzer.standard_signatures import standard_callable_signature
    for api in ('malloc', 'memcpy', 'memmove', 'strncpy'):
        sig = standard_callable_signature(api)
        integer_positions = {n for n, p in enumerate(sig.parameters, 1) if not p.is_pointer}
        for source in ('prototype', 'fallback', 'local_header', 'compile_database'):
            assert {c['parameter'] for c in CASES if c.get('api') == api and c['signature_source'] == source} == integer_positions


@pytest.mark.parametrize('case', [c for c in CASES if c['signature_source'] != 'custom'], ids=lambda c: c['id'])
def test_disabling_signature_resolution_exposes_gap(case, monkeypatch):
    import cgull.rules.types_and_arrays.integer_narrowing_cast as rule
    class Unresolved:
        def resolve(self, call):
            return None
    monkeypatch.setattr(rule, 'build_direct_call_signature_index', lambda *args: Unresolved())
    # Explicit casts remain detectable; all implicit external bindings disappear.
    actual = scan_case(case)
    assert len(actual) == 2
    assert {cwe for _, _, cwe in actual} == {'CWE-194', 'CWE-195'}
    assert len(actual) < len(case['expected'])


def test_parallel_matches_sequential():
    case = next(c for c in CASES if c['id'] == 'memcpy_compile_database')
    assert scan_case(case, jobs=2) == scan_case(case)


def test_compile_header_is_used_and_config_does_not_leak(tmp_path, monkeypatch):
    import cgull.ast_analyzer.callable_signatures as signatures
    monkeypatch.setattr(signatures, 'standard_callable_signature', lambda name: None)
    for case in CASES:
        if case['signature_source'] in {'prototype', 'local_header', 'compile_database'}:
            assert len(scan_case(case)) == len(case['expected'])
        if case['signature_source'] == 'compile_database':
            without_database = {**case, 'signature_source': 'fallback'}
            assert len(scan_case(without_database)) == 2
    source = tmp_path / 'other.c'
    source.write_text('void caller(int n) { malloc(n); }\n', encoding='utf-8')
    scanner = CGullScanner(rules=[IntegerNarrowingCastRule()], engine_mode=AnalysisEngine.AST)
    assert scanner.scan_path(str(source), quiet=True).issues == []


def test_signature_metadata_does_not_change_behavioral_findings(tmp_path, monkeypatch):
    import cgull.ast_analyzer.callable_signatures as signatures
    from cgull.rules import get_rule_by_id
    source = tmp_path / 'effects.c'
    source.write_text('''void caller(int argc, char **argv) {
    char *p = malloc(8);
    if (!p) return;
    free(p);
    free(p);
    system(argv[1]);
}
''', encoding='utf-8')
    def findings():
        scanner = CGullScanner(rules=[get_rule_by_id(r) for r in ('CGULL-027', 'CGULL-030')])
        return [(i.rule_id, i.line_number, i.cwe_id) for i in scanner.scan_path(str(source), quiet=True).issues]
    before = findings()
    assert {rule for rule, _, _ in before} == {'CGULL-027', 'CGULL-030'}
    monkeypatch.setattr(signatures, 'standard_callable_signature', lambda name: None)
    assert findings() == before
