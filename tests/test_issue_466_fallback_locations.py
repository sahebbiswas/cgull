"""Fallback CGULL-042 must retain a concrete write/binding/source association."""

import re
from pathlib import Path

import pytest

from cgull.ast_analyzer import CASTParser
from cgull.ast_analyzer.visitor import CASTParser as LegacyParser
from cgull.engine import CGullScanner, compute_issue_fingerprint
from cgull.models import FixType, ScanConfig
from cgull.rules import get_rule_by_id
from cgull.rules.dead_stores import _expanded_context
from cgull.rules.fallback_writes import WriteSource, verified_write


def force_fallback(monkeypatch, parser_type=CASTParser):
    monkeypatch.setattr(parser_type, '_try_pycparser', lambda *a, **k: (None, False, 'regex-fallback'))


def scan(source, monkeypatch, parser_type=CASTParser):
    force_fallback(monkeypatch, parser_type)
    context = parser_type().parse(source)
    assert context.parse_tier == 'regex-fallback'
    return context, get_rule_by_id('CGULL-042').scan_ast('test.c', context)


OSLOG = '''void log_message(void)
{
    unsigned long long fileSize = 0;
    int space = measure();
    char msg[10] = {0};
    int msgLen = measure();
    char pad[3] = "*";
    int varLen = measure();
    OSGetLocalTime();
    varLen = measure();
    char debugMsg[10] = {0};
    int logSize = measure();
    {
        int rtnVal = measure();
    }
}
'''


@pytest.mark.parametrize('parser_type', [CASTParser, LegacyParser])
@pytest.mark.parametrize('header', ['void log_message(void)\n{', 'void log_message(\n    void)\n{'])
def test_oslog_adjacent_declarations_and_calls(monkeypatch, parser_type, header):
    source = OSLOG.replace('void log_message(void)\n{', header)
    context, issues = scan(source, monkeypatch, parser_type)
    expected = {i for i, line in enumerate(source.splitlines(), 1) if '= measure()' in line}
    assert {issue.line_number for issue in issues} == expected
    assert len(issues) == 6
    for issue in issues:
        name = re.search("variable '([^']+)'", issue.message).group(1)
        assert re.search(rf'\b{name}\s*=', issue.code_snippet)
        assert issue.code_snippet == source.splitlines()[issue.line_number - 1].strip()
        assert issue.fix_type == FixType.MANUAL_REVIEW
    assert context.functions[0].calls[-1][1] == max(expected)


def test_multiline_declarations_and_assignments_start_at_statement(monkeypatch):
    source = '''void f(void)
{
    int value =
        compute();
    value =
        compute();
    int
        other = compute();
    other
        = compute();
}
'''
    context, issues = scan(source, monkeypatch)
    assert {issue.line_number for issue in issues} == {3, 5, 7, 9}
    assert context.functions[0].variables['other'].declaration_line == 7
    for issue in issues:
        name = re.search("variable '([^']+)'", issue.message).group(1)
        assert re.search(rf'\b{name}\s*=', issue.code_snippet)


def test_shadowed_binding_reads_and_writes_remain_in_scope(monkeypatch):
    source = '''void f(void)
{
    int x = compute();
    {
        int x = compute();
        x = 1;
    }
    consume(x);
    x = 2;
}
'''
    context, issues = scan(source, monkeypatch)
    outer, inner = dict.values(context.functions[0].variables)
    assert outer.assigned_lines == [3, 9]
    assert outer.read_lines == [8]
    assert inner.assigned_lines == [5, 6]
    assert inner.read_lines == []
    assert {issue.line_number for issue in issues} == {5, 6, 9}


@pytest.mark.parametrize('statement', ['x = 1; x = 2;', 'x = 1; call();', 'int x = compute(), y = compute();'])
def test_ambiguous_compact_statements_are_withheld(monkeypatch, statement):
    _, issues = scan('void f(void) {\nint x;\n' + statement + '\n}', monkeypatch)
    assert issues == []


def test_inconsistent_binding_location_is_withheld(monkeypatch):
    context, _ = scan('void f(void)\n{\nint x;\ncall();\nx = 1;\n}', monkeypatch)
    variable = context.functions[0].variables['x']
    variable.assigned_lines_exp = [2, 4]
    assert get_rule_by_id('CGULL-042').scan_ast('test.c', context) == []


def test_expanded_and_original_coordinates_are_distinct(monkeypatch):
    force_fallback(monkeypatch)
    source = 'void f(void)\n{\nint x;\nx = 1;\n}'
    context = CASTParser().parse(source, line_map={i: i + 100 for i in range(1, 6)})
    variable = context.functions[0].variables['x']
    assert variable.declaration_line == 103
    assert variable.declaration_line_exp == 3
    assert variable.assigned_lines == [104]
    assert variable.assigned_lines_exp == [4]
    expanded = _expanded_context(context)
    function = expanded.functions[0]
    variable = next(iter(function.variables.values()))
    event = verified_write(expanded, function, variable, 4, WriteSource(expanded))
    assert event.expanded_line == 4
    assert event.original_location == 104
    assert event.kind == 'assignment'
    assert event.binding[0] == 'x'


def test_tu_original_locations_header_provenance_and_suppression(tmp_path, monkeypatch):
    force_fallback(monkeypatch)
    header = tmp_path / 'types.h'
    header_source = 'typedef int LogInfo;\nvoid helper(void)\n{\nint headerValue = compute();\n}\n'
    header.write_text(header_source)
    main = tmp_path / 'OSLog.c'
    source = '#include "types.h"\n' + OSLOG
    main.write_text(source)
    scanner = CGullScanner(rules=[get_rule_by_id('CGULL-042')], config=ScanConfig.create(mode='tu'))
    result = scanner.scan_path(str(tmp_path), quiet=True)
    assert all(item.parse_tier == 'regex-fallback' for item in result.file_summaries)
    assert len(result.issues) == 7
    for issue in result.issues:
        original = header_source if Path(issue.file_path).name == header.name else source
        assert issue.code_snippet == original.splitlines()[issue.line_number - 1].strip()
        name = re.search("variable '([^']+)'", issue.message).group(1)
        assert re.search(rf'\b{name}\s*=', issue.code_snippet)
        assert issue.fingerprint == compute_issue_fingerprint(issue.rule_id, issue.file_path, issue.code_snippet)
    assert any(Path(issue.file_path).name == header.name and issue.line_number == 4 for issue in result.issues)
    main.write_text(source.replace('int space = measure();', 'int space = measure(); // cgull-ignore: CGULL-042'))
    suppressed = scanner.scan_path(str(tmp_path), quiet=True)
    assert len(suppressed.issues) == 6
    assert not any("variable 'space'" in issue.message for issue in suppressed.issues)


def test_multiline_pure_declaration_is_suppressed(monkeypatch):
    _, issues = scan("void f(void)\n{\nint\n x = 0;\n}", monkeypatch)
    assert issues == []


def test_compound_assignment_event_retains_kind(monkeypatch):
    context, _ = scan("void f(void)\n{\nint x;\nx += 1;\n}", monkeypatch)
    function = context.functions[0]
    variable = function.variables['x']
    event = verified_write(context, function, variable, 4, WriteSource(context))
    assert event.kind == 'compound_assignment'
    assert event.statement == 'x += 1;'


def test_legacy_rule_entry_point_uses_verified_fallback(monkeypatch):
    from cgull.rules.misra_and_style import DeadStoresRule
    context, expected = scan(OSLOG, monkeypatch)
    assert DeadStoresRule().scan_ast('test.c', context) == expected


def test_repeated_original_lines_do_not_collapse_expanded_writes(monkeypatch):
    force_fallback(monkeypatch)
    source = "void f(void)\n{\nint x;\nx = 1;\nx = 2;\n}"
    context = CASTParser().parse(source, line_map={4: 100, 5: 100})
    variable = context.functions[0].variables['x']
    assert variable.assigned_lines == [100]
    assert variable.assigned_lines_exp == [4, 5]
    assert {issue.line_number for issue in get_rule_by_id('CGULL-042').scan_ast('test.c', context)} == {4, 5}


def test_tu_multiline_write_restores_entire_original_statement(tmp_path, monkeypatch):
    force_fallback(monkeypatch)
    (tmp_path / 'types.h').write_text('typedef int LogInfo;\n\n')
    main = tmp_path / 'main.c'
    main.write_text('#include "types.h"\nvoid f(void)\n{\nLogInfo\n value = compute();\nvalue =\n compute();\n}\n')
    scanner = CGullScanner(rules=[get_rule_by_id('CGULL-042')], config=ScanConfig.create(mode='tu'))
    result = scanner.scan_path(str(tmp_path), quiet=True)
    assert [(i.line_number, i.code_snippet) for i in result.issues] == [
        (4, 'LogInfo\n value = compute();'), (6, 'value =\n compute();'),
    ]
    assert all(i.expanded_end_line is None for i in result.issues)
