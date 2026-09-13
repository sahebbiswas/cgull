"""Parser failure metadata is useful without changing scan success semantics."""
import json
import logging
import subprocess
import sys

import pytest

from cgull import CGullScanner, ScanConfig, AnalysisEngine, ScanMode
from cgull.ast_analyzer import CASTParser
from cgull.ast_analyzer.configuration import _PRELUDE_LINE_COUNT
from cgull.parse_diagnostics import make_attempt, format_attempts
from cgull.reporter import ReportGenerator

BAD = 'void f(void) {\n    unknown_type threadAttr;\n}\n'


def test_both_failures_and_coordinates():
    ctx = CASTParser().parse(BAD)
    assert ctx.parse_tier == 'regex-fallback'
    assert [a['status'] for a in ctx.parse_attempts] == ['failure', 'failure']
    for a in ctx.parse_attempts:
        assert a['exception_category'] == 'ParseError'
        assert 'threadAttr' in a['message']
        assert a['expanded_line'] == 2 + _PRELUDE_LINE_COUNT
        assert a['original_line'] == 2
        assert a['original_column'] == 18
        assert a['preprocessing_failed'] is False


def test_first_failure_second_success(monkeypatch):
    parser = CASTParser()
    monkeypatch.setattr(parser, '_try_pcpp_preprocess', lambda *a, **kw: 'broken text;')
    ctx = parser.parse('int x;')
    assert ctx.parse_tier == 'directive-stripped'
    assert [a['status'] for a in ctx.parse_attempts] == ['failure', 'success']


def test_preprocessing_failure(monkeypatch):
    import pcpp
    def fail(*args, **kwargs):
        raise ValueError('broken\nmacro\x1b[31m' + 'x' * 500)
    monkeypatch.setattr(pcpp.Preprocessor, 'parse', fail)
    ctx = CASTParser().parse('int x;')
    attempt = ctx.parse_attempts[0]
    assert attempt['preprocessing_failed']
    assert attempt['exception_category'] == 'ValueError'
    assert len(attempt['message']) <= 240
    assert all(c.isprintable() for c in attempt['message'])
    assert ctx.parse_tier == 'directive-stripped'


def test_missing_dependency(monkeypatch):
    monkeypatch.setitem(sys.modules, 'pycparser', None)
    ctx = CASTParser().parse('int x;')
    assert [a['status'] for a in ctx.parse_attempts] == ['skipped', 'skipped']


def test_parser_reuse_resets_attempts():
    parser = CASTParser()
    failed = parser.parse(BAD)
    success = parser.parse('int x;')
    assert len(failed.parse_attempts) == 2
    assert [a['status'] for a in success.parse_attempts] == ['success']


def test_header_mapping_parallel_and_reports(tmp_path):
    (tmp_path / 'bad.h').write_text(BAD)
    for name in ['a.c', 'b.c']:
        (tmp_path / name).write_text('#include "bad.h"\n')
    config = ScanConfig.create(engine_mode=AnalysisEngine.HYBRID, mode=ScanMode.TU)
    scanner = CGullScanner(config=config)
    seq = scanner.scan_path(str(tmp_path), jobs=1, quiet=True)
    par = scanner.scan_path(str(tmp_path), jobs=2, quiet=True)
    assert seq.files_failed == par.files_failed == 0
    left = [(s.file_path, s.parse_attempts) for s in seq.file_summaries]
    assert left == [(s.file_path, s.parse_attempts) for s in par.file_summaries]
    assert left
    for _, attempts in left:
        assert len(attempts) == 2
        for a in attempts:
            assert a['original_file'] == 'bad.h'
            assert a['original_line'] == 2
    data = json.loads(ReportGenerator.to_json(seq))
    assert data['file_summaries'][0]['parse_attempts'] == left[0][1]
    sarif = json.loads(ReportGenerator.to_sarif(seq))
    assert sarif['runs'][0]['properties']['file_summaries'][0] == {
        'file_path': left[0][0], 'parse_attempts': left[0][1],
    }


def test_debug_only_for_fallback(caplog):
    scanner = CGullScanner()
    with caplog.at_level(logging.DEBUG):
        result = scanner.scan_text(BAD, file_path='broken.c')
    assert result.files_failed == 0
    assert 'used regex-fallback' in caplog.text
    assert 'threadAttr' in caplog.text
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        scanner.scan_text('int x;')
    assert 'used regex-fallback' not in caplog.text


def test_warn_stdout_is_json(tmp_path):
    source = tmp_path / 'bad.c'
    source.write_text(BAD)
    run = subprocess.run([sys.executable, '-m', 'cgull', 'scan', str(source),
                          '--format', 'json', '--warn-on-fallback'], text=True, capture_output=True)
    assert run.returncode == 1
    data = json.loads(run.stdout)
    assert data['file_summaries'][0]['status'] == 'success'
    assert 'pcpp+pycparser failure' in run.stderr
    assert 'directive-stripped failure' in run.stderr
    assert 'threadAttr' in run.stderr


def test_macro_column_not_invented():
    ctx = CASTParser().parse('#define TYPE unknown_type\nvoid f(void) { TYPE x; }\n')
    attempt = ctx.parse_attempts[0]
    assert attempt['expanded_column']
    assert attempt['original_column'] is None


def test_format_sanitized_and_bounded():
    attempt = make_attempt('directive-stripped', 'failure', ValueError('\n' + 'x' * 1000))
    text = format_attempts('bad\r\n.c', [attempt])
    assert '\n' not in text and '\r' not in text
    assert len(attempt['message']) == 240


def test_active_preprocessor_error_has_original_location(capsys):
    ctx = CASTParser().parse('#error unsupported configuration\nint x;\n')
    attempt = ctx.parse_attempts[0]
    assert attempt['preprocessing_failed'] is True
    assert attempt['expanded_line'] == _PRELUDE_LINE_COUNT + 1
    assert attempt['source_line'] == attempt['original_line'] == 1
    assert 'unsupported configuration' in attempt['message']
    assert ctx.parse_tier == 'directive-stripped'
    assert capsys.readouterr() == ('', '')


def test_profile_attempts_preserved():
    from cgull import ConfigProfile
    profiles = [ConfigProfile('a', {'A': True}), ConfigProfile('b', {'A': False})]
    result = CGullScanner().scan_text_profiles(BAD, profiles, quiet=True)
    attempts = result.file_summaries[0].parse_attempts
    assert [a['profile'] for a in attempts] == ['a', 'a', 'b', 'b']
    assert all(a['status'] == 'failure' for a in attempts)


def test_regex_only_has_no_attempts():
    scanner = CGullScanner(config=ScanConfig.create(engine_mode=AnalysisEngine.REGEX))
    assert scanner.scan_text(BAD).file_summaries[0].parse_attempts == []


def test_pcpp_unavailable_is_skipped(monkeypatch):
    monkeypatch.setitem(sys.modules, 'pcpp', None)
    ctx = CASTParser().parse('int x;')
    assert ctx.parse_attempts[0]['status'] == 'skipped'
    assert ctx.parse_attempts[0]['preprocessing_failed'] is False
    assert ctx.parse_tier == 'directive-stripped'


def test_report_path_preserves_spaces(tmp_path):
    from cgull.parse_diagnostics import map_attempts, report_attempts
    path = str(tmp_path / 'two  spaces.c')
    attempts = map_attempts([make_attempt('directive-stripped', 'failure')], '', file_path=path)
    assert report_attempts(attempts, str(tmp_path))[0]['original_file'] == 'two  spaces.c'


@pytest.mark.parametrize('path', [None, ''])
@pytest.mark.parametrize('fallback', [None, 'input.c'])
def test_missing_provenance_path_uses_fallback(path, fallback):
    from cgull.includes import SourceLocation
    from cgull.parse_diagnostics import map_attempts
    attempt = make_attempt('directive-stripped', 'failure', ValueError('<input>:1:1: bad'))
    line_map = {1: SourceLocation(path, 12, 'int x;')}
    result = map_attempts([attempt], 'int x;', line_map, fallback)[0]
    assert result['original_file'] == fallback
    assert result['original_line'] == 12


@pytest.mark.parametrize('line', [-1, 0, 2])
def test_unavailable_coordinates_do_not_verify_columns(line):
    attempt = make_attempt('directive-stripped', 'failure',
                           ValueError(f'<input>:{line}:1: bad'),
                           prepared='int x;', source='int x;')
    assert attempt['source_column'] is None


def test_preprocessor_on_error_includes_prelude_offset(capsys):
    ctx = CASTParser().parse('#if 1\nint x;\n')
    attempt = ctx.parse_attempts[0]
    assert attempt['preprocessing_failed'] is True
    assert attempt['expanded_line'] == _PRELUDE_LINE_COUNT + 1
    assert attempt['original_line'] == 1
    assert 'unterminated #if' in attempt['message'].lower()
    assert capsys.readouterr() == ('', '')
