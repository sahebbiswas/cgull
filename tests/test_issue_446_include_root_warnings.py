import json
import os

import pytest

from cgull import CGullScanner, IncludeResolver, ReportGenerator, ScanConfig, load_config
from cgull.cli import main
from cgull.compile_database import CompileCommandIncludeDatabase


@pytest.mark.parametrize('filename,prefix', [('.cgull.toml', ''), ('pyproject.toml', 'tool.cgull.')])
def test_config_roots_keep_original_source_and_deduplicate(tmp_path, filename, prefix):
    (tmp_path / 'include').mkdir()
    (tmp_path / 'not-directory').write_text('text')
    path = tmp_path / filename
    path.write_text(f'[{prefix}includes]\nroots = ["include", "../missing", "../missing/../missing", "not-directory"]\n')
    (tmp_path / '.cgullincludes').write_text('../missing\nlegacy-missing\n')
    config = load_config(str(path))
    assert config.error is None
    assert len(config.warnings) == 3
    assert len(config.include_roots) == 4
    first = config.warnings[0]
    assert repr('../missing') in first
    assert repr(str((tmp_path.parent / 'missing').resolve())) in first
    assert str(path) in first
    assert 'not-directory' in config.warnings[1]
    assert '.cgullincludes:2' in config.warnings[2]


def test_valid_config_relative_to_declaration_not_cwd(tmp_path, monkeypatch):
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'include').mkdir()
    config_path = project / '.cgull.toml'
    config_path.write_text('[includes]\nroots = ["include"]\n')
    monkeypatch.chdir(tmp_path)
    assert load_config(str(config_path)).warnings == []


@pytest.mark.skipif(os.name == 'nt', reason='Backslashes are native separators on Windows')
def test_posix_does_not_reinterpret_backslashes(tmp_path):
    (tmp_path / 'include').mkdir()
    resolver = IncludeResolver([r'.\include'], base_dir=str(tmp_path))
    assert len(resolver.warnings) == 1
    assert resolver.include_roots == [str(tmp_path / r'.\include')]


def test_compile_database_attributes_and_deduplicates_roots(tmp_path):
    database = CompileCommandIncludeDatabase.from_data([
        {'directory': str(tmp_path), 'file': 'a.c',
         'arguments': ['cc', '-Imissing', '-isystem', './missing', '-I', 'generated']},
        {'directory': str(tmp_path), 'file': 'b.c',
         'arguments': ['cc', '-I./missing']},
    ])
    assert len(database.warnings) == 2
    assert 'entry 0' in database.warnings[0]
    assert str(tmp_path / 'a.c') in database.warnings[0]
    assert repr('missing') in database.warnings[0]
    assert repr(str(tmp_path / 'missing')) in database.warnings[0]
    assert database.roots_for(str(tmp_path / 'b.c')) == (str(tmp_path / 'missing'),)


@pytest.mark.parametrize('jobs', [1, 2])
@pytest.mark.parametrize('mode', ['file', 'tu'])
def test_api_scan_reports_warnings_once_and_continues(tmp_path, caplog, jobs, mode):
    for name in ['a', 'b']:
        (tmp_path / f'{name}.c').write_text(f'int {name}(void) {{ return 1; }}\n')
    config = ScanConfig.create(rules=[], include_roots=[str(tmp_path / 'missing')], mode=mode)
    scanner = CGullScanner(config=config)
    result = scanner.scan_path(str(tmp_path), jobs=jobs, quiet=True)
    assert result.files_analyzed == 2
    assert len(result.configuration_warnings) == 1
    assert 'API include_roots' in result.configuration_warnings[0]
    assert sum('Include root' in r.message for r in caplog.records) == 1
    assert json.loads(ReportGenerator.to_json(result))['configuration_warnings'] == result.configuration_warnings
    sarif = json.loads(ReportGenerator.to_sarif(result))
    assert sarif['runs'][0]['invocations'][0]['properties']['configurationWarnings'] == result.configuration_warnings
    # Collection is scoped to a scan; corrected roots must not leak old warnings.
    (tmp_path / 'missing').mkdir()
    assert scanner.scan_path(str(tmp_path), jobs=jobs, quiet=True).configuration_warnings == []


def test_cli_json_keeps_original_warning_without_duplicates(tmp_path, capsys):
    (tmp_path / 'a.c').write_text('int a(void) { return 0; }\n')
    (tmp_path / '.cgull.toml').write_text('[includes]\nroots = ["generated", "./generated"]\n')
    status = main(['scan', str(tmp_path), '--format', 'json', '--quiet', '-j', '1'])
    output = capsys.readouterr()
    assert status == 0
    assert output.err.count('Include root') == 1
    report = json.loads(output.out)
    assert len(report['configuration_warnings']) == 1
    assert repr('generated') in report['configuration_warnings'][0]
    assert '.cgull.toml' in report['configuration_warnings'][0]


def test_scan_text_and_compile_warnings_keep_provenance(tmp_path, caplog):
    source = tmp_path / 'a.c'
    database = CompileCommandIncludeDatabase.from_data([
        {'directory': str(tmp_path), 'file': 'a.c', 'arguments': ['cc', '-Imissing']},
    ])
    scanner = CGullScanner(config=ScanConfig.create(rules=[], mode='tu'), compile_database=database)
    result = scanner.scan_text('int a(void) { return 0; }', file_path=str(source), quiet=True)
    assert result.configuration_warnings == list(database.warnings)
    assert sum('Include root' in r.message for r in caplog.records) == 1


def test_scan_config_warning_serialization():
    config = ScanConfig.create(rules=[], include_root_warnings={'path': 'warning'})
    assert ScanConfig.from_dict(config.to_dict()).include_root_warnings == {'path': 'warning'}


def test_legacy_roots_are_collected_in_api_scan(tmp_path, caplog):
    source = tmp_path / 'a.c'
    source.write_text('int a(void) { return 0; }')
    (tmp_path / '.cgullincludes').write_text('# roots\nmissing\n./missing\n')
    scanner = CGullScanner(config=ScanConfig.create(rules=[], mode='tu'))
    result = scanner.scan_path(str(source), quiet=True)
    assert len(result.configuration_warnings) == 1
    assert '.cgullincludes:2' in result.configuration_warnings[0]
    assert sum('Include root' in r.message for r in caplog.records) == 1


def test_cli_deduplicates_config_and_compile_database(tmp_path, capsys):
    (tmp_path / 'a.c').write_text('int a(void) { return 0; }')
    (tmp_path / '.cgull.toml').write_text('[includes]\nroots = ["missing"]\n')
    (tmp_path / 'compile_commands.json').write_text(json.dumps([
        {'directory': str(tmp_path), 'file': 'a.c', 'arguments': ['cc', '-I./missing']},
    ]))
    assert main(['scan', str(tmp_path), '--format', 'json', '--quiet', '-j', '1']) == 0
    output = capsys.readouterr()
    assert output.err.count('Include root') == 1
    assert len(json.loads(output.out)['configuration_warnings']) == 1


def test_failed_scan_resets_warning_collection(tmp_path, monkeypatch, caplog):
    from cgull.include_diagnostics import record_root_warning

    scanner = CGullScanner(config=ScanConfig.create(rules=[]))

    def fail(*args, **kwargs):
        record_root_warning(str(tmp_path / 'bad'), 'first scan warning')
        raise ValueError('controlled failure')

    monkeypatch.setattr(scanner, '_scan_path', fail)
    with pytest.raises(ValueError, match='controlled failure'):
        scanner.scan_path(str(tmp_path))
    caplog.clear()
    # A standalone resolver must not append/log into an abandoned scan context.
    resolver = IncludeResolver(['bad'], base_dir=str(tmp_path))
    assert len(resolver.warnings) == 1
    assert not caplog.records


@pytest.mark.skipif(os.name != 'nt', reason='Windows canonical path casing')
def test_windows_equivalent_case_and_separator_roots(tmp_path):
    resolver = IncludeResolver(['Missing', './MISSING'], base_dir=str(tmp_path))
    assert len(resolver.warnings) == 1
    assert len(resolver.include_roots) == 1
