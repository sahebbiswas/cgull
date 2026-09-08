"""Manifest-driven external conversion pipeline corpus shared with run_corpus."""
import json
from pathlib import Path

from cgull import CGullScanner, CompileCommandIncludeDatabase
from cgull.models import AnalysisEngine, ScanConfig, ScanMode
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule

ROOT = Path(__file__).parent / 'rules' / 'CGULL-049' / 'external_calls'
MANIFEST = json.loads((ROOT / 'manifest.json').read_text(encoding='utf-8'))
CASES = MANIFEST['cases']


def scan_case(case, mode=ScanMode.FILE, engine=AnalysisEngine.AST, jobs=1):
    source = ROOT / case['file']
    database = None
    if case['signature_source'] == 'compile_database':
        database = CompileCommandIncludeDatabase.from_data([{
            'directory': str(source.parent), 'file': str(source),
            'arguments': ['cc', '-I', str(source.parent / 'include'), '-c', str(source)],
        }], database_dir=str(source.parent))
    scanner = CGullScanner(config=ScanConfig.create(
        rules=[IntegerNarrowingCastRule()], mode=mode, engine_mode=engine,
    ), compile_database=database)
    result = scanner.scan_path(str(source), quiet=True, jobs=jobs)
    assert result.files_failed == 0
    assert all((source.parent / i.file_path).resolve() == source.resolve() for i in result.issues)
    return sorted((i.line_number, i.column_number, i.cwe_id) for i in result.issues)
