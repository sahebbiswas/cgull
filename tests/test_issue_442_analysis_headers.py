"""Linux TU parsing, precedence and infrastructure provenance regressions."""

from pathlib import Path
import shutil

import pytest

from cgull import CGullScanner
from cgull.analysis_headers import analysis_header_roots, is_analysis_header
from cgull.ast_analyzer import CASTParser
from cgull.includes import HEADER_CACHE, IncludeResolver, expand_includes
from cgull.models import ScanConfig


FIXTURE = Path(__file__).parent / "fixtures" / "linux_analysis_headers"


def test_six_linux_sources_parse_with_only_project_include_root():
    HEADER_CACHE.clear()
    for source in sorted(FIXTURE.glob("*.c")):
        expanded = expand_includes(
            source.read_text(), str(source), include_roots=[str(FIXTURE / "include")]
        )
        assert CASTParser().parse(expanded).parse_tier == "pcpp+pycparser", source.name
        assert expanded.included_files == {str((FIXTURE / "include/project.h").resolve())}
        assert any(loc.is_analysis for loc in expanded.line_map.values())
        user_lines = [loc for loc in expanded.line_map.values() if loc.file_path == str(source.resolve())]
        assert user_lines[-1].line_number == len(source.read_text().splitlines())


def test_project_and_compile_roots_override_models(tmp_path):
    local = tmp_path / "src"
    explicit = tmp_path / "explicit"
    compile_root = tmp_path / "compile"
    for root in (local, explicit, compile_root):
        root.mkdir()
        (root / "pthread.h").write_text("typedef long pthread_t;\n")
    resolver = IncludeResolver([str(explicit), str(compile_root)], str(tmp_path))
    assert resolver.resolve('"pthread.h"', str(local)) == str(local / "pthread.h")
    assert resolver.resolve("<pthread.h>", str(local)) == str(explicit / "pthread.h")
    (explicit / "pthread.h").unlink()
    assert resolver.resolve("<pthread.h>", str(local)) == str(compile_root / "pthread.h")
    (compile_root / "pthread.h").unlink()
    assert is_analysis_header(resolver.resolve("<pthread.h>", str(local)))
    assert resolver.resolve('"missing.h"', str(local)) is None
    assert resolver.resolve("<../../missing.h>", str(local)) is None
    # A project quote include does not unexpectedly acquire a system model.
    (local / "pthread.h").unlink()
    assert resolver.resolve('"pthread.h"', str(local)) is None
    assert resolver.resolve("<dlfcn.h>", str(local)) == str(Path(analysis_header_roots()[0]) / "dlfcn.h")


def test_models_do_not_receive_findings_but_project_provenance_survives(tmp_path):
    header = tmp_path / "project.h"
    header.write_text("void danger(char *p) { gets(p); }\n")
    source = '#include <pthread.h>\n#include "project.h"\nvoid run(char *p) { gets(p); }\n'
    result = CGullScanner().scan_text(source, file_path=str(tmp_path / "main.c"), quiet=True)
    assert result.issues
    assert all(not is_analysis_header(i.file_path) for i in result.issues)
    assert any(i.file_path == str(header) and i.line_number == 1 for i in result.issues)
    assert any(i.file_path == str(tmp_path / "main.c") and i.line_number == 3 for i in result.issues)


def test_parallel_matches_sequential_and_counts_only_project_sources(tmp_path):
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    config = ScanConfig.create(mode="tu", include_roots=[str(project / "include")])
    results = [CGullScanner(config=config).scan_path(str(project), jobs=n, quiet=True) for n in (1, 2)]
    def snapshot(result):
        return (
            sorted((s.file_path, s.parse_tier) for s in result.file_summaries),
            sorted((i.file_path, i.line_number, i.rule_id, i.message) for i in result.issues),
        )
    assert snapshot(results[0]) == snapshot(results[1])
    for result in results:
        assert result.scanned_files_count == 6
        assert result.files_discovered == 6
        assert all(s.parse_tier == "pcpp+pycparser" for s in result.file_summaries)
        assert all(not is_analysis_header(i.file_path) for i in result.issues)


@pytest.mark.parametrize("root", analysis_header_roots())
def test_explicit_model_targets_are_not_scanned_as_orphan_headers(root):
    result = CGullScanner(config=ScanConfig.create(mode="tu")).scan_path(root, quiet=True)
    assert result.scanned_files_count == 0
    assert result.files_discovered == 0
    assert not result.issues


def test_model_findings_are_filtered_even_with_cached_expansion(tmp_path, monkeypatch):
    import cgull.analysis_headers as models
    import cgull.includes as includes

    model_root = tmp_path / "models"
    model_root.mkdir()
    (model_root / "unsafe.h").write_text(
        '#ifndef MODEL_H\n#define MODEL_H\nvoid modeled(char *p) { gets(p); }\n#endif\n'
    )
    def roots():
        return (str(model_root),)
    monkeypatch.setattr(models, "analysis_header_roots", roots)
    monkeypatch.setattr(includes, "analysis_header_roots", roots)
    source = '#include <unsafe.h>\nvoid user(char *p) { gets(p); }\n'
    HEADER_CACHE.clear()
    for _ in range(2):
        result = CGullScanner().scan_text(source, file_path=str(tmp_path / "main.c"), quiet=True)
        assert any(i.rule_id == "CGULL-001" for i in result.issues)
        assert all(i.file_path == str(tmp_path / "main.c") for i in result.issues)
        assert all(i.line_number == 2 for i in result.issues)
    HEADER_CACHE.clear()
