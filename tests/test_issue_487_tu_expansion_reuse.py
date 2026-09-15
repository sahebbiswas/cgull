"""Regression coverage for issue #487 scan-local TU expansion reuse."""

from collections import Counter
import os

import pytest

from cgull import CGullScanner
from cgull.includes import TUIncludeExpander
from cgull.models import AnalysisEngine, ConfigProfile, ScanConfig, ScanMode
from cgull.project_analysis import prepare_units, profile_key


def _count_expansions(monkeypatch):
    calls = []
    original_expand = TUIncludeExpander.expand

    def counted_expand(self, source_code, source_path="source.c"):
        calls.append((os.path.realpath(source_path), profile_key(self.defined_syms)))
        return original_expand(self, source_code, source_path=source_path)

    monkeypatch.setattr(TUIncludeExpander, "expand", counted_expand)
    return calls


@pytest.mark.parametrize("engine_mode", [AnalysisEngine.HYBRID, AnalysisEngine.REGEX])
def test_single_tu_directory_expands_source_once(tmp_path, monkeypatch, engine_mode):
    shared = tmp_path / "shared.h"
    shared.write_text("int shared_value(void);\n", encoding="utf-8")
    source = tmp_path / "main.c"
    source.write_text(
        '#include "shared.h"\nint main(void) { return 0; }\n',
        encoding="utf-8",
    )

    calls = _count_expansions(monkeypatch)
    config = ScanConfig.create(mode=ScanMode.TU, engine_mode=engine_mode)
    result = CGullScanner(config=config).scan_path(str(tmp_path), quiet=True)

    assert not result.scan_errors
    assert {os.path.basename(summary.file_path) for summary in result.file_summaries} == {"main.c"}
    counts = Counter(calls)
    assert counts[(os.path.realpath(source), profile_key(config.defined_syms))] == 1
    assert sum(counts.values()) == 1


def test_multi_profile_tu_reuses_prepared_sources_and_orphans(tmp_path, monkeypatch):
    optional = tmp_path / "optional.h"
    optional.write_text("int optional_value(void);\n", encoding="utf-8")
    orphan = tmp_path / "orphan.h"
    orphan.write_text("int orphan_value(void);\n", encoding="utf-8")
    source = tmp_path / "main.c"
    source.write_text(
        '#ifdef USE_OPTIONAL\n#include "optional.h"\n#endif\nint main(void) { return 0; }\n',
        encoding="utf-8",
    )
    profiles = [
        ConfigProfile(name="without_optional", flags={}),
        ConfigProfile(name="with_optional", flags={"USE_OPTIONAL": None}),
    ]

    calls = _count_expansions(monkeypatch)
    config = ScanConfig.create(mode=ScanMode.TU)
    result = CGullScanner(config=config).scan_path(
        str(tmp_path),
        profiles=profiles,
        quiet=True,
    )

    assert not result.scan_errors
    scanned = {os.path.basename(summary.file_path) for summary in result.file_summaries}
    assert scanned == {"main.c", "orphan.h"}

    counts = Counter(calls)
    for profile in profiles:
        key = profile_key(profile.flags)
        assert counts[(os.path.realpath(source), key)] == 1
        assert counts[(os.path.realpath(orphan), key)] == 1
    assert not any(path == os.path.realpath(optional) for path, _ in calls)
    assert sum(counts.values()) == 4


def test_prepare_units_reexpands_when_include_configuration_changes(tmp_path, monkeypatch):
    first_include = tmp_path / "first"
    second_include = tmp_path / "second"
    first_include.mkdir()
    second_include.mkdir()
    (first_include / "value.h").write_text("int first_value(void);\n", encoding="utf-8")
    (second_include / "value.h").write_text("int second_value(void);\n", encoding="utf-8")
    source = tmp_path / "main.c"
    source.write_text("#include <value.h>\n", encoding="utf-8")

    calls = _count_expansions(monkeypatch)
    first_config = ScanConfig.create(
        mode=ScanMode.TU,
        include_roots=[str(first_include)],
    )
    second_config = ScanConfig.create(
        mode=ScanMode.TU,
        include_roots=[str(second_include)],
    )

    prepared, diagnostics = prepare_units([str(source)], lambda _: first_config)
    assert not diagnostics
    first_unit = prepared[str(source)][profile_key(first_config.defined_syms)]
    assert "first_value" in first_unit.expanded.expanded_text

    prepared, diagnostics = prepare_units(
        [str(source)],
        lambda _: second_config,
        prepared_units=prepared,
    )
    assert not diagnostics
    second_unit = prepared[str(source)][profile_key(second_config.defined_syms)]
    assert "second_value" in second_unit.expanded.expanded_text
    assert first_unit.preparation_key != second_unit.preparation_key
    assert Counter(calls)[(os.path.realpath(source), profile_key({}))] == 2