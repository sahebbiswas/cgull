"""Persistent content-addressed result cache (issue #545)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cgull import __version__
from cgull.engine import CGullScanner, _scan_file_content
from cgull.models import AnalysisEngine, Confidence, Issue, Severity, ScanConfig
from cgull.result_cache import (
    CACHE_SCHEMA_VERSION,
    ResultCache,
    compute_cache_key,
    config_fingerprint,
    default_cache_dir,
    is_cache_disabled,
    rebind_cached_result,
    resolve_cache_dir,
)


SOURCE_GETS = """\
#include <stdio.h>
void sink(char *p) {
    gets(p);
}
"""

SOURCE_SAFE = """\
#include <stdio.h>
void sink(char *p) {
    fgets(p, 16, stdin);
}
"""


@pytest.fixture
def cache_root(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    cache = root / ".cgull" / "cache"
    monkeypatch.delenv("CGULL_NO_CACHE", raising=False)
    monkeypatch.delenv("CGULL_CACHE_DIR", raising=False)
    return root, cache


def test_default_cache_dir_under_project(tmp_path):
    assert default_cache_dir(str(tmp_path)) == str(tmp_path / ".cgull" / "cache")


def test_default_cache_dir_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert default_cache_dir(None) == str(tmp_path / "xdg" / "cgull")


def test_resolve_opt_in_and_disable(tmp_path, monkeypatch):
    monkeypatch.delenv("CGULL_NO_CACHE", raising=False)
    monkeypatch.delenv("CGULL_CACHE_DIR", raising=False)
    assert resolve_cache_dir(None, project_state_root=str(tmp_path)) is None
    assert resolve_cache_dir("", project_state_root=str(tmp_path)) == str(
        tmp_path / ".cgull" / "cache"
    )
    explicit = resolve_cache_dir(str(tmp_path / "custom"), project_state_root=str(tmp_path))
    assert explicit == str((tmp_path / "custom").resolve())
    monkeypatch.setenv("CGULL_CACHE_DIR", str(tmp_path / "env-cache"))
    assert resolve_cache_dir(None, project_state_root=str(tmp_path)).endswith("env-cache")
    assert resolve_cache_dir("", project_state_root=str(tmp_path), no_cache_flag=True) is None
    monkeypatch.setenv("CGULL_NO_CACHE", "1")
    assert is_cache_disabled()
    assert resolve_cache_dir("", project_state_root=str(tmp_path)) is None


def test_corrupt_entry_is_miss(tmp_path):
    cache = ResultCache(str(tmp_path / "cache"))
    key = "a" * 64
    path = Path(cache._entry_path(key))
    path.parent.mkdir(parents=True)
    path.write_text("{not-json", encoding="utf-8")
    assert cache.get(key) is None
    assert cache.misses == 1


def test_atomic_roundtrip(tmp_path):
    cache = ResultCache(str(tmp_path / "cache"))
    config = ScanConfig.create(engine_mode=AnalysisEngine.REGEX)
    key = compute_cache_key(
        source_text="int x;",
        expanded_text="int x;",
        config=config,
        cgull_version=__version__,
        file_path="a.c",
    )
    assert key is not None
    issue = Issue(
        rule_id="CGULL-001",
        rule_name="Banned",
        impact=Severity.HIGH,
        file_path="a.c",
        line_number=1,
        message="gets",
        fingerprint="fp",
        confidence=Confidence.FULL,
    )
    cache.put(
        key,
        issues=[issue],
        lines_of_code=1,
        parser_status="regex",
        parse_tier="regex-fallback",
        status="success",
        confidence="limited",
        cgull_version=__version__,
    )
    loaded = cache.get(key)
    assert loaded is not None
    assert loaded.issues[0].rule_id == "CGULL-001"
    assert loaded.issues[0].message == "gets"
    assert loaded.issues[0].confidence == Confidence.FULL
    assert cache.hits == 1
    assert (tmp_path / "cache" / f"v{CACHE_SCHEMA_VERSION}").exists()


def test_version_change_invalidates(tmp_path):
    cache = ResultCache(str(tmp_path / "cache"))
    config = ScanConfig.create(engine_mode=AnalysisEngine.REGEX)
    key_a = compute_cache_key(
        source_text="int x;",
        expanded_text="int x;",
        config=config,
        cgull_version="0.0.1",
        file_path="a.c",
    )
    key_b = compute_cache_key(
        source_text="int x;",
        expanded_text="int x;",
        config=config,
        cgull_version="0.0.2",
        file_path="a.c",
    )
    assert key_a != key_b
    cache.put(
        key_a,
        issues=[],
        lines_of_code=1,
        parser_status="regex",
        parse_tier="regex-fallback",
        status="success",
        confidence="limited",
        cgull_version="0.0.1",
    )
    assert cache.get(key_b) is None


def test_config_change_invalidates_key():
    source = "int x;"
    key_a = compute_cache_key(
        source_text=source,
        expanded_text=source,
        config=ScanConfig.create(engine_mode=AnalysisEngine.REGEX),
        cgull_version=__version__,
        file_path="a.c",
    )
    key_b = compute_cache_key(
        source_text=source,
        expanded_text=source,
        config=ScanConfig.create(engine_mode=AnalysisEngine.HYBRID),
        cgull_version=__version__,
        file_path="a.c",
    )
    assert key_a != key_b


def test_file_path_included_in_cache_key():
    source = "int x;"
    config = ScanConfig.create(engine_mode=AnalysisEngine.REGEX)
    key_a = compute_cache_key(
        source_text=source,
        expanded_text=source,
        config=config,
        cgull_version=__version__,
        file_path="/tmp/one.c",
    )
    key_b = compute_cache_key(
        source_text=source,
        expanded_text=source,
        config=config,
        cgull_version=__version__,
        file_path="/tmp/two.c",
    )
    assert key_a is not None and key_b is not None
    assert key_a != key_b


def test_rebind_rewrites_paths_and_fingerprints():
    from cgull.result_cache import CachedFileResult
    from cgull.utils import compute_issue_fingerprint

    issue = Issue(
        rule_id="CGULL-001",
        rule_name="Banned",
        impact=Severity.HIGH,
        file_path="old.c",
        line_number=3,
        code_snippet="gets(p);",
        message="gets",
        fingerprint=compute_issue_fingerprint("CGULL-001", "old.c", "gets(p);"),
    )
    result = CachedFileResult(
        issues=(issue,),
        lines_of_code=1,
        parser_status="regex",
        parse_tier="regex-fallback",
        status="success",
        confidence="FULL",
        parse_attempts=(),
    )
    rebound = rebind_cached_result(result, "new.c")
    assert rebound.issues[0].file_path == "new.c"
    assert rebound.issues[0].fingerprint == compute_issue_fingerprint(
        "CGULL-001", "new.c", "gets(p);"
    )


def test_identical_content_different_paths_do_not_share_hit(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    config = ScanConfig.create(engine_mode=AnalysisEngine.HYBRID, cache_dir=str(cache_dir))
    calls = _count_parse_calls(monkeypatch)

    first = _scan_file_content(SOURCE_GETS, "alpha.c", config=config)
    second = _scan_file_content(SOURCE_GETS, "beta.c", config=config)

    assert len(calls) == 2
    assert all(i.file_path == "alpha.c" for i in first[0])
    assert all(i.file_path == "beta.c" for i in second[0])


def test_corrupt_confidence_is_miss(tmp_path):
    cache = ResultCache(str(tmp_path / "cache"))
    config = ScanConfig.create(engine_mode=AnalysisEngine.REGEX)
    key = compute_cache_key(
        source_text="int x;",
        expanded_text="int x;",
        config=config,
        cgull_version=__version__,
        file_path="a.c",
    )
    assert key is not None
    issue = Issue(
        rule_id="CGULL-001",
        rule_name="Banned",
        impact=Severity.HIGH,
        file_path="a.c",
        line_number=1,
        message="gets",
        fingerprint="fp",
    )
    cache.put(
        key,
        issues=[issue],
        lines_of_code=1,
        parser_status="regex",
        parse_tier="regex-fallback",
        status="success",
        confidence="limited",
        cgull_version=__version__,
    )
    path = Path(cache._entry_path(key))
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["issues"][0]["confidence"] = "not-a-real-confidence"
    path.write_text(json.dumps(raw), encoding="utf-8")

    assert cache.get(key) is None
    assert cache.misses == 1


def test_custom_unregistered_rule_does_not_crash_fingerprint():
    from cgull.rules.base import BaseRule

    class UnregisteredCustom(BaseRule):
        rule_id = "CUSTOM-CACHE-1"
        name = "Custom cache rule"
        impact = Severity.LOW

        def scan_line(self, file_path, line_number, line_content, **kwargs):
            return []

    config = ScanConfig.create(
        rules=[UnregisteredCustom()],
        engine_mode=AnalysisEngine.REGEX,
    )
    with pytest.raises(ValueError):
        config.to_dict()

    fp = config_fingerprint(config)
    assert fp["enabled_rules"][0]["rule_id"] == "CUSTOM-CACHE-1"

    key = compute_cache_key(
        source_text="int x;",
        expanded_text="int x;",
        config=config,
        cgull_version=__version__,
        file_path="a.c",
    )
    assert key is not None


def test_custom_rule_scan_with_cache_does_not_crash(tmp_path):
    from cgull.rules.base import BaseRule

    class UnregisteredCustom(BaseRule):
        rule_id = "CUSTOM-CACHE-2"
        name = "Custom cache rule"
        impact = Severity.LOW

        def scan_line(self, file_path, line_number, line_content, **kwargs):
            return []

    cache_dir = tmp_path / "cache"
    config = ScanConfig.create(
        rules=[UnregisteredCustom()],
        engine_mode=AnalysisEngine.REGEX,
        cache_dir=str(cache_dir),
    )
    first = _scan_file_content("int x;\n", "sample.c", config=config)
    second = _scan_file_content("int x;\n", "sample.c", config=config)
    assert first[5] == "success"
    assert second[5] == "success"


def test_put_mkstemp_oserror_is_best_effort(tmp_path, monkeypatch):
    cache = ResultCache(str(tmp_path / "cache"))
    config = ScanConfig.create(engine_mode=AnalysisEngine.REGEX)
    key = compute_cache_key(
        source_text="int x;",
        expanded_text="int x;",
        config=config,
        cgull_version=__version__,
        file_path="a.c",
    )
    assert key is not None

    def boom(*args, **kwargs):
        raise OSError("read-only cache")

    monkeypatch.setattr("cgull.result_cache.tempfile.mkstemp", boom)
    cache.put(
        key,
        issues=[],
        lines_of_code=1,
        parser_status="regex",
        parse_tier="regex-fallback",
        status="success",
        confidence="limited",
        cgull_version=__version__,
    )
    assert cache.stores == 0
    assert cache.get(key) is None


def _count_parse_calls(monkeypatch):
    from cgull.ast_analyzer import CASTParser

    calls: list[int] = []
    real = CASTParser.parse

    def wrapped(self, *args, **kwargs):
        calls.append(1)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(CASTParser, "parse", wrapped)
    return calls


def test_cache_hit_skips_reanalysis(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    config = ScanConfig.create(engine_mode=AnalysisEngine.HYBRID, cache_dir=str(cache_dir))
    calls = _count_parse_calls(monkeypatch)

    first = _scan_file_content(SOURCE_GETS, "sample.c", config=config)
    second = _scan_file_content(SOURCE_GETS, "sample.c", config=config)

    assert len(calls) == 1
    assert [i.rule_id for i in first[0]] == [i.rule_id for i in second[0]]
    assert [i.fingerprint or i.message for i in first[0]] == [
        i.fingerprint or i.message for i in second[0]
    ]
    # Second call should be a hit (findings present for gets).
    assert any(i.rule_id == "CGULL-001" for i in second[0])
    assert (cache_dir / f"v{CACHE_SCHEMA_VERSION}").exists()


def test_cache_miss_on_content_change_recomputes(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    config = ScanConfig.create(engine_mode=AnalysisEngine.HYBRID, cache_dir=str(cache_dir))
    calls = _count_parse_calls(monkeypatch)

    _scan_file_content(SOURCE_GETS, "sample.c", config=config)
    changed = _scan_file_content(SOURCE_SAFE, "sample.c", config=config)

    assert len(calls) == 2
    assert not any(i.rule_id == "CGULL-001" for i in changed[0])


def test_no_cache_dir_always_reanalyzes(tmp_path, monkeypatch):
    config = ScanConfig.create(engine_mode=AnalysisEngine.HYBRID, cache_dir=None)
    calls = _count_parse_calls(monkeypatch)
    _scan_file_content(SOURCE_GETS, "sample.c", config=config)
    _scan_file_content(SOURCE_GETS, "sample.c", config=config)
    assert len(calls) == 2


def test_scanner_scan_path_uses_cache(tmp_path, monkeypatch):
    src = tmp_path / "sample.c"
    src.write_text(SOURCE_GETS, encoding="utf-8")
    cache_dir = tmp_path / "cache"
    config = ScanConfig.create(engine_mode=AnalysisEngine.HYBRID, cache_dir=str(cache_dir))
    calls = _count_parse_calls(monkeypatch)

    scanner = CGullScanner(config=config)
    first = scanner.scan_path(str(src), jobs=1, quiet=True)
    second = scanner.scan_path(str(src), jobs=1, quiet=True)

    assert len(calls) == 1
    assert first.total_issues_count == second.total_issues_count
    assert {i.fingerprint for i in first.issues} == {i.fingerprint for i in second.issues}


def test_cli_help_documents_cache_flags():
    from cgull.cli import build_parser

    parser = build_parser()
    scan_actions = []
    for action in parser._subparsers._group_actions:
        for choice in action.choices.values():
            if getattr(choice, "prog", "").endswith("scan") or "scan" in getattr(choice, "prog", ""):
                scan_actions.extend(choice._actions)
    dests = {a.dest for a in scan_actions}
    options = []
    for a in scan_actions:
        options.extend(a.option_strings)
    assert "--cache-dir" in options
    assert "--cache-path" in options
    assert "--no-cache" in options
    assert "cache_dir" in dests
    assert "cache_path" in dests
    assert "no_cache" in dests


def test_cli_cache_dir_does_not_steal_scan_target(tmp_path):
    from cgull.cli import build_parser

    src = tmp_path / "file.c"
    src.write_text("int x;\n", encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(["scan", "--cache-dir", str(src)])
    assert args.cache_dir is True
    assert args.cache_path is None
    assert args.target == [str(src)]

    args2 = parser.parse_args(["scan", "--cache-path", str(tmp_path / "cache"), str(src)])
    assert args2.cache_path == str(tmp_path / "cache")
    assert args2.target == [str(src)]
