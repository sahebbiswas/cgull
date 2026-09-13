import json
from types import SimpleNamespace

from cgull.cli import _resolve_scan_mode_args
from cgull.cli_mode import MODE_SOURCE_INFERRED, mode_aware_reporter
from cgull.models import ScanMode


def test_none_target_defaults_to_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    args = SimpleNamespace(target=None, config=None, mode=None)

    resolved, mode, source = _resolve_scan_mode_args(args)

    assert resolved.target == ["."]
    assert mode == ScanMode.TU
    assert source == MODE_SOURCE_INFERRED


def test_json_metadata_repairs_non_mapping_meta():
    class Reporter:
        @staticmethod
        def to_json(result):
            return json.dumps({"meta": None, "issues": []})

    wrapped = mode_aware_reporter(Reporter, ScanMode.FILE, MODE_SOURCE_INFERRED)
    data = json.loads(wrapped.to_json(SimpleNamespace()))

    assert data["meta"]["scan_mode"] == "file"
    assert data["meta"]["scan_mode_source"] == MODE_SOURCE_INFERRED


def test_json_metadata_ignores_non_mapping_top_level():
    class Reporter:
        @staticmethod
        def to_json(result):
            return json.dumps(["unexpected"])

    wrapped = mode_aware_reporter(Reporter, ScanMode.FILE, MODE_SOURCE_INFERRED)

    assert json.loads(wrapped.to_json(SimpleNamespace())) == ["unexpected"]


def test_sarif_metadata_ignores_non_mapping_top_level_and_run():
    class TopLevelReporter:
        @staticmethod
        def to_sarif(result):
            return json.dumps(["unexpected"])

    class RunReporter:
        @staticmethod
        def to_sarif(result):
            return json.dumps({"runs": [None]})

    top_level = mode_aware_reporter(TopLevelReporter, ScanMode.TU, MODE_SOURCE_INFERRED)
    bad_run = mode_aware_reporter(RunReporter, ScanMode.TU, MODE_SOURCE_INFERRED)

    assert json.loads(top_level.to_sarif(SimpleNamespace())) == ["unexpected"]
    assert json.loads(bad_run.to_sarif(SimpleNamespace())) == {"runs": [None]}
