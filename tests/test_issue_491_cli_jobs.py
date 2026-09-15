import json
from types import SimpleNamespace
from unittest.mock import patch

from cgull.cli import _resolve_scan_jobs_args, build_parser
from cgull.cli_jobs import (
    AUTO_JOBS_CAP,
    JOBS_SOURCE_AUTOMATIC,
    JOBS_SOURCE_EXPLICIT,
    JOBS_SOURCE_SEQUENTIAL_DEFAULT,
    jobs_aware_reporter,
    resolve_cli_jobs,
)
from cgull.cli_mode import MODE_SOURCE_INFERRED, mode_aware_reporter
from cgull.models import ScanMode


def test_parser_keeps_legacy_default_value_while_tracking_omission(tmp_path):
    parser = build_parser()
    args = parser.parse_args(["scan", str(tmp_path)])

    # Existing parser consumers still see the historical numeric default.
    assert args.jobs == 1

    resolved, jobs, source = _resolve_scan_jobs_args(args)
    assert jobs == min(AUTO_JOBS_CAP, __import__("os").cpu_count() or 1)
    assert resolved.jobs == jobs
    assert source == JOBS_SOURCE_AUTOMATIC


def test_omitted_jobs_auto_parallelize_directories_with_a_bounded_cap(tmp_path):
    with patch("cgull.cli_jobs.os.cpu_count", return_value=128):
        jobs, source = resolve_cli_jobs([str(tmp_path)], None)

    assert jobs == AUTO_JOBS_CAP == 8
    assert source == JOBS_SOURCE_AUTOMATIC


def test_omitted_jobs_keep_file_only_targets_sequential(tmp_path):
    first = tmp_path / "first.c"
    second = tmp_path / "second.c"
    first.write_text("int first(void) { return 1; }\n", encoding="utf-8")
    second.write_text("int second(void) { return 2; }\n", encoding="utf-8")

    jobs, source = resolve_cli_jobs([str(first)], None)
    assert (jobs, source) == (1, JOBS_SOURCE_SEQUENTIAL_DEFAULT)

    jobs, source = resolve_cli_jobs([str(first), str(second)], None)
    assert (jobs, source) == (1, JOBS_SOURCE_SEQUENTIAL_DEFAULT)


def test_explicit_job_controls_are_preserved(tmp_path):
    for requested in (1, 2, 7):
        jobs, source = resolve_cli_jobs([str(tmp_path)], requested)
        assert jobs == requested
        assert source == JOBS_SOURCE_EXPLICIT

    with patch("cgull.cli_jobs.os.cpu_count", return_value=64):
        jobs, source = resolve_cli_jobs([str(tmp_path)], 0)
    assert jobs == AUTO_JOBS_CAP
    assert source == JOBS_SOURCE_AUTOMATIC


def test_parser_distinguishes_explicit_one_from_omitted_one(tmp_path):
    parser = build_parser()

    omitted = parser.parse_args(["scan", str(tmp_path)])
    explicit = parser.parse_args(["scan", str(tmp_path), "--jobs", "1"])

    with patch("cgull.cli_jobs.os.cpu_count", return_value=4):
        omitted_resolved = _resolve_scan_jobs_args(omitted)
        explicit_resolved = _resolve_scan_jobs_args(explicit)

    assert omitted_resolved[1:] == (4, JOBS_SOURCE_AUTOMATIC)
    assert explicit_resolved[1:] == (1, JOBS_SOURCE_EXPLICIT)


def test_effective_jobs_metadata_is_capped_to_actual_scan_work():
    class Delegate:
        @staticmethod
        def to_json(_result):
            return json.dumps({"meta": {}, "summary": {}})

        @staticmethod
        def to_sarif(_result):
            return json.dumps({"runs": [{"invocations": [{"properties": {}}]}]})

        @staticmethod
        def to_markdown(_result):
            return "# Report\n\nBody"

        @staticmethod
        def to_terminal_text(_result):
            return "Scan complete\n  Files scanned:       3\n"

    result = SimpleNamespace(files_analyzed=3, files_failed=0, scanned_files_count=3)
    reporter = jobs_aware_reporter(Delegate, AUTO_JOBS_CAP, JOBS_SOURCE_AUTOMATIC)

    json_report = json.loads(reporter.to_json(result))
    assert json_report["meta"]["jobs"] == 3
    assert json_report["meta"]["jobs_source"] == JOBS_SOURCE_AUTOMATIC

    sarif_report = json.loads(reporter.to_sarif(result))
    properties = sarif_report["runs"][0]["invocations"][0]["properties"]
    assert properties["jobs"] == 3
    assert properties["jobsSource"] == JOBS_SOURCE_AUTOMATIC

    markdown = reporter.to_markdown(result)
    assert "**Workers**: `3`" in markdown
    assert "**Worker Source**: `automatic`" in markdown

    terminal = reporter.to_terminal_text(result)
    assert "Workers:             3" in terminal
    assert "Worker source:       automatic" in terminal


def test_worker_and_mode_metadata_compose_without_overwriting_each_other():
    class Delegate:
        @staticmethod
        def to_json(_result):
            return json.dumps({"meta": {}})

    result = SimpleNamespace(files_analyzed=2, files_failed=0, scanned_files_count=2)
    mode_reporter = mode_aware_reporter(Delegate, ScanMode.TU, MODE_SOURCE_INFERRED)
    reporter = jobs_aware_reporter(mode_reporter, AUTO_JOBS_CAP, JOBS_SOURCE_AUTOMATIC)

    data = json.loads(reporter.to_json(result))
    assert data["meta"] == {
        "scan_mode": "tu",
        "scan_mode_source": MODE_SOURCE_INFERRED,
        "jobs": 2,
        "jobs_source": JOBS_SOURCE_AUTOMATIC,
    }
