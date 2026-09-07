import io
import json
import math

from cgull import (
    AnalysisEngine,
    CGullScanner,
    ConfigProfile,
    Issue,
    ScanConfig,
    Severity,
)
from cgull.reporter import ReportGenerator
from cgull.telemetry import ProgressIndicator, ScanTelemetry, telemetry_for


def _scanner() -> CGullScanner:
    return CGullScanner(
        config=ScanConfig.create(rules=[], engine_mode=AnalysisEngine.REGEX)
    )


def _issue(*, impact=Severity.HIGH, file_path="shared.h") -> Issue:
    return Issue(
        rule_id="CGULL-TEST",
        rule_name="Telemetry test",
        impact=impact,
        file_path=file_path,
        line_number=1,
        code_snippet="int x;",
        message="test finding",
    )


def test_throughput_math_is_deterministic_and_safe_for_tiny_scans():
    telemetry = ScanTelemetry(analyzed_lines=5000, elapsed_seconds=2.0)
    assert telemetry.throughput_kloc_per_sec == 2.5

    zero_time = ScanTelemetry(analyzed_lines=5000, elapsed_seconds=0.0)
    assert zero_time.throughput_kloc_per_sec == 0.0
    assert math.isfinite(zero_time.throughput_kloc_per_sec)

    empty = ScanTelemetry(analyzed_lines=0, elapsed_seconds=1.0)
    assert empty.throughput_kloc_per_sec == 0.0


def test_progress_indicator_renders_parent_aggregated_kloc_and_findings():
    stream = io.StringIO()
    progress = ProgressIndicator(stream=stream)
    progress.update_telemetry(
        ScanTelemetry(
            files_scanned=1,
            unique_source_lines=82400,
            analyzed_lines=82400,
            elapsed_seconds=5.6,
            findings_count=6,
        )
    )
    progress.update(1, 3, "src/a.c")

    rendered = stream.getvalue()
    assert "1/3 files" in rendered
    assert "82.4 KLOC" in rendered
    assert "14.7 KLOC/s" in rendered
    assert "6 issues" in rendered


def test_quiet_progress_emits_nothing():
    stream = io.StringIO()
    progress = ProgressIndicator(stream=stream, quiet=True)
    progress.update_telemetry(
        ScanTelemetry(analyzed_lines=1000, elapsed_seconds=1.0)
    )
    progress.update(1, 1, "a.c")
    progress.finish()
    assert stream.getvalue() == ""


def test_file_scan_counts_physical_lines_without_trailing_newline(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text("int x;\n\n// comment", encoding="utf-8")

    result = _scanner().scan_path(str(source), quiet=True)
    telemetry = telemetry_for(result)

    assert telemetry.files_scanned == 1
    assert telemetry.unique_source_lines == 3
    assert telemetry.analyzed_lines == 3
    assert result.total_lines_of_code == 3
    assert telemetry.elapsed_seconds > 0.0
    assert math.isfinite(telemetry.throughput_kloc_per_sec)


def test_duplicate_targets_are_counted_once(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text("int x;\nint y;\n", encoding="utf-8")

    result = _scanner().scan_path([str(source), str(source)], quiet=True)
    telemetry = telemetry_for(result)

    assert telemetry.files_scanned == 1
    assert telemetry.unique_source_lines == 2
    assert telemetry.analyzed_lines == 2


def test_ignored_file_does_not_contribute_lines(tmp_path):
    included = tmp_path / "included.c"
    ignored = tmp_path / "ignored.c"
    included.write_text("int x;\n", encoding="utf-8")
    ignored.write_text("int a;\nint b;\nint c;\n", encoding="utf-8")

    result = _scanner().scan_path(
        str(tmp_path),
        custom_ignore_patterns=["ignored.c"],
        quiet=True,
    )
    telemetry = telemetry_for(result)

    assert telemetry.files_scanned == 1
    assert telemetry.unique_source_lines == 1
    assert telemetry.analyzed_lines == 1


def test_live_files_discovered_matches_final_definition_with_ignored_file(tmp_path):
    included = tmp_path / "included.c"
    ignored = tmp_path / "ignored.c"
    included.write_text("int x;\n", encoding="utf-8")
    ignored.write_text("int y;\n", encoding="utf-8")

    snapshots = []
    progress_calls = []
    result = _scanner().scan_path(
        str(tmp_path),
        custom_ignore_patterns=["ignored.c"],
        progress_callback=lambda completed, total, current: progress_calls.append(
            (completed, total, current)
        ),
        telemetry_callback=snapshots.append,
        quiet=True,
    )

    assert progress_calls
    assert snapshots
    assert snapshots[-1].files_discovered == result.files_discovered == 2
    assert snapshots[-1].files_scanned == result.files_analyzed == 1


def test_plain_progress_callback_can_receive_telemetry_explicitly(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text("int x;\n", encoding="utf-8")
    progress_calls = []
    snapshots = []

    _scanner().scan_path(
        str(source),
        progress_callback=lambda completed, total, current: progress_calls.append(
            (completed, total, current)
        ),
        telemetry_callback=snapshots.append,
        quiet=True,
    )

    assert progress_calls[-1][0:2] == (1, 1)
    assert snapshots[-1].unique_source_lines == 1
    assert snapshots[-1].files_scanned == 1


def test_live_findings_use_final_filter_and_dedup_semantics():
    scanner = _scanner()
    scanner.severity_filter = {Severity.HIGH}
    scanner._begin_telemetry()
    snapshots = []
    scanner._telemetry_callback = snapshots.append

    high = _issue(impact=Severity.HIGH)
    low = _issue(impact=Severity.LOW, file_path="low.c")
    scanner._record_progress_result(
        loc=1,
        file_issues=[high, low],
        parser_status="regex",
        status="success",
        multiplier=1,
        completed=1,
        total=2,
        progress_callback=None,
        current_file="a.c",
    )
    scanner._record_progress_result(
        loc=1,
        file_issues=[high],
        parser_status="regex",
        status="success",
        multiplier=1,
        completed=2,
        total=2,
        progress_callback=None,
        current_file="b.c",
    )

    assert snapshots[-1].findings_count == 1
    assert snapshots[-1].files_scanned == 2


def test_profile_repetition_increases_analysis_volume(tmp_path):
    source = tmp_path / "profiles.c"
    source.write_text("int x;\nint y;\n", encoding="utf-8")
    profiles = [
        ConfigProfile(name="debug", flags={"DEBUG": None}),
        ConfigProfile(name="release", flags={}),
    ]

    result = _scanner().scan_path(str(source), profiles=profiles, quiet=True)
    telemetry = telemetry_for(result)

    assert telemetry.unique_source_lines == 2
    assert telemetry.analyzed_lines == 4
    assert telemetry.analyzed_lines > telemetry.unique_source_lines
    # This is the Windows regression: a scan completing within one timer tick
    # must still expose a positive canonical interval so consumers can safely
    # recompute the documented throughput formula.
    assert telemetry.elapsed_seconds > 0.0
    assert telemetry.to_dict()["elapsed_seconds"] > 0.0
    expected = (telemetry.analyzed_lines / 1000.0) / telemetry.elapsed_seconds
    assert telemetry.throughput_kloc_per_sec == expected


def test_parallel_scan_aggregates_in_parent(tmp_path):
    for index in range(3):
        (tmp_path / f"file_{index}.c").write_text(
            f"int value_{index};\n", encoding="utf-8"
        )

    result = _scanner().scan_path(str(tmp_path), jobs=2, quiet=True)
    telemetry = telemetry_for(result)

    assert telemetry.files_scanned == 3
    assert telemetry.unique_source_lines == 3
    assert telemetry.analyzed_lines == 3


def test_empty_scan_has_finite_zero_throughput(tmp_path):
    result = _scanner().scan_path(str(tmp_path), quiet=True)
    telemetry = telemetry_for(result)

    assert telemetry.files_scanned == 0
    assert telemetry.unique_source_lines == 0
    assert telemetry.analyzed_lines == 0
    assert telemetry.throughput_kloc_per_sec == 0.0
    assert math.isfinite(telemetry.throughput_kloc_per_sec)


def test_structured_and_human_reports_expose_scan_telemetry(tmp_path):
    source = tmp_path / "sample.c"
    source.write_text("int x;\n", encoding="utf-8")
    result = _scanner().scan_path(str(source), quiet=True)
    telemetry = telemetry_for(result)

    json_report = json.loads(ReportGenerator.to_json(result))
    assert json_report["scan"]["unique_source_lines"] == 1
    assert json_report["scan"]["analyzed_lines"] == 1
    assert json_report["scan"]["elapsed_seconds"] > 0.0

    sarif = json.loads(ReportGenerator.to_sarif(result))
    metrics = sarif["runs"][0]["invocations"][0]["properties"]["scanMetrics"]
    assert metrics["unique_source_lines"] == 1
    assert metrics["analyzed_lines"] == 1

    markdown = ReportGenerator.to_markdown(result)
    assert "## Scan Summary" in markdown
    assert "| Lines scanned | 1 |" in markdown

    text = ReportGenerator.to_terminal_text(result)
    assert "Scan complete" in text
    assert "Lines scanned:       1" in text
    assert f"Throughput:          {telemetry.throughput_kloc_per_sec:.2f} KLOC/s" in text
