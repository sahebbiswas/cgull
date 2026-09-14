import io

from cgull import AnalysisEngine, CGullScanner, ScanConfig
from cgull.logging_config import _ProgressSafeStderr
from cgull.telemetry import ProgressIndicator


def _scanner() -> CGullScanner:
    return CGullScanner(
        config=ScanConfig.create(rules=[], engine_mode=AnalysisEngine.REGEX)
    )


class _DiscoveryRecorder:
    def __init__(self) -> None:
        self.discovery = []
        self.scan = []

    def __call__(self, completed: int, total: int, current_file: str) -> None:
        self.scan.append((completed, total, current_file))

    def discovery_update(self, found: int) -> None:
        self.discovery.append(found)


class _TTYStringIO(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_directory_discovery_reports_only_nonignored_scan_candidates(tmp_path):
    (tmp_path / "a.c").write_text("int a;\n", encoding="utf-8")
    (tmp_path / "b.h").write_text("int b;\n", encoding="utf-8")
    (tmp_path / "ignored.c").write_text("int ignored;\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not source\n", encoding="utf-8")

    recorder = _DiscoveryRecorder()
    result = _scanner().scan_path(
        str(tmp_path),
        custom_ignore_patterns=["ignored.c"],
        progress_callback=recorder,
        quiet=True,
    )

    assert recorder.discovery == [0, 1, 2]
    assert result.files_discovered == 3
    assert recorder.scan[-1][0:2] == (2, 2)


def test_legacy_progress_callback_needs_no_discovery_method(tmp_path):
    (tmp_path / "a.c").write_text("int a;\n", encoding="utf-8")
    calls = []

    _scanner().scan_path(
        str(tmp_path),
        progress_callback=lambda completed, total, current: calls.append(
            (completed, total, current)
        ),
        quiet=True,
    )

    assert calls[-1][0:2] == (1, 1)


def test_discovery_renderer_is_throttled_by_time_or_candidate_count(monkeypatch):
    moments = iter([10.0, 10.01, 10.02])
    monkeypatch.setattr("cgull.telemetry.time.monotonic", lambda: next(moments))

    stream = io.StringIO()
    progress = ProgressIndicator(stream=stream)
    progress.discovery_update(0)
    progress.discovery_update(1)
    progress.discovery_update(25)

    rendered = stream.getvalue()
    assert rendered.count("Discovering files...") == 2
    assert "Discovering files... 0 found" in rendered
    assert "Discovering files... 25 found" in rendered
    assert "Discovering files... 1 found" not in rendered


def test_discovery_transitions_in_place_to_scan_progress():
    stream = io.StringIO()
    progress = ProgressIndicator(stream=stream, bar_width=5)

    progress.discovery_update(0)
    progress.update(0, 2, "")

    rendered = stream.getvalue()
    assert "\rDiscovering files... 0 found" in rendered
    assert "\rScanning [" in rendered
    assert rendered.rfind("\rScanning [") > rendered.rfind("\rDiscovering files...")
    assert "\n" not in rendered


def test_quiet_mode_suppresses_discovery_and_scan_progress():
    stream = io.StringIO()
    progress = ProgressIndicator(stream=stream, quiet=True)

    progress.discovery_update(0)
    progress.discovery_update(25)
    progress.update(0, 1, "")
    progress.finish()

    assert stream.getvalue() == ""


def test_diagnostic_output_redraws_discovery_status_before_scan_transition():
    raw = _TTYStringIO()
    safe_stderr = _ProgressSafeStderr(raw)
    progress = ProgressIndicator(stream=safe_stderr, bar_width=5)

    progress.discovery_update(0)
    safe_stderr.write("warning during discovery\n")

    rendered = raw.getvalue()
    assert "warning during discovery\n" in rendered
    assert rendered.endswith("\rDiscovering files... 0 found")

    progress.update(0, 1, "")
    assert safe_stderr._progress_line.startswith("\rScanning [")
