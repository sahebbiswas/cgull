"""Regression coverage for issue #403 preprocessor diagnostic leakage."""

from io import StringIO
import sys

import pytest


pcpp = pytest.importorskip("pcpp")

from cgull.ast_analyzer import CASTParser
from cgull.ast_analyzer.pcpp_diagnostics import install_pcpp_diagnostic_suppression
from cgull.engine import _emit_error
from cgull.logging_config import _ProgressSafeStderr, configure_logging
from cgull.telemetry import ProgressIndicator


class TTYStringIO(StringIO):
    """In-memory stream that models an interactive stderr terminal."""

    def isatty(self):
        return True


def test_pcpp_error_is_consumed_without_raw_terminal_output(capsys):
    """An active #error must retain pcpp failure state without writing stderr."""

    install_pcpp_diagnostic_suppression()
    preprocessor = pcpp.Preprocessor()
    preprocessor.parse(
        "\n" * 23
        + "#if 1\n"
        + '#error "unsupported configuration"\n'
        + "#endif\n"
        + "int value;\n",
        "actual/source/config.c",
    )
    output = StringIO()
    preprocessor.write(output)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert "int value;" in output.getvalue()
    assert preprocessor.return_code == 1


def test_pcpp_warning_is_consumed_without_raw_terminal_output(capsys):
    install_pcpp_diagnostic_suppression()
    preprocessor = pcpp.Preprocessor()
    preprocessor.parse(
        '#warning "configuration is deprecated"\nint value;\n',
        "actual/source/config.c",
    )
    output = StringIO()
    preprocessor.write(output)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert "int value;" in output.getvalue()
    assert preprocessor.return_code == 0


def test_cast_parser_active_error_does_not_leak_synthetic_location(capsys):
    """The real parser path must not expose pcpp's <input>:N diagnostic."""

    source = (
        "\n" * 17
        + "#if 1\n"
        + '#error "unsupported configuration"\n'
        + "#endif\n"
        + "int configured_value(void) { return 7; }\n"
    )

    parser = CASTParser()
    context = parser.parse(source)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert "<input>" not in captured.out + captured.err
    assert "unsupported configuration" not in captured.out + captured.err
    assert context is not None


def test_analysis_error_clears_and_redraws_live_progress(monkeypatch):
    """Structured analysis errors must not leave a stale progress line behind."""

    terminal = TTYStringIO()
    monkeypatch.setattr(sys, "stderr", terminal)
    configure_logging()

    progress = ProgressIndicator()
    progress.update(1, 2, "first.c")
    _emit_error(
        "offsetof.c",
        "CoverageDegradedError",
        "AST preprocessing/layout precision degraded: offsetof(...) remained unexpanded",
        quiet=False,
        progress_active=True,
    )
    progress.update(2, 2, "offsetof.c")
    progress.finish()

    rendered = terminal.getvalue()
    assert "CoverageDegradedError" in rendered
    assert "offsetof" in rendered
    # The diagnostic must be preceded by an explicit erase of the current
    # carriage-return progress line instead of being appended to it.
    error_offset = rendered.index("[ERROR] Analysis failed")
    before_error = rendered[:error_offset]
    assert "\r" in before_error
    assert "\r " in before_error
    assert not before_error.endswith("files)\n")
    # Progress continues after the diagnostic and is finally erased cleanly.
    assert rendered.count("\rScanning [") >= 3
    assert rendered.endswith("\r")


def test_progress_safe_stderr_passes_redirected_output_through_plainly():
    redirected = StringIO()
    stream = _ProgressSafeStderr(redirected)

    stream.write("\rScanning [████] 50% (1/2 files)")
    before = redirected.getvalue()
    stream.write("diagnostic\n")

    rendered = redirected.getvalue()
    assert rendered == before + "diagnostic\n"
    assert "\r " not in rendered[len(before):]


def test_progress_safe_stderr_write_returns_input_length_on_coordinated_write():
    terminal = TTYStringIO()
    stream = _ProgressSafeStderr(terminal)
    stream.write("\rScanning [████] 50% (1/2 files)")

    diagnostic = "diagnostic\n"
    assert stream.write(diagnostic) == len(diagnostic)


def test_progress_safe_stderr_does_not_overwrite_partial_line_diagnostic():
    terminal = TTYStringIO()
    stream = _ProgressSafeStderr(terminal)
    stream.write("\rScanning [████] 50% (1/2 files)")

    diagnostic = "partial diagnostic"
    assert stream.write(diagnostic) == len(diagnostic)

    rendered = terminal.getvalue()
    assert rendered.endswith(diagnostic)
    assert not rendered.endswith("\rScanning [████] 50% (1/2 files)")


def test_progress_safe_stderr_preserves_consecutive_partial_chunks():
    terminal = TTYStringIO()
    stream = _ProgressSafeStderr(terminal)
    stream.write("\rScanning [████] 50% (1/2 files)")

    first = "partial diagnostic: "
    second = "continued"
    assert stream.write(first) == len(first)
    assert stream.write(second) == len(second)

    rendered = terminal.getvalue()
    assert rendered.endswith(first + second)
    assert rendered.count(first) == 1
    assert rendered.count(second) == 1