"""Regression coverage for issue #403 preprocessor diagnostic leakage."""

import pytest


pcpp = pytest.importorskip("pcpp")

from cgull.ast_analyzer import CASTParser
from cgull.ast_analyzer.pcpp_diagnostics import install_pcpp_diagnostic_suppression


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

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert preprocessor.return_code == 1


def test_pcpp_warning_is_consumed_without_raw_terminal_output(capsys):
    install_pcpp_diagnostic_suppression()
    preprocessor = pcpp.Preprocessor()
    preprocessor.parse(
        '#warning "configuration is deprecated"\nint value;\n',
        "actual/source/config.c",
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
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
