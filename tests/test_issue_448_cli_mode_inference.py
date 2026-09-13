import json
from types import SimpleNamespace

import cgull.cli as cli_module
from cgull.cli import _resolve_scan_mode_args, _scan_subparser, build_parser
from cgull.cli_mode import (
    MODE_SOURCE_COMMAND_LINE,
    MODE_SOURCE_CONFIGURATION,
    MODE_SOURCE_INFERRED,
    mode_aware_reporter,
    resolve_cli_scan_mode,
)
from cgull.models import ScanConfig, ScanMode


def test_target_matrix(tmp_path, monkeypatch):
    source_a = tmp_path / "a.c"
    source_b = tmp_path / "b.c"
    source_a.write_text("int a;\n", encoding="utf-8")
    source_b.write_text("int b;\n", encoding="utf-8")
    source_dir = tmp_path / "src"
    source_dir.mkdir()

    assert resolve_cli_scan_mode([str(source_a)], None, None) == (
        ScanMode.FILE,
        MODE_SOURCE_INFERRED,
    )
    assert resolve_cli_scan_mode([str(source_a), str(source_b)], None, None) == (
        ScanMode.FILE,
        MODE_SOURCE_INFERRED,
    )
    assert resolve_cli_scan_mode([str(source_dir)], None, None) == (
        ScanMode.TU,
        MODE_SOURCE_INFERRED,
    )
    assert resolve_cli_scan_mode([str(source_a), str(source_dir)], None, None) == (
        ScanMode.TU,
        MODE_SOURCE_INFERRED,
    )

    other_dir = tmp_path / "other"
    other_dir.mkdir()
    assert resolve_cli_scan_mode([str(source_dir), str(other_dir)], None, None) == (
        ScanMode.TU,
        MODE_SOURCE_INFERRED,
    )

    monkeypatch.chdir(tmp_path)
    assert resolve_cli_scan_mode([], None, None) == (
        ScanMode.TU,
        MODE_SOURCE_INFERRED,
    )


def test_precedence_cli_then_configuration_then_inference(tmp_path):
    source = tmp_path / "one.c"
    source.write_text("int one;\n", encoding="utf-8")

    assert resolve_cli_scan_mode([str(tmp_path)], "file", ScanMode.TU) == (
        ScanMode.FILE,
        MODE_SOURCE_COMMAND_LINE,
    )
    assert resolve_cli_scan_mode([str(tmp_path)], None, ScanMode.FILE) == (
        ScanMode.FILE,
        MODE_SOURCE_CONFIGURATION,
    )
    assert resolve_cli_scan_mode([str(source)], None, ScanMode.TU) == (
        ScanMode.TU,
        MODE_SOURCE_CONFIGURATION,
    )


def test_auto_discovered_config_beats_directory_inference(tmp_path):
    (tmp_path / ".cgull.toml").write_text('[scan]\nmode = "file"\n', encoding="utf-8")
    source_dir = tmp_path / "src"
    source_dir.mkdir()

    parser = build_parser()
    args = parser.parse_args(["scan", str(source_dir)])
    resolved, mode, source = _resolve_scan_mode_args(args)

    assert resolved.mode == "file"
    assert mode == ScanMode.FILE
    assert source == MODE_SOURCE_CONFIGURATION


def test_explicit_mode_beats_discovered_config(tmp_path):
    (tmp_path / ".cgull.toml").write_text('[scan]\nmode = "file"\n', encoding="utf-8")
    source = tmp_path / "one.c"
    source.write_text("int one;\n", encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args(["scan", str(source), "--mode", "tu"])
    resolved, mode, source = _resolve_scan_mode_args(args)

    assert resolved.mode == "tu"
    assert mode == ScanMode.TU
    assert source == MODE_SOURCE_COMMAND_LINE


def test_no_target_form_infers_tu(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    parser = build_parser()
    args = parser.parse_args(["scan"])

    resolved, mode, source = _resolve_scan_mode_args(args)

    assert resolved.target == ["."]
    assert resolved.mode == "tu"
    assert mode == ScanMode.TU
    assert source == MODE_SOURCE_INFERRED


def test_missing_target_keeps_existing_cli_error_path(tmp_path):
    missing = tmp_path / "missing.c"
    parser = build_parser()
    args = parser.parse_args(["scan", str(missing)])

    resolved, mode, source = _resolve_scan_mode_args(args)

    assert resolved.mode is None
    assert mode is None
    assert source is None


def test_resolution_is_independent_of_parallelism(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    parser = build_parser()

    sequential = parser.parse_args(["scan", str(source_dir), "--jobs", "1"])
    parallel = parser.parse_args(["scan", str(source_dir), "--jobs", "4"])

    assert _resolve_scan_mode_args(sequential)[1:] == _resolve_scan_mode_args(parallel)[1:]


def test_scan_reuses_discovered_config(tmp_path, monkeypatch):
    source = tmp_path / "one.c"
    source.write_text("int one;\n", encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(["scan", str(source)])

    original_load_config = cli_module._base.load_config
    loaded = []

    def counting_load_config(config_path=None, target_path=None):
        config = original_load_config(config_path=config_path, target_path=target_path)
        loaded.append(config)
        return config

    monkeypatch.setattr(cli_module._base, "load_config", counting_load_config)
    seen = {}

    def fake_handle_scan(internal):
        seen["config"] = cli_module._base.load_config(
            config_path=internal.config,
            target_path=cli_module._primary_target(internal),
        )
        return 0

    monkeypatch.setattr(cli_module, "_ORIGINAL_HANDLE_SCAN", fake_handle_scan)

    assert cli_module._run_original_scan(args) == 0
    assert len(loaded) == 1
    assert seen["config"] is loaded[0]


def test_library_default_remains_file_mode():
    assert ScanConfig.create().mode == ScanMode.FILE


def test_mode_help_describes_inference():
    parser = build_parser()
    help_text = " ".join(_scan_subparser(parser).format_help().split())
    assert "inferred from targets" in help_text
    assert "TU if any target is a directory" in help_text


def test_mode_metadata_is_visible_in_all_report_formats():
    class DummyReporter:
        @staticmethod
        def to_json(result):
            return json.dumps({"meta": {}, "issues": []})

        @staticmethod
        def to_sarif(result):
            return json.dumps({"runs": [{"invocations": [{"properties": {}}]}]})

        @staticmethod
        def to_markdown(result):
            return "# Report\n\n**Target**: `.`"

        @staticmethod
        def to_terminal_text(result):
            return "Report body\n\nScan complete\n  Files scanned:       1"

    result = SimpleNamespace()
    reporter = mode_aware_reporter(DummyReporter, ScanMode.TU, MODE_SOURCE_INFERRED)

    json_report = json.loads(reporter.to_json(result))
    assert json_report["meta"]["scan_mode"] == "tu"
    assert json_report["meta"]["scan_mode_source"] == MODE_SOURCE_INFERRED

    sarif = json.loads(reporter.to_sarif(result))
    props = sarif["runs"][0]["invocations"][0]["properties"]
    assert props["scanMode"] == "tu"
    assert props["scanModeSource"] == MODE_SOURCE_INFERRED

    markdown = reporter.to_markdown(result)
    assert "**Scan Mode**: `tu`" in markdown
    assert f"**Scan Mode Source**: `{MODE_SOURCE_INFERRED}`" in markdown

    terminal = reporter.to_terminal_text(result)
    assert "Scan mode:           tu" in terminal
    assert f"Mode source:         {MODE_SOURCE_INFERRED}" in terminal
    assert result.scan_mode == "tu"
    assert result.scan_mode_source == MODE_SOURCE_INFERRED


def test_mode_reporter_preserves_suppressed_capture():
    class EmptyReporter:
        @staticmethod
        def to_json(result):
            return ""

        @staticmethod
        def to_sarif(result):
            return ""

        @staticmethod
        def to_markdown(result):
            return ""

        @staticmethod
        def to_terminal_text(result):
            return ""

    result = SimpleNamespace()
    reporter = mode_aware_reporter(EmptyReporter, ScanMode.FILE, MODE_SOURCE_COMMAND_LINE)

    assert reporter.to_json(result) == ""
    assert reporter.to_sarif(result) == ""
    assert reporter.to_markdown(result) == ""
    assert reporter.to_terminal_text(result) == ""
    assert result.scan_mode == "file"
    assert result.scan_mode_source == MODE_SOURCE_COMMAND_LINE


def test_mode_reporter_delegates_unhandled_reporter_extensions():
    class ExtendedReporter:
        custom_value = "extended"

        @staticmethod
        def to_custom(result):
            return f"custom:{result}"

    reporter = mode_aware_reporter(ExtendedReporter, ScanMode.FILE, MODE_SOURCE_COMMAND_LINE)

    assert reporter.custom_value == "extended"
    assert reporter.to_custom("result") == "custom:result"


def test_mode_reporter_handles_null_sarif_invocations():
    class NullInvocationReporter:
        @staticmethod
        def to_sarif(result):
            return json.dumps({"runs": [{"invocations": None}]})

    reporter = mode_aware_reporter(
        NullInvocationReporter,
        ScanMode.TU,
        MODE_SOURCE_CONFIGURATION,
    )
    sarif = json.loads(reporter.to_sarif(SimpleNamespace()))

    props = sarif["runs"][0]["invocations"][0]["properties"]
    assert props["scanMode"] == "tu"
    assert props["scanModeSource"] == MODE_SOURCE_CONFIGURATION


def test_mode_reporter_preserves_crlf_terminal_summary():
    class CRLFReporter:
        @staticmethod
        def to_terminal_text(result):
            return "Report body\r\n\r\nScan complete\r\n  Files scanned:       1\r\n"

    reporter = mode_aware_reporter(CRLFReporter, ScanMode.TU, MODE_SOURCE_INFERRED)
    terminal = reporter.to_terminal_text(SimpleNamespace())

    assert "Scan complete\r\n  Scan mode:           tu\r\n" in terminal
    assert f"  Mode source:         {MODE_SOURCE_INFERRED}\r\n" in terminal
    assert not terminal.startswith("Selected scan mode:")
