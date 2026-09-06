from pathlib import Path

from benchmarks.diagnose_juliet_oracle import format_markdown, inspect_entry, main, run_diagnostic


def _write_flow54(root: Path, cwe_dir: str, name: str, sink_call: str) -> None:
    directory = root / "testcases" / cwe_dir / "s01"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(
        "void sample_54_bad(void) {\n"
        f"    {sink_call};\n"
        "}\n"
        "void sample_54_good(void) {\n"
        f"    {sink_call};\n"
        "}\n",
        encoding="utf-8",
    )


def test_inspect_entry_marks_split_sink_as_unownable_by_lexical_wrapper(tmp_path):
    path = tmp_path / "sample_54a.c"
    path.write_text(
        "void sample_54_bad(void) { sample_54b_badSink(data); }\n",
        encoding="utf-8",
    )
    result = inspect_entry(path, "CWE-134")
    assert result["has_external_sink_stage"] is True
    assert result["lexical_oracle_can_own_sink"] is False


def test_run_diagnostic_counts_both_target_cwes(tmp_path):
    _write_flow54(
        tmp_path,
        "CWE134_Uncontrolled_Format_String",
        "CWE134_Uncontrolled_Format_String__sample_54a.c",
        "sample_54b_badSink(data)",
    )
    _write_flow54(
        tmp_path,
        "CWE369_Divide_by_Zero",
        "CWE369_Divide_by_Zero__sample_54a.c",
        "sample_54b_badSink(data)",
    )
    report = run_diagnostic(tmp_path, per_cwe=1)
    assert report["totals"] == {
        "sampled": 2,
        "split_sink": 2,
        "lexical_oracle_can_own_sink": 0,
    }
    assert report["warnings"] == []
    rendered = format_markdown(report)
    assert "2/2" not in rendered
    assert "CWE-134: 1/1" in rendered
    assert "CWE-369: 1/1" in rendered


def test_partial_sample_is_warning_and_cli_remains_nonfatal(tmp_path, capsys):
    _write_flow54(
        tmp_path,
        "CWE134_Uncontrolled_Format_String",
        "CWE134_Uncontrolled_Format_String__sample_54a.c",
        "sample_54b_badSink(data)",
    )
    _write_flow54(
        tmp_path,
        "CWE369_Divide_by_Zero",
        "CWE369_Divide_by_Zero__sample_54a.c",
        "sample_54b_badSink(data)",
    )
    output = tmp_path / "diagnostic.md"

    assert main([str(tmp_path), "--per-cwe", "2", "--output", str(output)]) == 0
    rendered = output.read_text(encoding="utf-8")
    assert "## Sampling warnings" in rendered
    assert "CWE-134: requested 2 flow-54 entry files, found 1" in rendered
    assert "CWE-369: requested 2 flow-54 entry files, found 1" in rendered
    captured = capsys.readouterr()
    assert "warning: CWE-134: requested 2 flow-54 entry files, found 1" in captured.err
