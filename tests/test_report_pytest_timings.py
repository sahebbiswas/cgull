from __future__ import annotations

from pathlib import Path

from scripts.report_pytest_timings import main


def test_report_orders_cases_and_limits_notices(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    junit = tmp_path / "pytest-junit.xml"
    junit.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" tests="3">
    <testcase classname="tests.test_fast" name="test_fast" time="0.125" />
    <testcase classname="tests.test_slow" name="test_slow" time="3.500" />
    <testcase classname="tests.test_mid" name="test_mid" time="1.250" />
  </testsuite>
</testsuites>
""",
        encoding="utf-8",
    )
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    assert main([str(junit), "--top", "2", "--notices", "1"]) == 0

    output = capsys.readouterr().out
    assert output.index("tests.test_slow::test_slow") < output.index(
        "tests.test_mid::test_mid"
    )
    assert "tests.test_fast::test_fast" not in output
    assert output.count("::notice title=Slow pytest case::") == 1
    assert "tests.test_slow::test_slow took 3.500s" in output

    summary_text = summary.read_text(encoding="utf-8")
    assert "tests.test_slow::test_slow" in summary_text
    assert "tests.test_mid::test_mid" in summary_text
    assert "tests.test_fast::test_fast" not in summary_text


def test_report_missing_junit_is_nonfatal(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "missing.xml"

    assert main([str(missing)]) == 0

    assert "Timing report not available" in capsys.readouterr().out
