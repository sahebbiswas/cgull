from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "report_pytest_timings.py"


def run_report(
    *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=SCRIPT.parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_report_orders_cases_and_limits_notices(tmp_path: Path) -> None:
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
    env = os.environ.copy()
    env["GITHUB_STEP_SUMMARY"] = str(summary)

    result = run_report(str(junit), "--top", "2", "--notices", "1", env=env)

    assert result.returncode == 0
    output = result.stdout
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


def test_report_missing_junit_is_nonfatal(tmp_path: Path) -> None:
    result = run_report(str(tmp_path / "missing.xml"))

    assert result.returncode == 0
    assert "Timing report not available" in result.stdout
