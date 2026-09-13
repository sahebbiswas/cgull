#!/usr/bin/env python3
"""Report the slowest pytest cases from a JUnit XML result.

The CI matrix uses this for the Windows/Python 3.11 lane so slow-test data is
visible in both the job log and the GitHub Actions job summary.  GitHub notice
annotations make the individual slow cases queryable without downloading logs.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def _github_escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _test_name(case: ET.Element) -> str:
    classname = case.attrib.get("classname", "")
    name = case.attrib.get("name", "<unnamed>")
    return f"{classname}::{name}" if classname else name


def _slowest_cases(path: Path, limit: int) -> list[tuple[float, str]]:
    root = ET.parse(path).getroot()
    cases: list[tuple[float, str]] = []
    for case in root.iter("testcase"):
        try:
            duration = float(case.attrib.get("time", "0") or 0)
        except ValueError:
            duration = 0.0
        cases.append((duration, _test_name(case)))
    cases.sort(key=lambda item: item[0], reverse=True)
    return cases[:limit]


def _markdown(cases: list[tuple[float, str]]) -> str:
    lines = [
        "### Slowest pytest cases",
        "",
        "| Rank | Test | Seconds |",
        "| ---: | --- | ---: |",
    ]
    for rank, (duration, name) in enumerate(cases, 1):
        safe_name = name.replace("|", "\\|")
        lines.append(f"| {rank} | `{safe_name}` | {duration:.3f} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit_xml", type=Path)
    parser.add_argument("--top", type=int, default=25)
    args = parser.parse_args(argv)

    if args.top < 1:
        parser.error("--top must be at least 1")
    if not args.junit_xml.exists():
        print(f"Timing report not available: {args.junit_xml}")
        return 0

    try:
        cases = _slowest_cases(args.junit_xml, args.top)
    except (ET.ParseError, OSError) as exc:
        print(f"Unable to read pytest timing report: {exc}", file=sys.stderr)
        return 0

    if not cases:
        print("Timing report contains no pytest test cases")
        return 0

    report = _markdown(cases)
    print(report, end="")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write(report)

    for duration, name in cases:
        message = _github_escape(f"{name} took {duration:.3f}s")
        print(f"::notice title=Slow pytest case::{message}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
