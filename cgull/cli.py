"""CLI facade adding safe-fix support on top of the established CLI."""

from __future__ import annotations

import argparse
import contextlib
import io
from typing import Optional

from . import cli_base as _base
from .fixes import FixResult, apply_safe_fixes
from .models import FixType


_ORIGINAL_BUILD_PARSER = _base.build_parser
_ORIGINAL_HANDLE_SCAN = _base.handle_scan
_ORIGINAL_REPORTER = _base.ReportGenerator


def _scan_subparser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices["scan"]
    raise RuntimeError("scan subparser not found")


def build_parser() -> argparse.ArgumentParser:
    parser = _ORIGINAL_BUILD_PARSER()
    scan_parser = _scan_subparser(parser)
    scan_parser.add_argument(
        "--fix",
        action="store_true",
        help="Preview mechanically safe SAFE_FIX replacements (does not modify files)",
    )
    scan_parser.add_argument(
        "--write",
        action="store_true",
        help="With --fix, write SAFE_FIX replacements to source files and re-scan",
    )
    return parser


def _run_scan_and_capture(args, *, suppress_output: bool):
    captured = {"result": None}

    class CapturingReporter:
        @staticmethod
        def _capture(method_name, result):
            captured["result"] = result
            if suppress_output:
                return ""
            return getattr(_ORIGINAL_REPORTER, method_name)(result)

        @staticmethod
        def to_json(result):
            return CapturingReporter._capture("to_json", result)

        @staticmethod
        def to_sarif(result):
            return CapturingReporter._capture("to_sarif", result)

        @staticmethod
        def to_markdown(result):
            return CapturingReporter._capture("to_markdown", result)

        @staticmethod
        def to_terminal_text(result):
            return CapturingReporter._capture("to_terminal_text", result)

    internal = argparse.Namespace(**vars(args))
    if suppress_output:
        internal.output = None
        internal.quiet = True
        internal.update_baseline = None
        internal.fail_on = None
        internal.fail_on_high = False
        internal.fail_on_error = False
        internal.warn_on_fallback = False

    previous = _base.ReportGenerator
    _base.ReportGenerator = CapturingReporter
    try:
        if suppress_output:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = _ORIGINAL_HANDLE_SCAN(internal)
        else:
            rc = _ORIGINAL_HANDLE_SCAN(internal)
    finally:
        _base.ReportGenerator = previous

    return rc, captured["result"]


def _print_fix_result(fix_result: FixResult, *, write: bool, remaining: Optional[int] = None) -> None:
    for diff in fix_result.diffs:
        if diff:
            _base.print(diff, end="" if diff.endswith("\n") else "\n")
    for conflict in fix_result.conflicts:
        _base.print(
            f"Warning: skipped fix at {conflict.file_path}:{conflict.line_number}: {conflict.reason}",
            file=_base.sys.stderr,
        )

    verb = "Applied" if write else "Would apply"
    summary = (
        f"{verb} {fix_result.replacements} SAFE_FIX replacement(s) across "
        f"{fix_result.files_changed} file(s); skipped {len(fix_result.conflicts)} conflict(s)."
    )
    if remaining is not None:
        summary += f" {remaining} issue(s) remain after re-scan."
    _base.print(summary)


def handle_scan(args) -> int:
    if getattr(args, "write", False) and not getattr(args, "fix", False):
        _base.print("Error: --write requires --fix.", file=_base.sys.stderr)
        return 2
    if not getattr(args, "fix", False):
        return _ORIGINAL_HANDLE_SCAN(args)

    if not getattr(args, "write", False):
        rc, result = _run_scan_and_capture(args, suppress_output=False)
        if result is None:
            return rc
        fix_result = apply_safe_fixes(result.issues, write=False)
        _print_fix_result(fix_result, write=False)
        return rc

    rc, initial = _run_scan_and_capture(args, suppress_output=True)
    if initial is None:
        return rc

    fix_result = apply_safe_fixes(initial.issues, write=True)
    rc, rescanned = _run_scan_and_capture(args, suppress_output=False)
    remaining = rescanned.total_issues_count if rescanned is not None else None
    _print_fix_result(fix_result, write=True, remaining=remaining)
    return rc


# The original ``main`` resolves these functions from its module globals.
_base.build_parser = build_parser
_base.handle_scan = handle_scan


def main() -> int:
    return _base.main()


# Re-export established CLI helpers for compatibility with direct imports.
handle_flags = _base.handle_flags
handle_rules = _base.handle_rules
print = _base.print
