"""CLI facade adding safe-fix and preprocessor support to the established CLI."""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
from typing import List, Optional, Tuple

from . import cli_base as _base
from .compile_database import (
    CompileCommandIncludeDatabase,
    CompileDatabaseCGullScanner,
    activate_compile_command_database,
    load_compile_commands_data,
)
from .fixes import FixResult, apply_safe_fixes
from .preprocessor_cli import handle_preprocessor
from .telemetry import ProgressIndicator as _TelemetryProgressIndicator


_ORIGINAL_BUILD_PARSER = _base.build_parser
_ORIGINAL_HANDLE_SCAN = _base.handle_scan
_ORIGINAL_REPORTER = _base.ReportGenerator

# Public symbols historically exposed from cgull.cli. Keep these aliases so
# callers/tests can monkey-patch cgull.cli without knowing about the internal
# compatibility module used by the fix facade.
CGullScanner = CompileDatabaseCGullScanner
ProgressIndicator = _TelemetryProgressIndicator
ReportGenerator = _base.ReportGenerator


def _subparsers_action(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    raise RuntimeError("subparsers action not found")


def _scan_subparser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    return _subparsers_action(parser).choices["scan"]


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

    subparsers = _subparsers_action(parser)
    preprocessor_parser = subparsers.add_parser(
        "preprocessor",
        help="Analyze conditional preprocessor structure and Boolean semantics",
    )
    preprocessor_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="C/C++ source file or directory to analyze (default: current directory)",
    )
    preprocessor_parser.add_argument(
        "--verbose",
        dest="preprocessor_verbose",
        action="store_true",
        help="Include unchanged structural entries",
    )
    preprocessor_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit stable structured JSON instead of human-readable output",
    )
    preprocessor_parser.add_argument(
        "-c",
        "--config",
        help="Path to .cgull.toml or pyproject.toml configuration file",
    )
    preprocessor_parser.add_argument("--ignore-file", help="Path to .cgullignore file")
    preprocessor_parser.add_argument(
        "--ignore-pattern",
        action="append",
        default=[],
        help="Pattern to ignore (can be specified multiple times)",
    )
    return parser


def _sync_base_symbols() -> None:
    """Propagate public monkey-patch points into the established CLI module."""
    _base.CGullScanner = CGullScanner
    _base.ProgressIndicator = ProgressIndicator
    _base.ReportGenerator = ReportGenerator


def _primary_target(args) -> str:
    targets = getattr(args, "target", ".")
    if isinstance(targets, str):
        targets = [targets]
    if len(targets) == 1:
        return targets[0]
    if targets:
        try:
            return os.path.commonpath([os.path.abspath(target) for target in targets])
        except ValueError:
            pass
    return "."


def _compile_database_for_args(
    args,
) -> Tuple[Optional[CompileCommandIncludeDatabase], Optional[List[object]], Optional[str]]:
    """Resolve and parse the compilation database once for both include and macro views."""
    explicit_path = getattr(args, "compile_commands", None)
    compile_commands_path = explicit_path

    if not compile_commands_path:
        from .ast_analyzer import find_compile_commands

        primary_target = _primary_target(args)
        config = _base.load_config(
            config_path=getattr(args, "config", None),
            target_path=primary_target,
        )
        if not config.error:
            compile_commands_path = find_compile_commands(
                primary_target,
                config_dir=config.config_dir,
            )

    if not compile_commands_path or not os.path.exists(compile_commands_path):
        return None, None, None

    try:
        data = load_compile_commands_data(compile_commands_path)
        database = CompileCommandIncludeDatabase.from_data(
            data,
            database_dir=os.path.dirname(os.path.realpath(compile_commands_path)),
        )
    except Exception:
        # cli_base owns the established error policy for explicit and
        # auto-discovered compile databases, including macro ingestion. Let it
        # report/ignore the parse failure exactly as before.
        return None, None, None

    for warning in database.warnings:
        _base.print(f"Warning: {warning}", file=_base.sys.stderr)
    return database, data, os.path.realpath(compile_commands_path)


@contextlib.contextmanager
def _shared_compile_commands_parse(data: Optional[List[object]], path: Optional[str]):
    """Feed cli_base the already-loaded JSON instead of reopening the same database."""
    if data is None or path is None:
        yield
        return

    from . import ast_analyzer

    original_parse = ast_analyzer.parse_compile_commands

    def parse_compile_commands_once(filepath_or_data):
        if isinstance(filepath_or_data, (str, os.PathLike)):
            if os.path.realpath(os.fspath(filepath_or_data)) == path:
                return original_parse(data)
        return original_parse(filepath_or_data)

    ast_analyzer.parse_compile_commands = parse_compile_commands_once
    try:
        yield
    finally:
        ast_analyzer.parse_compile_commands = original_parse


def _run_original_scan(args):
    database, data, compile_commands_path = _compile_database_for_args(args)
    with activate_compile_command_database(database), _shared_compile_commands_parse(data, compile_commands_path):
        _sync_base_symbols()
        return _ORIGINAL_HANDLE_SCAN(args)


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

    _sync_base_symbols()
    previous = _base.ReportGenerator
    _base.ReportGenerator = CapturingReporter
    try:
        if suppress_output:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = _run_original_scan(internal)
        else:
            rc = _run_original_scan(internal)
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
        return _run_original_scan(args)

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


def _is_preprocessor_command(argv: List[str]) -> bool:
    """Recognize preprocessor after supported global logging options."""
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "preprocessor":
            return True
        if token == "--":
            return False
        if token in ("--log-level", "--log-file"):
            index += 2
            continue
        if token.startswith("--log-level=") or token.startswith("--log-file="):
            index += 1
            continue
        if token == "--verbose" or (token.startswith("-") and len(token) > 1 and set(token[1:]) == {"v"}):
            index += 1
            continue
        return False
    return False


def main(argv: Optional[List[str]] = None) -> int:
    """Run the CLI while preserving the established injectable argv API."""
    _base.build_parser = build_parser
    _base.handle_scan = handle_scan
    _sync_base_symbols()

    effective_argv = list(sys.argv[1:] if argv is None else argv)
    if _is_preprocessor_command(effective_argv):
        parser = build_parser()
        args = parser.parse_args(effective_argv)
        from .logging_config import configure_logging

        try:
            configure_logging(
                verbose_count=getattr(args, "verbose", 0) or 0,
                log_level_str=getattr(args, "log_level", None),
                log_file=getattr(args, "log_file", None),
            )
        except OSError as exc:
            _base.print(f"Error configuring logging: {exc}", file=_base.sys.stderr)
            return 1
        return handle_preprocessor(args)

    return _base.main(argv)


handle_flags = _base.handle_flags
handle_rules = _base.handle_rules
handle_init_ignore = _base.handle_init_ignore
print = _base.print
