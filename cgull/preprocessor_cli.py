"""CLI reporting for symbolic preprocessor analysis."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import sys
from typing import Iterable

from .config import load_config
from .ignore import CGullIgnoreFilter
from .preprocessor import parse_conditional_directives
from .preprocessor.branch_analysis import (
    BranchAnalysis,
    BranchStatus,
    analyze_conditional_tree,
)


_SOURCE_EXTENSIONS = frozenset(
    {".c", ".h", ".i", ".ii", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}
)
_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class PreprocessorFileResult:
    path: str
    analyses: tuple[BranchAnalysis, ...]
    diagnostics: tuple[object, ...]

    @property
    def has_errors(self) -> bool:
        return bool(self.diagnostics)


def _location_dict(location) -> dict[str, int]:
    return {
        "line": location.line,
        "column": location.column,
        "offset": location.offset,
    }


def _analysis_dict(analysis: BranchAnalysis) -> dict[str, object]:
    directive = analysis.branch.directive
    source_range = directive.source_range
    return {
        "kind": directive.kind,
        "status": analysis.status.value,
        "reachability": analysis.reachability.value,
        "location": _location_dict(source_range.start),
        "range": {
            "start": _location_dict(source_range.start),
            "end": _location_dict(source_range.end),
        },
        "original_condition": analysis.original_condition,
        "simplified_condition": analysis.simplified_condition_text,
        "context_condition": analysis.context_text,
        "effective_condition": analysis.effective_condition_text,
        "contextual_simplification": analysis.contextual_simplification,
    }


def _diagnostic_dict(diagnostic) -> dict[str, object]:
    source_range = diagnostic.source_range
    return {
        "code": diagnostic.code,
        "message": diagnostic.message,
        "location": _location_dict(source_range.start),
        "range": {
            "start": _location_dict(source_range.start),
            "end": _location_dict(source_range.end),
        },
    }


def _display_path(path: str, target: str) -> str:
    absolute = os.path.abspath(path)
    target_absolute = os.path.abspath(target)
    if os.path.isdir(target_absolute):
        relative = os.path.relpath(absolute, target_absolute)
        return relative.replace(os.sep, "/")
    return os.path.normpath(target).replace(os.sep, "/")


def _discover_files(
    target: str,
    *,
    ignore_file: str | None,
    ignore_patterns: Iterable[str],
    config_path: str | None,
) -> tuple[list[str], str | None]:
    if not os.path.exists(target):
        return [], f"Target path '{target}' does not exist."

    config = load_config(config_path=config_path, target_path=target)
    if config.error:
        return [], config.error

    patterns = list(ignore_patterns)
    patterns.extend(config.get_resolved_exclude_paths(target))
    target_absolute = os.path.abspath(target)
    base_dir = target_absolute if os.path.isdir(target_absolute) else (os.path.dirname(target_absolute) or ".")
    filter_obj = CGullIgnoreFilter(base_dir=base_dir, custom_patterns=patterns)
    if ignore_file:
        if not os.path.exists(ignore_file):
            return [], f"Ignore file '{ignore_file}' does not exist."
        filter_obj.load_from_file(ignore_file)

    if os.path.isfile(target_absolute):
        extension = os.path.splitext(target_absolute)[1].lower()
        if extension not in _SOURCE_EXTENSIONS:
            return [], f"Target '{target}' is not a supported C/C++ source file."
        if filter_obj.should_ignore(target_absolute):
            return [], None
        return [target_absolute], None

    files: list[str] = []
    for root, dirs, names in os.walk(target_absolute):
        dirs[:] = sorted(
            d
            for d in dirs
            if not filter_obj.should_prune_dir(os.path.join(root, d))
        )
        for name in sorted(names):
            path = os.path.join(root, name)
            if os.path.splitext(name)[1].lower() not in _SOURCE_EXTENSIONS:
                continue
            if not filter_obj.should_ignore(path):
                files.append(path)
    files.sort()
    return files, None


def _analyze_file(path: str, target: str) -> PreprocessorFileResult:
    with open(path, "r", encoding="utf-8", errors="strict") as stream:
        source = stream.read()
    tree = parse_conditional_directives(source)
    analyses = tuple(
        sorted(
            analyze_conditional_tree(tree),
            key=lambda item: item.branch.directive.source_range.start.offset,
        )
    )
    return PreprocessorFileResult(
        path=_display_path(path, target),
        analyses=analyses,
        diagnostics=tree.diagnostics,
    )


def _summary(results: Iterable[PreprocessorFileResult]) -> dict[str, int]:
    counts = {
        "files": 0,
        "entries": 0,
        "dead": 0,
        "redundant": 0,
        "simplified": 0,
        "unchanged": 0,
        "diagnostics": 0,
    }
    for result in results:
        counts["files"] += 1
        counts["diagnostics"] += len(result.diagnostics)
        for analysis in result.analyses:
            counts["entries"] += 1
            counts[analysis.status.value] += 1
    return counts


def _json_report(
    target: str,
    results: list[PreprocessorFileResult],
    *,
    verbose: bool,
    io_errors: list[dict[str, object]],
) -> str:
    files = []
    for result in results:
        entries = [
            _analysis_dict(analysis)
            for analysis in result.analyses
            if verbose or analysis.status != BranchStatus.UNCHANGED
        ]
        files.append(
            {
                "path": result.path,
                "entries": entries,
                "diagnostics": [_diagnostic_dict(item) for item in result.diagnostics],
            }
        )
    return json.dumps(
        {
            "schema_version": _SCHEMA_VERSION,
            "target": os.path.normpath(target).replace(os.sep, "/"),
            "files": files,
            "errors": io_errors,
            "summary": _summary(results),
        },
        indent=2,
        sort_keys=False,
    )


def _human_lines(result: PreprocessorFileResult, *, verbose: bool) -> list[str]:
    lines: list[str] = []
    for analysis in result.analyses:
        if not verbose and analysis.status == BranchStatus.UNCHANGED:
            continue
        directive = analysis.branch.directive
        location = directive.source_range.start
        condition = f" {directive.condition_text}" if directive.condition_text else ""
        lines.append(
            f"{result.path}:{location.line}:{location.column} "
            f"[{analysis.status.value.upper()}] #{directive.kind}{condition}"
        )
        if analysis.status == BranchStatus.SIMPLIFIED:
            lines.append(f"  simplified: {analysis.simplified_condition_text}")
        if analysis.status in (BranchStatus.DEAD, BranchStatus.REDUNDANT):
            lines.append(f"  context: {analysis.context_text}")
        if analysis.status == BranchStatus.DEAD:
            lines.append(f"  effective: {analysis.effective_condition_text}")
        if verbose:
            lines.append(f"  reachability: {analysis.reachability.value}")

    for diagnostic in result.diagnostics:
        location = diagnostic.source_range.start
        lines.append(
            f"{result.path}:{location.line}:{location.column} "
            f"[ERROR {diagnostic.code}] {diagnostic.message}"
        )
    return lines


def handle_preprocessor(args) -> int:
    """Run the supported CPRE-style symbolic preprocessor report."""

    target = getattr(args, "target", ".")
    verbose = bool(getattr(args, "preprocessor_verbose", False))
    as_json = bool(getattr(args, "json", False))
    files, discovery_error = _discover_files(
        target,
        ignore_file=getattr(args, "ignore_file", None),
        ignore_patterns=getattr(args, "ignore_pattern", []) or [],
        config_path=getattr(args, "config", None),
    )
    if discovery_error:
        if as_json:
            print(
                json.dumps(
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "target": os.path.normpath(target).replace(os.sep, "/"),
                        "files": [],
                        "errors": [{"path": target, "message": discovery_error}],
                        "summary": {
                            "files": 0,
                            "entries": 0,
                            "dead": 0,
                            "redundant": 0,
                            "simplified": 0,
                            "unchanged": 0,
                            "diagnostics": 0,
                        },
                    },
                    indent=2,
                )
            )
        else:
            print(f"Error: {discovery_error}", file=sys.stderr)
        return 2

    results: list[PreprocessorFileResult] = []
    io_errors: list[dict[str, object]] = []
    for path in files:
        try:
            results.append(_analyze_file(path, target))
        except UnicodeDecodeError as exc:
            io_errors.append(
                {
                    "path": _display_path(path, target),
                    "message": f"invalid UTF-8 at byte {exc.start}",
                }
            )
        except OSError as exc:
            io_errors.append(
                {"path": _display_path(path, target), "message": str(exc)}
            )

    if as_json:
        print(_json_report(target, results, verbose=verbose, io_errors=io_errors))
    else:
        output: list[str] = []
        for result in results:
            output.extend(_human_lines(result, verbose=verbose))
        if output:
            print("\n".join(output))
        elif not io_errors:
            print("No semantically interesting preprocessor conditions found.")
        for error in io_errors:
            print(f"Error: {error['path']}: {error['message']}", file=sys.stderr)

    has_structure_errors = any(result.has_errors for result in results)
    return 2 if io_errors or has_structure_errors else 0
