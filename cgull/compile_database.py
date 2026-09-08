"""Compilation-database include context for translation-unit scanning.

This module intentionally leaves the existing ``parse_compile_commands`` macro
profile ingestion untouched.  It derives only include-search context and layers
that context onto the scanner per translation unit, so one compile command can
never change another translation unit's include roots.
"""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import os
from pathlib import Path
import shlex
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from .engine import _emit_error, _scan_file_worker
from .models import Confidence, ConfigProfile, ParseTier, ParserStatus, ScanConfig, ScanError
from .telemetry import CGullScanner as _TelemetryCGullScanner, _profile_multiplier


@dataclass(frozen=True)
class CompileCommandIncludeDatabase:
    """Canonical, ordered include roots keyed by translation-unit source file."""

    include_roots_by_file: Mapping[str, Tuple[str, ...]]
    warnings: Tuple[str, ...] = ()

    @classmethod
    def from_file(cls, path: Union[str, os.PathLike[str]]) -> "CompileCommandIncludeDatabase":
        import json

        db_path = Path(path)
        if not db_path.exists():
            raise FileNotFoundError(f"Compile commands file '{db_path}' does not exist.")
        with db_path.open("r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
        return cls.from_data(data, database_dir=str(db_path.resolve().parent))

    @classmethod
    def from_data(
        cls,
        data: Sequence[Any],
        *,
        database_dir: Optional[str] = None,
    ) -> "CompileCommandIncludeDatabase":
        if not isinstance(data, list):
            raise ValueError("compile_commands.json top-level JSON must be an array")

        base_dir = os.path.realpath(database_dir or os.getcwd())
        roots_by_file: Dict[str, Tuple[str, ...]] = {}
        warnings: List[str] = []

        for entry_index, entry in enumerate(data):
            if not isinstance(entry, dict):
                continue
            args = _entry_arguments(entry, entry_index, warnings)
            if args is None:
                continue

            raw_directory = str(entry.get("directory") or base_dir)
            if os.path.isabs(raw_directory):
                command_dir = os.path.realpath(raw_directory)
            else:
                command_dir = os.path.realpath(os.path.join(base_dir, raw_directory))

            raw_file = entry.get("file")
            if raw_file is None:
                warnings.append(
                    f"compile_commands entry {entry_index} has no 'file'; include context was ignored"
                )
                continue
            file_path = _canonical_path(str(raw_file), command_dir)

            ordinary_roots, system_roots = _parse_include_args(
                args,
                command_dir=command_dir,
                entry_label=str(raw_file),
                warnings=warnings,
            )
            roots = tuple(_dedupe_paths([*ordinary_roots, *system_roots]))

            existing = roots_by_file.get(file_path)
            if existing is None:
                roots_by_file[file_path] = roots
            elif existing != roots:
                warnings.append(
                    f"multiple compile commands for '{raw_file}' provide different include roots; "
                    "C-GULL uses the first entry deterministically"
                )

        return cls(include_roots_by_file=roots_by_file, warnings=tuple(_dedupe_strings(warnings)))

    def roots_for(self, file_path: str) -> Tuple[str, ...]:
        return self.include_roots_by_file.get(_canonical_path(file_path, os.getcwd()), ())


def _entry_arguments(
    entry: Mapping[str, Any],
    entry_index: int,
    warnings: List[str],
) -> Optional[List[str]]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list):
        return [str(arg) for arg in arguments]

    command = entry.get("command")
    if isinstance(command, str):
        try:
            return shlex.split(command, posix=True)
        except ValueError as exc:
            warnings.append(
                f"compile_commands entry {entry_index} command could not be shell-split ({exc}); "
                "include context was ignored"
            )
            return None
    return None


def _canonical_path(path: str, relative_to: str) -> str:
    raw = os.path.expanduser(path)
    if not os.path.isabs(raw):
        raw = os.path.join(relative_to, raw)
    return os.path.normcase(os.path.realpath(raw))


def _dedupe_paths(paths: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen: set[str] = set()
    for path in paths:
        canonical = os.path.normcase(os.path.realpath(path))
        if canonical in seen:
            continue
        seen.add(canonical)
        result.append(os.path.realpath(path))
    return result


def _dedupe_strings(values: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _resolve_root(value: str, command_dir: str) -> str:
    if os.path.isabs(value):
        return os.path.realpath(value)
    return os.path.realpath(os.path.join(command_dir, value))


def _parse_include_args(
    args: Sequence[str],
    *,
    command_dir: str,
    entry_label: str,
    warnings: List[str],
) -> Tuple[List[str], List[str]]:
    ordinary_roots: List[str] = []
    system_roots: List[str] = []
    index = 0

    while index < len(args):
        arg = args[index]

        if arg == "-I":
            if index + 1 < len(args):
                index += 1
                ordinary_roots.append(_resolve_root(args[index], command_dir))
            else:
                warnings.append(f"'{entry_label}': trailing -I has no path and was ignored")
        elif arg.startswith("-I") and len(arg) > 2:
            ordinary_roots.append(_resolve_root(arg[2:], command_dir))
        elif arg == "-isystem":
            if index + 1 < len(args):
                index += 1
                system_roots.append(_resolve_root(args[index], command_dir))
            else:
                warnings.append(f"'{entry_label}': trailing -isystem has no path and was ignored")
        elif arg.startswith("-isystem") and len(arg) > len("-isystem"):
            raw = arg[len("-isystem"):]
            if raw.startswith("="):
                raw = raw[1:]
            if raw:
                system_roots.append(_resolve_root(raw, command_dir))
        elif arg == "-iquote" or arg.startswith("-iquote"):
            warnings.append(
                f"'{entry_label}': -iquote is ignored because C-GULL's current include resolver "
                "cannot preserve quote-only search semantics"
            )
            if arg == "-iquote" and index + 1 < len(args):
                index += 1
        elif _is_unsupported_include_flag(arg):
            warnings.append(
                f"'{entry_label}': include-affecting compiler option '{arg}' is not modeled and was ignored"
            )
            if arg in {"-idirafter", "-iprefix", "-iwithprefix", "-iwithprefixbefore", "-isysroot", "-F"}:
                if index + 1 < len(args):
                    index += 1
        index += 1

    return _dedupe_paths(ordinary_roots), _dedupe_paths(system_roots)


def _is_unsupported_include_flag(arg: str) -> bool:
    exact = {
        "-idirafter",
        "-iprefix",
        "-iwithprefix",
        "-iwithprefixbefore",
        "-isysroot",
        "-nostdinc",
        "-nostdinc++",
        "-F",
    }
    prefixes = (
        "--sysroot=",
        "-idirafter=",
        "-iprefix=",
        "-iwithprefix=",
        "-iwithprefixbefore=",
        "-isysroot=",
        "-F",
    )
    return arg in exact or any(arg.startswith(prefix) and arg != prefix for prefix in prefixes)


_ACTIVE_DATABASE: ContextVar[Optional[CompileCommandIncludeDatabase]] = ContextVar(
    "cgull_compile_command_include_database",
    default=None,
)


@contextmanager
def activate_compile_command_database(
    database: Optional[CompileCommandIncludeDatabase],
) -> Iterator[None]:
    """Make a compile database available to scanner instances created in this context."""

    token = _ACTIVE_DATABASE.set(database)
    try:
        yield
    finally:
        _ACTIVE_DATABASE.reset(token)


class CompileDatabaseCGullScanner(_TelemetryCGullScanner):
    """Telemetry scanner that adds compile-command include roots per source TU."""

    def __init__(self, *args, compile_database: Optional[CompileCommandIncludeDatabase] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.compile_database = compile_database if compile_database is not None else _ACTIVE_DATABASE.get()

    def _config_for_file(self, config: ScanConfig, file_path: str) -> ScanConfig:
        database = self.compile_database
        if database is None:
            return config
        compile_roots = database.roots_for(file_path)
        if not compile_roots:
            return config

        # Explicit project configuration / .cgullincludes wins. Compile-database
        # paths supplement it and are canonical-deduplicated without reordering.
        merged_roots = _dedupe_paths([*config.include_roots, *compile_roots])
        if merged_roots == list(config.include_roots):
            return config

        import copy

        per_file_config = copy.copy(config)
        per_file_config.include_roots = merged_roots
        return per_file_config

    def _scan_single_file_content(self, file_path, content, config=None, **kwargs):
        if config is not None:
            config = self._config_for_file(config, file_path)
        return super()._scan_single_file_content(file_path, content, config=config, **kwargs)

    def _scan_files_parallel(
        self,
        files_to_scan: List[str],
        jobs: int,
        config: ScanConfig,
        progress_callback=None,
        quiet: bool = False,
        progress_active: bool = False,
        profiles: Optional[List[ConfigProfile]] = None,
    ):
        import pickle
        import time

        try:
            pickle.dumps(config)
            if profiles:
                pickle.dumps(profiles)
        except Exception as exc:
            raise ValueError(
                f"Configuration/profiles cannot be serialized for parallel worker processes: {exc}. "
                "Ensure all custom rules and profiles are picklable or use jobs=1 for sequential scanning."
            ) from exc

        results = []
        total_files = len(files_to_scan)
        multiplier = _profile_multiplier(profiles)
        completed_count = 0
        pool = ProcessPoolExecutor(max_workers=jobs)
        futures = {}
        try:
            futures = {
                pool.submit(
                    _scan_file_worker,
                    file_path,
                    self._config_for_file(config, file_path),
                    profiles,
                    quiet,
                    progress_active,
                ): file_path
                for file_path in files_to_scan
            }
            for future in as_completed(futures):
                file_path = futures[future]
                completed_count += 1
                try:
                    file_issues, loc, duration_ms, parser_status, parse_tier, status, confidence, scan_err = future.result()
                    result = (
                        file_path,
                        file_issues,
                        loc,
                        duration_ms,
                        parser_status,
                        parse_tier,
                        status,
                        confidence,
                        scan_err,
                    )
                except Exception as exc:
                    scan_err = ScanError(
                        file_path=file_path,
                        error_type=type(exc).__name__,
                        message=str(exc) or f"Worker execution failed for {file_path}",
                    )
                    _emit_error(
                        file_path,
                        scan_err.error_type,
                        scan_err.message,
                        quiet=quiet,
                        progress_active=progress_active,
                    )
                    result = (
                        file_path,
                        [],
                        0,
                        0.0,
                        ParserStatus.PARSE_FAILED.value,
                        ParseTier.REGEX_FALLBACK.value,
                        "failed",
                        Confidence.LIMITED.value,
                        scan_err,
                    )
                results.append(result)
                _, file_issues, loc, _, parser_status, _, status, _, _ = result
                self._record_progress_result(
                    loc=loc,
                    file_issues=file_issues,
                    parser_status=parser_status,
                    status=status,
                    multiplier=multiplier,
                    completed=completed_count,
                    total=total_files,
                    progress_callback=progress_callback,
                    current_file=file_path,
                )
            pool.shutdown(wait=True)
        except BaseException:
            processes = list((getattr(pool, "_processes", {}) or {}).values())
            for future in futures:
                future.cancel()
            for process in processes:
                if process and process.is_alive():
                    process.terminate()

            join_deadline = time.monotonic() + 1.0
            for process in processes:
                if process:
                    process.join(timeout=max(0.0, join_deadline - time.monotonic()))
            for process in processes:
                if process and process.is_alive() and hasattr(process, "kill"):
                    process.kill()
            for process in processes:
                if process and process.is_alive():
                    process.join(timeout=0.5)
            pool.shutdown(wait=True, cancel_futures=True)
            raise
        return results
