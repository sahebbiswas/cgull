"""Compilation-database include context for translation-unit scanning.

This module intentionally leaves the existing ``parse_compile_commands`` macro
profile ingestion untouched. It derives only include-search context and layers
that context onto the scanner per translation unit, so one compile command can
never change another translation unit's include roots.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shlex
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from .models import ConfigProfile, ScanConfig
from .preprocessor import ConfigReductionStats, reduce_generated_profiles
from .telemetry import CGullScanner as _TelemetryCGullScanner


@dataclass(frozen=True)
class CompileCommandIncludeDatabase:
    """Canonical, ordered include roots keyed by translation-unit source file."""

    include_roots_by_file: Mapping[str, Tuple[str, ...]]
    warnings: Tuple[str, ...] = ()

    @classmethod
    def from_file(cls, path: Union[str, os.PathLike[str]]) -> "CompileCommandIncludeDatabase":
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


def load_compile_commands_data(path: Union[str, os.PathLike[str]]) -> List[Any]:
    """Load a compilation database once for callers that need multiple views of it."""

    db_path = Path(path)
    if not db_path.exists():
        raise FileNotFoundError(f"Compile commands file '{db_path}' does not exist.")
    with db_path.open("r", encoding="utf-8", errors="replace") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("compile_commands.json top-level JSON must be an array")
    return data


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
        self._reduce_generated_profiles_enabled = False
        self._config_reduction_stats: Optional[ConfigReductionStats] = None
        self._reduced_profiles_cache: Optional[List[ConfigProfile]] = None

    @staticmethod
    def _positional_profiles(args: tuple[Any, ...]) -> Optional[List[ConfigProfile]]:
        # Base scan_path positional layout: target, ignore, patterns, jobs,
        # progress, quiet, profiles, strategy, threshold, seed_profiles.
        return args[6] if len(args) >= 7 else None

    def scan_path(self, *args, **kwargs):
        explicit_profiles = kwargs.get("profiles")
        if "profiles" not in kwargs:
            explicit_profiles = self._positional_profiles(args)
        requested_strategy = kwargs.get("config_strategy")
        if requested_strategy is None and len(args) >= 8:
            requested_strategy = args[7]
        configured_strategy = getattr(self.config, "config_strategy", "one-at-a-time")

        self._reduce_generated_profiles_enabled = (
            explicit_profiles is None
            and (requested_strategy is not None or configured_strategy != "one-at-a-time")
        )
        self._config_reduction_stats = None
        self._reduced_profiles_cache = None
        try:
            result = super().scan_path(*args, **kwargs)
        finally:
            self._reduce_generated_profiles_enabled = False

        if self._config_reduction_stats is not None:
            result.config_reduction_stats = self._config_reduction_stats
        return result

    def scan_text(
        self,
        source_code: str,
        file_path: str = "source.c",
        quiet: bool = False,
        profiles: Optional[List[ConfigProfile]] = None,
        config_strategy: Optional[str] = None,
        exhaustive_threshold: Optional[int] = None,
    ):
        """Scan in-memory source, reducing only internally generated profiles."""

        reduction_stats: Optional[ConfigReductionStats] = None
        effective_profiles = profiles
        configured_strategy = getattr(self.config, "config_strategy", "one-at-a-time")
        should_generate = profiles is None and (
            config_strategy is not None or configured_strategy != "one-at-a-time"
        )
        if should_generate:
            strat = config_strategy if config_strategy is not None else configured_strategy
            threshold = (
                exhaustive_threshold
                if exhaustive_threshold is not None
                else getattr(self.config, "exhaustive_threshold", 10)
            )
            from .ast_analyzer import ConditionalFlagCollector, generate_config_profiles
            from .utils import strip_comments_keep_lines

            _, clean_code = strip_comments_keep_lines(source_code)
            collected = ConditionalFlagCollector.collect(clean_code)
            if collected.presence_flags or strat == "baseline":
                candidates = generate_config_profiles(
                    collected.presence_flags,
                    strategy=strat,
                    exhaustive_threshold=threshold,
                    base_flags=self.config.defined_syms,
                )
                reduction = reduce_generated_profiles([source_code], candidates)
                effective_profiles = list(reduction.profiles)
                reduction_stats = reduction.stats

        result = super().scan_text(
            source_code,
            file_path=file_path,
            quiet=quiet,
            profiles=effective_profiles,
            config_strategy=config_strategy,
            exhaustive_threshold=exhaustive_threshold,
        )
        if reduction_stats is not None:
            result.config_reduction_stats = reduction_stats
        return result

    def _reduce_profiles_for_scan(
        self,
        files_to_scan: List[str],
        profiles: Optional[List[ConfigProfile]],
    ) -> Optional[List[ConfigProfile]]:
        if not self._reduce_generated_profiles_enabled or not profiles:
            return profiles
        if self._reduced_profiles_cache is not None:
            return self._reduced_profiles_cache

        sources: List[str] = []
        try:
            for file_path in files_to_scan:
                with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                    sources.append(handle.read())
            reduction = reduce_generated_profiles(sources, profiles)
            reduced = list(reduction.profiles)
            self._config_reduction_stats = reduction.stats
            self._reduced_profiles_cache = reduced
            return reduced
        except OSError:
            # File scanning owns read-error reporting. Reduction must never turn
            # an optimization failure into a scan failure or drop a candidate.
            self._config_reduction_stats = ConfigReductionStats(
                len(profiles), len(profiles), 0, 0
            )
            self._reduced_profiles_cache = list(profiles)
            return self._reduced_profiles_cache

    def _scan_files_sequential(
        self,
        files_to_scan: List[str],
        config: ScanConfig,
        progress_callback=None,
        quiet: bool = False,
        progress_active: bool = False,
        profiles: Optional[List[ConfigProfile]] = None,
    ):
        profiles = self._reduce_profiles_for_scan(files_to_scan, profiles)
        return super()._scan_files_sequential(
            files_to_scan,
            config,
            progress_callback=progress_callback,
            quiet=quiet,
            progress_active=progress_active,
            profiles=profiles,
        )

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
        profiles = self._reduce_profiles_for_scan(files_to_scan, profiles)
        return super()._scan_files_parallel(
            files_to_scan,
            jobs,
            config,
            progress_callback=progress_callback,
            quiet=quiet,
            progress_active=progress_active,
            profiles=profiles,
        )

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
