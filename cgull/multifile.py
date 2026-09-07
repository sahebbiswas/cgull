"""Helpers for analyzing a related group of source files as one semantic unit."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Sequence, Union

from .engine import CGullScanner
from .models import ScanResult


SourcePath = Union[str, os.PathLike[str]]


def scan_translation_unit_group(
    scanner: CGullScanner,
    source_paths: Sequence[SourcePath],
    *,
    quiet: bool = False,
) -> ScanResult:
    """Analyze related source files through one shared AST/call graph.

    The files are included into a synthetic root that lives beside the first
    source file. Include expansion preserves source locations in the line map,
    so findings remain attributed to the original member file while direct
    calls across sibling source files participate in the same interprocedural
    analysis session.

    This helper is intentionally explicit rather than changing ordinary project
    scanning semantics: separate C translation units remain separate unless a
    caller knows that a set of files represents one analyzable source group
    (for example, Juliet's split-file testcase stages).
    """
    members = [Path(path).resolve() for path in source_paths]
    if not members:
        raise ValueError("source_paths must contain at least one source file")
    if len(set(members)) != len(members):
        raise ValueError("source_paths must not contain duplicate files")
    missing = [path for path in members if not path.is_file()]
    if missing:
        raise FileNotFoundError(str(missing[0]))

    common_parent = Path(os.path.commonpath([str(path.parent) for path in members]))
    root_name = ".cgull-source-group.c"
    synthetic_path = common_parent / root_name

    include_lines = []
    for member in members:
        relative = os.path.relpath(member, common_parent).replace("\\", "/")
        escaped = relative.replace('"', '\\"')
        include_lines.append(f'#include "{escaped}"')

    source = "\n".join(include_lines) + "\n"
    return scanner.scan_text(source, file_path=str(synthetic_path), quiet=quiet)
