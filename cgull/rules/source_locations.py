"""Source-location helpers for rule diagnostics.

Rule primary locations stay in expanded-TU coordinates until the scan engine
normalizes them. Related sites embedded in messages, however, must be rendered
from source provenance before that final normalization step.
"""

from __future__ import annotations

import os
from typing import Any, Optional, Tuple


def _source_site(
    ast_ctx: Any,
    site: Any,
    *,
    fallback_file: Optional[str] = None,
) -> Tuple[Optional[str], int]:
    """Resolve a CFG event or expanded line number to its original source site."""
    location = getattr(site, "source_location", None)
    location_line = int(getattr(location, "line_number", 0) or 0)
    if location_line > 0:
        return getattr(location, "file_path", None) or fallback_file, location_line

    raw_line = getattr(site, "line_number", None)
    if raw_line is None and isinstance(site, int):
        raw_line = site
    try:
        expanded_line = int(raw_line or 0)
    except (TypeError, ValueError):
        expanded_line = 0

    line_map = getattr(ast_ctx, "line_map", None)
    mapped = line_map.get(expanded_line) if line_map and expanded_line > 0 else None
    if mapped is not None:
        return (
            getattr(mapped, "file_path", None) or fallback_file,
            int(getattr(mapped, "line_number", expanded_line) or expanded_line),
        )
    return fallback_file, expanded_line


def format_related_site(
    ast_ctx: Any,
    site: Any,
    *,
    primary_site: Any = None,
    fallback_file: Optional[str] = None,
) -> str:
    """Format a related site without exposing expanded/preprocessed coordinates.

    Same-file references retain the established "line N" wording. When the
    related site comes from a different included file, include a stable path
    relative to the primary site directory so the message preserves file
    identity without embedding machine-specific absolute paths.
    """
    related_path, related_line = _source_site(
        ast_ctx, site, fallback_file=fallback_file
    )
    primary_path, _ = _source_site(
        ast_ctx,
        site if primary_site is None else primary_site,
        fallback_file=fallback_file,
    )

    if related_path and primary_path:
        related_real = os.path.realpath(related_path)
        primary_real = os.path.realpath(primary_path)
        if os.path.normcase(related_real) != os.path.normcase(primary_real):
            try:
                display_path = os.path.relpath(
                    related_real,
                    os.path.dirname(primary_real),
                )
            except ValueError:
                display_path = related_path
            display_path = display_path.replace("\\", "/")
            return f"{display_path}:{related_line}"

    return f"line {related_line}"
