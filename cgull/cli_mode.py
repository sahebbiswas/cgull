"""CLI-only scan mode inference and reporting helpers.

The library/API default intentionally remains :class:`ScanMode.FILE`.  These
helpers are used only by the command-line facade after target validation and
configuration discovery.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional, Sequence, Tuple

from .models import ScanMode


MODE_SOURCE_COMMAND_LINE = "command line"
MODE_SOURCE_CONFIGURATION = "configuration"
MODE_SOURCE_INFERRED = "inferred from targets"


def resolve_cli_scan_mode(
    targets: Sequence[str],
    cli_mode: Optional[str | ScanMode],
    configured_mode: Optional[str | ScanMode],
) -> Tuple[ScanMode, str]:
    """Resolve the CLI scan mode using the documented precedence.

    ``targets`` are expected to have already passed the CLI's normal existence
    validation.  ``os.path.isdir`` intentionally follows the platform's normal
    symlink semantics, matching the rest of the CLI filesystem handling.
    """
    if cli_mode is not None:
        mode = cli_mode if isinstance(cli_mode, ScanMode) else ScanMode(str(cli_mode).lower())
        return mode, MODE_SOURCE_COMMAND_LINE

    if configured_mode is not None:
        mode = configured_mode if isinstance(configured_mode, ScanMode) else ScanMode(str(configured_mode).lower())
        return mode, MODE_SOURCE_CONFIGURATION

    effective_targets = list(targets) or ["."]
    if any(os.path.isdir(target) for target in effective_targets):
        return ScanMode.TU, MODE_SOURCE_INFERRED
    return ScanMode.FILE, MODE_SOURCE_INFERRED


def mode_aware_reporter(delegate: Any, mode: ScanMode, source: str):
    """Wrap a reporter so CLI-selected mode provenance is visible everywhere."""

    def annotate(result: Any) -> None:
        # These attributes are deliberately CLI metadata rather than ScanResult
        # dataclass fields so programmatic callers retain the existing API shape.
        result.scan_mode = mode.value
        result.scan_mode_source = source

    class DelegateReporterMeta(type):
        def __getattr__(cls, name: str):
            """Preserve reporter extensions not overridden by this wrapper."""
            return getattr(delegate, name)

    class ModeAwareReporter(metaclass=DelegateReporterMeta):
        @staticmethod
        def to_json(result):
            annotate(result)
            rendered = delegate.to_json(result)
            if not rendered:
                return rendered
            data = json.loads(rendered)
            meta = data.setdefault("meta", {})
            meta["scan_mode"] = mode.value
            meta["scan_mode_source"] = source
            return json.dumps(data, indent=2)

        @staticmethod
        def to_sarif(result):
            annotate(result)
            rendered = delegate.to_sarif(result)
            if not rendered:
                return rendered
            data = json.loads(rendered)
            runs = data.get("runs") or []
            if runs:
                invocations = runs[0].get("invocations")
                if not isinstance(invocations, list):
                    invocations = []
                    runs[0]["invocations"] = invocations
                if not invocations:
                    invocations.append({})
                if not isinstance(invocations[0], dict):
                    invocations[0] = {}
                props = invocations[0].get("properties")
                if not isinstance(props, dict):
                    props = {}
                    invocations[0]["properties"] = props
                props["scanMode"] = mode.value
                props["scanModeSource"] = source
            return json.dumps(data, indent=2)

        @staticmethod
        def to_markdown(result):
            annotate(result)
            rendered = delegate.to_markdown(result)
            if not rendered:
                return rendered
            lines = rendered.splitlines()
            insertion = [
                f"**Scan Mode**: `{mode.value}`  ",
                f"**Scan Mode Source**: `{source}`  ",
            ]
            if len(lines) >= 2 and lines[1] == "":
                lines[2:2] = insertion
            else:
                lines = insertion + [""] + lines
            return "\n".join(lines)

        @staticmethod
        def to_terminal_text(result):
            annotate(result)
            rendered = delegate.to_terminal_text(result)
            if not rendered:
                return rendered
            newline = "\r\n" if "\r\n" in rendered else "\n"
            marker = f"Scan complete{newline}"
            details = (
                f"  Scan mode:           {mode.value}{newline}"
                f"  Mode source:         {source}{newline}"
            )
            if marker in rendered:
                return rendered.replace(marker, marker + details, 1)
            return (
                f"Selected scan mode: {mode.value}{newline}"
                f"Mode source: {source}{newline}{newline}"
                f"{rendered}"
            )

    return ModeAwareReporter
