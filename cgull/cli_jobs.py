"""CLI-only worker-count inference and reporting helpers.

The programmatic scanner API intentionally keeps ``jobs=1`` as its default.
These helpers are used by the public CLI so project/directory scans can choose
bounded automatic parallelism without changing library callers.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional, Sequence, Tuple


AUTO_JOBS_CAP = 8
JOBS_SOURCE_EXPLICIT = "explicit"
JOBS_SOURCE_AUTOMATIC = "automatic"
JOBS_SOURCE_SEQUENTIAL_DEFAULT = "sequential default"


def automatic_job_limit() -> int:
    """Return the bounded CLI automatic worker limit."""
    return max(1, min(AUTO_JOBS_CAP, os.cpu_count() or 1))


def resolve_cli_jobs(
    targets: Sequence[str],
    cli_jobs: Optional[int],
) -> Tuple[int, str]:
    """Resolve CLI worker selection while preserving explicit overrides.

    Explicit positive values are returned unchanged. ``--jobs 0`` retains its
    automatic meaning, but uses the bounded CLI auto limit. When ``--jobs`` is
    omitted, a single explicit file remains sequential while directory and
    multi-target scans use automatic parallelism.
    """
    if cli_jobs is not None:
        if cli_jobs == 0:
            return automatic_job_limit(), JOBS_SOURCE_AUTOMATIC
        return cli_jobs, JOBS_SOURCE_EXPLICIT

    effective_targets = list(targets) or ["."]
    if len(effective_targets) == 1 and os.path.isfile(effective_targets[0]):
        return 1, JOBS_SOURCE_SEQUENTIAL_DEFAULT
    return automatic_job_limit(), JOBS_SOURCE_AUTOMATIC


def _effective_worker_count(result: Any, selected_jobs: int) -> int:
    """Mirror the engine's post-discovery cap for user-facing metadata."""
    attempted = int(getattr(result, "files_analyzed", 0) or 0) + int(
        getattr(result, "files_failed", 0) or 0
    )
    if attempted <= 0:
        attempted = int(getattr(result, "scanned_files_count", 0) or 0)
    if attempted <= 0:
        return 0
    return min(max(1, selected_jobs), attempted)


def jobs_aware_reporter(delegate: Any, selected_jobs: int, source: str):
    """Wrap a reporter so effective CLI worker metadata is visible everywhere."""

    def annotate(result: Any) -> int:
        effective_jobs = _effective_worker_count(result, selected_jobs)
        result.jobs = effective_jobs
        result.jobs_source = source
        return effective_jobs

    class DelegateReporterMeta(type):
        def __getattr__(cls, name: str):
            return getattr(delegate, name)

    class JobsAwareReporter(metaclass=DelegateReporterMeta):
        @staticmethod
        def to_json(result):
            effective_jobs = annotate(result)
            rendered = delegate.to_json(result)
            if not rendered:
                return rendered
            data = json.loads(rendered)
            if not isinstance(data, dict):
                return json.dumps(data, indent=2)
            meta = data.get("meta")
            if not isinstance(meta, dict):
                meta = {}
                data["meta"] = meta
            meta["jobs"] = effective_jobs
            meta["jobs_source"] = source
            return json.dumps(data, indent=2)

        @staticmethod
        def to_sarif(result):
            effective_jobs = annotate(result)
            rendered = delegate.to_sarif(result)
            if not rendered:
                return rendered
            data = json.loads(rendered)
            if not isinstance(data, dict):
                return json.dumps(data, indent=2)
            runs = data.get("runs")
            if not isinstance(runs, list) or not runs or not isinstance(runs[0], dict):
                return json.dumps(data, indent=2)
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
            props["jobs"] = effective_jobs
            props["jobsSource"] = source
            return json.dumps(data, indent=2)

        @staticmethod
        def to_markdown(result):
            effective_jobs = annotate(result)
            rendered = delegate.to_markdown(result)
            if not rendered:
                return rendered
            lines = rendered.splitlines()
            insertion = [
                f"**Workers**: `{effective_jobs}`  ",
                f"**Worker Source**: `{source}`  ",
            ]
            if len(lines) >= 2 and lines[1] == "":
                lines[2:2] = insertion
            else:
                lines = insertion + [""] + lines
            return "\n".join(lines)

        @staticmethod
        def to_terminal_text(result):
            effective_jobs = annotate(result)
            rendered = delegate.to_terminal_text(result)
            if not rendered:
                return rendered
            newline = "\r\n" if "\r\n" in rendered else "\n"
            marker = f"Scan complete{newline}"
            details = (
                f"  Workers:             {effective_jobs}{newline}"
                f"  Worker source:       {source}{newline}"
            )
            if marker in rendered:
                return rendered.replace(marker, marker + details, 1)
            return (
                f"Workers: {effective_jobs}{newline}"
                f"Worker source: {source}{newline}{newline}"
                f"{rendered}"
            )

    return JobsAwareReporter
