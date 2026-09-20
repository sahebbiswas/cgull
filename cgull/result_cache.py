"""Persistent content-addressed per-file analysis result cache (issue #545).

Opt-in on-disk cache for finalized per-file findings so unchanged files can skip
full reanalysis across process invocations. Entries are keyed by a digest of the
analysis inputs (source bytes, expanded TU text, ScanConfig fingerprint, semantic
model digest, C-GULL version, and cache schema version).

Correctness notes for this first slice:
- Cache hits are refused when the prepared AST context carries cross-TU project
  summaries (interprocedural inputs not yet folded into the key).
- Corrupt or incomplete entries degrade to a miss.
- Writes are atomic (temp file + os.replace).
- Disabled by ``--no-cache`` / ``CGULL_NO_CACHE``; enabled by ``--cache-dir`` /
  ``CGULL_CACHE_DIR`` (opt-in).
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .models import (
    Confidence,
    FixType,
    Issue,
    RelatedLocation,
    ScanConfig,
    ScanError,
    Severity,
)

CACHE_SCHEMA_VERSION = 1
NO_CACHE_ENV = "CGULL_NO_CACHE"
CACHE_DIR_ENV = "CGULL_CACHE_DIR"


def is_cache_disabled(*, no_cache_flag: bool = False) -> bool:
    """Return True when persistent caching must not be used."""
    if no_cache_flag:
        return True
    raw = os.environ.get(NO_CACHE_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def default_cache_dir(project_state_root: Optional[str] = None) -> str:
    """Resolve the default on-disk cache directory.

    Prefer ``<project>/.cgull/cache`` (already gitignored via ``.cgull/``).
    When no project root is available, fall back to ``$XDG_CACHE_HOME/cgull``
    or ``~/.cache/cgull``.
    """
    if project_state_root:
        return os.path.join(os.path.realpath(project_state_root), ".cgull", "cache")
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    if xdg:
        return os.path.join(os.path.expanduser(xdg), "cgull")
    return os.path.join(os.path.expanduser("~"), ".cache", "cgull")


def resolve_cache_dir(
    explicit: Optional[str] = None,
    *,
    project_state_root: Optional[str] = None,
    no_cache_flag: bool = False,
) -> Optional[str]:
    """Resolve an enabled cache directory, or None when caching is off.

    Opt-in: caching is enabled only when ``explicit`` is not None (including the
    empty string, which selects the default location) or ``CGULL_CACHE_DIR`` is
    set. ``--no-cache`` / ``CGULL_NO_CACHE`` always wins.
    """
    if is_cache_disabled(no_cache_flag=no_cache_flag):
        return None

    env_dir = os.environ.get(CACHE_DIR_ENV, "").strip()
    if explicit is None and not env_dir:
        return None

    if explicit is not None:
        path = explicit.strip() if explicit else ""
        if not path:
            return default_cache_dir(project_state_root)
        return os.path.realpath(os.path.abspath(os.path.expanduser(path)))

    return os.path.realpath(os.path.abspath(os.path.expanduser(env_dir)))


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _models_digest(rules: Sequence[Any]) -> str:
    """Stable digest of rule-attached semantic model registries."""
    chunks: List[str] = []
    for rule in rules:
        registry = getattr(rule, "_semantic_models", None)
        if registry is None:
            continue
        sources = getattr(registry, "sources", {}) or {}
        validators = getattr(registry, "validators", {}) or {}
        sinks = getattr(registry, "sinks", {}) or {}
        effects = getattr(getattr(registry, "call_effects", None), "effects", {}) or {}
        if not (sources or validators or sinks or effects):
            continue
        chunks.append(
            _canonical_json(
                {
                    "rule_id": getattr(rule, "rule_id", type(rule).__name__),
                    "sources": sorted(str(k) for k in sources),
                    "validators": sorted(str(k) for k in validators),
                    "sinks": sorted(str(k) for k in sinks),
                    "effects": sorted(str(k) for k in effects),
                    "sources_repr": repr(dict(sorted(sources.items()))),
                    "validators_repr": repr(dict(sorted(validators.items()))),
                    "sinks_repr": repr(dict(sorted(sinks.items()))),
                    "effects_repr": repr(dict(sorted(effects.items()))),
                }
            )
        )
    if not chunks:
        return "empty"
    return _sha256_text("\n".join(chunks))


def config_fingerprint(config: ScanConfig) -> Dict[str, Any]:
    """Serializable analysis-affecting configuration (excludes cache_dir)."""
    data = config.to_dict()
    data.pop("cache_dir", None)
    return data


def compute_cache_key(
    *,
    source_text: str,
    expanded_text: str,
    config: ScanConfig,
    cgull_version: str,
) -> str:
    """Content-addressed key for one file's reusable analysis product."""
    payload = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "cgull_version": cgull_version,
        "source_sha256": _sha256_text(source_text),
        "expanded_sha256": _sha256_text(expanded_text),
        "config": config_fingerprint(config),
        "models": _models_digest(config.get_rules()),
    }
    return _sha256_text(_canonical_json(payload))


def has_project_summaries(prepared: Any) -> bool:
    """True when prepared AST context carries cross-TU summaries (not keyed yet)."""
    if prepared is None:
        return False
    try:
        context = prepared.context
    except Exception:
        return False
    summaries = getattr(context, "project_summaries", None) or {}
    return bool(summaries)


def issue_from_dict(data: Mapping[str, Any]) -> Issue:
    """Reconstruct an Issue from its JSON-serializable dict form."""
    related_raw = data.get("related_locations") or []
    related = [
        RelatedLocation(
            file_path=str(item.get("file_path", "")),
            line_number=int(item.get("line_number", 1)),
            column_number=int(item.get("column_number", 1)),
        )
        for item in related_raw
        if isinstance(item, Mapping)
    ]
    confidence_raw = data.get("confidence")
    confidence = Confidence(confidence_raw) if confidence_raw else None
    fix_raw = data.get("fix_type", FixType.MANUAL_REVIEW.value)
    try:
        fix_type = FixType(fix_raw)
    except ValueError:
        fix_type = FixType.MANUAL_REVIEW
    return Issue(
        rule_id=str(data.get("rule_id", "")),
        rule_name=str(data.get("rule_name", "")),
        impact=Severity(data.get("impact", Severity.LOW.value)),
        file_path=str(data.get("file_path", "")),
        line_number=int(data.get("line_number", 1)),
        column_number=int(data.get("column_number", 1)),
        code_snippet=str(data.get("code_snippet", "")),
        message=str(data.get("message", "")),
        remediation=str(data.get("remediation", "")),
        cwe_id=str(data.get("cwe_id", "")),
        engine=str(data.get("engine", "Regex")),
        auto_fix_replacement=data.get("auto_fix_replacement"),
        fingerprint=str(data.get("fingerprint", "")),
        fix_type=fix_type,
        suggested_fix_replacement=data.get("suggested_fix_replacement"),
        confidence=confidence,
        reachable_under=list(data.get("reachable_under") or []),
        related_tus=list(data.get("related_tus") or []),
        related_locations=related,
    )


@dataclass(frozen=True)
class CachedFileResult:
    issues: Tuple[Issue, ...]
    lines_of_code: int
    parser_status: str
    parse_tier: str
    status: str
    confidence: str
    parse_attempts: Tuple[Dict[str, Any], ...]
    scan_error: Optional[ScanError] = None

    def as_scan_tuple(self, duration_ms: float = 0.0):
        return (
            list(self.issues),
            self.lines_of_code,
            duration_ms,
            self.parser_status,
            self.parse_tier,
            self.status,
            self.confidence,
            self.scan_error,
            [dict(item) for item in self.parse_attempts],
        )


class ResultCache:
    """Filesystem-backed content-addressed result store."""

    def __init__(self, cache_dir: str):
        self.cache_dir = os.path.realpath(cache_dir)
        self.hits = 0
        self.misses = 0
        self.stores = 0

    def _entry_path(self, key: str) -> str:
        prefix = key[:2]
        directory = os.path.join(self.cache_dir, f"v{CACHE_SCHEMA_VERSION}", prefix)
        return os.path.join(directory, f"{key}.json")

    def get(self, key: str) -> Optional[CachedFileResult]:
        path = self._entry_path(key)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self.misses += 1
            return None

        if not isinstance(raw, dict):
            self.misses += 1
            return None
        if raw.get("schema_version") != CACHE_SCHEMA_VERSION:
            self.misses += 1
            return None
        if raw.get("key") != key:
            self.misses += 1
            return None
        if raw.get("status") != "success":
            self.misses += 1
            return None

        try:
            issues = tuple(issue_from_dict(item) for item in (raw.get("issues") or []))
            scan_error = None
            err = raw.get("scan_error")
            if isinstance(err, dict) and err:
                scan_error = ScanError(
                    file_path=str(err.get("file_path", "")),
                    error_type=str(err.get("error_type", "")),
                    message=str(err.get("message", "")),
                )
            attempts = tuple(
                dict(item) for item in (raw.get("parse_attempts") or []) if isinstance(item, dict)
            )
            result = CachedFileResult(
                issues=issues,
                lines_of_code=int(raw.get("lines_of_code", 0)),
                parser_status=str(raw.get("parser_status", "")),
                parse_tier=str(raw.get("parse_tier", "")),
                status=str(raw.get("status", "success")),
                confidence=str(raw.get("confidence", "")),
                parse_attempts=attempts,
                scan_error=scan_error,
            )
        except (TypeError, ValueError, KeyError):
            self.misses += 1
            return None

        self.hits += 1
        return result

    def put(
        self,
        key: str,
        *,
        issues: Iterable[Issue],
        lines_of_code: int,
        parser_status: str,
        parse_tier: str,
        status: str,
        confidence: str,
        parse_attempts: Optional[Sequence[Mapping[str, Any]]] = None,
        scan_error: Optional[ScanError] = None,
        cgull_version: str,
    ) -> None:
        if status != "success":
            return
        directory = os.path.dirname(self._entry_path(key))
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            return

        payload = {
            "schema_version": CACHE_SCHEMA_VERSION,
            "cgull_version": cgull_version,
            "key": key,
            "issues": [issue.to_dict() for issue in issues],
            "lines_of_code": int(lines_of_code),
            "parser_status": parser_status,
            "parse_tier": parse_tier,
            "status": status,
            "confidence": confidence,
            "parse_attempts": [dict(item) for item in (parse_attempts or [])],
            "scan_error": scan_error.to_dict() if scan_error is not None else None,
        }
        path = self._entry_path(key)
        fd, tmp_path = tempfile.mkstemp(prefix=".cgull-cache-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
            self.stores += 1
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
