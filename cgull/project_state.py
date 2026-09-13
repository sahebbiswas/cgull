"""Project-local state path resolution shared by CLI bootstrap and configuration."""

from __future__ import annotations

import os
from typing import Optional, Sequence, Union

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore


DEFAULT_LOG_RETENTION_RUNS = 20
PathLike = Union[str, os.PathLike[str]]


def normalize_project_path(path: PathLike) -> str:
    """Return a stable absolute path without requiring the path to exist."""
    return os.path.abspath(os.path.expanduser(os.fspath(path)))


def _target_directory(target: PathLike) -> str:
    resolved = normalize_project_path(target)
    if os.path.isdir(resolved):
        return resolved
    if os.path.isfile(resolved):
        return os.path.dirname(resolved) or os.getcwd()

    # Missing targets are validated by the command handler. For logging bootstrap,
    # treat path-looking values as files only when they have an existing parent;
    # otherwise fall back to cwd rather than creating state beside a typo.
    parent = os.path.dirname(resolved)
    if parent and os.path.isdir(parent):
        return parent
    return os.getcwd()


def effective_target_root(targets: Optional[Sequence[PathLike]] = None) -> str:
    """Return the common directory represented by scan targets, or cwd safely."""
    values = list(targets or ["."])
    directories = [_target_directory(target) for target in values]
    try:
        common = os.path.commonpath(directories)
    except ValueError:
        # Windows cross-drive targets have no meaningful common path.
        return os.getcwd()
    return common or os.getcwd()


def _existing_explicit_config(config_path: Optional[PathLike]) -> Optional[str]:
    """Return any existing explicit config path, regardless of its filename."""
    if config_path is None:
        return None
    resolved = normalize_project_path(config_path)
    if not os.path.isfile(resolved):
        return None
    return resolved


def resolve_project_config_file(
    targets: Optional[Sequence[PathLike]] = None,
    config_path: Optional[PathLike] = None,
) -> Optional[str]:
    """Resolve the config that establishes project state without loading it fully."""
    explicit = _existing_explicit_config(config_path)
    if explicit is not None:
        return explicit
    if config_path is not None:
        # An explicit-but-invalid path is reported later by load_config(). Avoid
        # silently adopting a different config only for bootstrap housekeeping.
        return None

    from .config import find_config_file

    return find_config_file(effective_target_root(targets))


def resolve_project_state_root(
    targets: Optional[Sequence[PathLike]] = None,
    config_path: Optional[PathLike] = None,
) -> str:
    """Resolve the canonical directory under which C-GULL stores project state.

    Existing explicit configuration wins. Otherwise configuration is discovered
    from the effective target/common target root. With no configuration, state is
    rooted at that effective target directory. Cross-drive target sets fall back
    deterministically to cwd. An invalid explicit config never causes bootstrap
    to adopt a different auto-discovered configuration.
    """
    explicit = _existing_explicit_config(config_path)
    if explicit is not None:
        return os.path.dirname(explicit)

    target_root = effective_target_root(targets)
    if config_path is not None:
        # load_config() owns the eventual missing/invalid explicit-path error.
        # Logging housekeeping must not choose a different discovered project.
        return target_root

    from .config import find_config_file

    discovered = find_config_file(target_root)
    if discovered:
        return os.path.dirname(os.path.abspath(discovered))
    return target_root


def _cgull_toml_payload(config_path: str) -> Optional[dict]:
    try:
        with open(config_path, "rb") as stream:
            data = tomllib.load(stream)
    except (OSError, ValueError, TypeError):
        return None

    if not isinstance(data, dict):
        return None
    if os.path.basename(config_path) == "pyproject.toml":
        tool_section = data.get("tool")
        data = tool_section.get("cgull", {}) if isinstance(tool_section, dict) else {}
    return data if isinstance(data, dict) else None


def read_logging_retention(
    targets: Optional[Sequence[PathLike]] = None,
    config_path: Optional[PathLike] = None,
) -> int:
    """Read only [logging].retention_runs for pre-scan housekeeping.

    Full configuration validation remains owned by ``load_config``. Invalid or
    unreadable bootstrap values deliberately fall back to the default so logging
    setup cannot change scan exit semantics.
    """
    resolved_config = resolve_project_config_file(targets, config_path)
    if not resolved_config:
        return DEFAULT_LOG_RETENTION_RUNS

    raw = _cgull_toml_payload(resolved_config)
    if raw is None:
        return DEFAULT_LOG_RETENTION_RUNS
    logging_section = raw.get("logging", {})
    if not isinstance(logging_section, dict):
        return DEFAULT_LOG_RETENTION_RUNS
    value = logging_section.get("retention_runs", DEFAULT_LOG_RETENTION_RUNS)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return DEFAULT_LOG_RETENTION_RUNS
    return value
