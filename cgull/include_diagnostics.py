"""Include-root validation and coordinator-scoped diagnostic collection."""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
import logging
import os

logger = logging.getLogger(__name__)
_ACTIVE_WARNINGS: ContextVar[dict[str, str] | None] = ContextVar("cgull_include_warnings", default=None)


def invalid_root_warning(original: str, resolved: str, source: str) -> str | None:
    """Keep native path semantics and report ineffective roots without rejecting them."""
    if os.path.isdir(resolved):
        return None
    return (f"Include root {original!r} from {source} resolves to {resolved!r}, "
            "which does not exist or is not a directory; scanning will continue.")


def record_root_warning(resolved: str, message: str | None) -> None:
    warnings = _ACTIVE_WARNINGS.get()
    if warnings is None or message is None:
        return
    key = os.path.normcase(os.path.realpath(resolved))
    if key not in warnings:
        warnings[key] = message
        logger.warning("%s", message)


@contextmanager
def collect_include_warnings(initial: Mapping[str, str] | None = None) -> Iterator[dict[str, str]]:
    # Initial warnings have already been displayed by the CLI configuration loader.
    warnings = dict(initial or {})
    token = _ACTIVE_WARNINGS.set(warnings)
    try:
        yield warnings
    finally:
        _ACTIVE_WARNINGS.reset(token)
