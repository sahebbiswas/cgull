"""C-GULL integration helpers for pcpp diagnostic handling.

pcpp handles ``#error`` and ``#warning`` in ``on_directive_handle`` and its
base implementation writes directly to ``sys.stderr``.  That bypasses
C-GULL's CLI/progress renderer and can corrupt both live progress output and
structured reports.

C-GULL currently does not surface preprocessor diagnostics as first-class
findings, so consume those directives at the integration boundary while
preserving pcpp's return-code semantics for ``#error``.
"""

from __future__ import annotations

from typing import Any, Callable, Optional


_INSTALLED_MARKER = "_cgull_suppresses_raw_diagnostics"


def install_pcpp_diagnostic_suppression() -> None:
    """Prevent pcpp from writing ``#error``/``#warning`` directly to stderr.

    The hook is intentionally installed before :mod:`visitor` is imported.
    ``CASTParser`` creates pcpp preprocessors later at parse time, so replacing
    the base hook here keeps the existing parser implementation focused while
    ensuring every C-GULL-owned pcpp instance has coordinated output behavior.

    The wrapper is idempotent and delegates every non-diagnostic directive to
    pcpp unchanged.
    """

    try:
        import pcpp
    except ImportError:
        return

    original: Optional[Callable[..., Any]] = getattr(
        pcpp.Preprocessor, "on_directive_handle", None
    )
    if original is None or getattr(original, _INSTALLED_MARKER, False):
        return

    def _cgull_on_directive_handle(self, directive, toks, ifpassthru, precedingtoks):
        directive_name = getattr(directive, "value", None)
        if directive_name == "error":
            # Match pcpp's default semantics without its direct stderr write.
            self.return_code += 1
            return True
        if directive_name == "warning":
            return True
        return original(self, directive, toks, ifpassthru, precedingtoks)

    setattr(_cgull_on_directive_handle, _INSTALLED_MARKER, True)
    pcpp.Preprocessor.on_directive_handle = _cgull_on_directive_handle
