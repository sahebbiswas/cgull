"""Structured diagnostics emitted by CFG construction."""

from dataclasses import dataclass
from typing import Optional

from .model import CFGSourceLocation


@dataclass(frozen=True)
class CFGDiagnostic:
    """A structured diagnostic produced while building a CFG."""

    code: str
    message: str
    source_location: Optional[CFGSourceLocation] = None
    target: Optional[str] = None


__all__ = ["CFGDiagnostic"]
