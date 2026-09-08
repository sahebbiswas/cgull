"""Compatibility facade for the core CFG graph and legacy data-flow engine.

Graph topology lives in :mod:`cgull.cfg.graph`; legacy state transfer and
queries live in :mod:`cgull.cfg.legacy_dataflow`; domain joins live in
:mod:`cgull.cfg.domains`.  This module retains the historic import surface.
"""

from .domains import meet_allocation, meet_initialization, meet_nullness
from .graph import StructuredGraph
from .legacy_dataflow import LegacyDataflowMixin


class StructuredCFG(LegacyDataflowMixin, StructuredGraph):
    """Historic CFG type composed from graph and data-flow responsibilities."""


__all__ = [
    "StructuredCFG",
    "meet_nullness",
    "meet_initialization",
    "meet_allocation",
]
