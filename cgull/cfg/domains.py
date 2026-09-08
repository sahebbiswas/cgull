"""State-domain lattice operations used by the legacy CFG data-flow engine.

These helpers are graph-independent so domain behavior can be tested and
reused without constructing a CFG.
"""

from .model import Allocation, Initialization, Nullness


def meet_nullness(a: Nullness, b: Nullness) -> Nullness:
    if a == Nullness.UNKNOWN:
        return b
    if b == Nullness.UNKNOWN:
        return a
    if a == b:
        return a
    if (a == Nullness.NON_NULL and b == Nullness.NULL) or (
        a == Nullness.NULL and b == Nullness.NON_NULL
    ):
        return Nullness.MAYBE_NULL
    if a == Nullness.MAYBE_NULL or b == Nullness.MAYBE_NULL:
        return Nullness.MAYBE_NULL
    return Nullness.UNKNOWN


def meet_initialization(a: Initialization, b: Initialization) -> Initialization:
    if a == b:
        return a
    if (
        a == Initialization.MAYBE_INITIALIZED
        or b == Initialization.MAYBE_INITIALIZED
    ):
        return Initialization.MAYBE_INITIALIZED
    if (
        a == Initialization.INITIALIZED
        and b == Initialization.UNINITIALIZED
    ) or (
        a == Initialization.UNINITIALIZED
        and b == Initialization.INITIALIZED
    ):
        return Initialization.MAYBE_INITIALIZED
    return a


def meet_allocation(a: Allocation, b: Allocation) -> Allocation:
    if a == b:
        return a
    if a == Allocation.MAYBE_FREED or b == Allocation.MAYBE_FREED:
        return Allocation.MAYBE_FREED
    if a == Allocation.FREED or b == Allocation.FREED:
        return Allocation.MAYBE_FREED
    if a == Allocation.MAYBE_ALLOCATED or b == Allocation.MAYBE_ALLOCATED:
        return Allocation.MAYBE_ALLOCATED
    if (
        a == Allocation.ALLOCATED
        and b == Allocation.NOT_ALLOCATED
    ) or (
        a == Allocation.NOT_ALLOCATED
        and b == Allocation.ALLOCATED
    ):
        return Allocation.MAYBE_ALLOCATED
    return Allocation.NOT_ALLOCATED


__all__ = ["meet_nullness", "meet_initialization", "meet_allocation"]
