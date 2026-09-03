"""Deterministic fixed-point evaluation over call-graph SCCs.

The engine is deliberately fact-domain agnostic.  Domains provide a finite
lattice and a monotone transfer function; the engine supplies stable SCC
ordering, bounded iteration, and explicit conservative degradation when a
component does not converge within the configured budget.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Generic, Mapping, Optional, Tuple, TypeVar


FactT = TypeVar("FactT")


@dataclass(frozen=True)
class FixedPointConfig:
    """Resource bounds shared by fixed-point fact domains."""

    max_iterations_per_scc: int = 64
    max_provenance: int = 128

    def __post_init__(self) -> None:
        if self.max_iterations_per_scc < 1:
            raise ValueError("max_iterations_per_scc must be at least 1")
        if self.max_provenance < 1:
            raise ValueError("max_provenance must be at least 1")


@dataclass(frozen=True)
class FixedPointDiagnostic:
    """Visible degradation emitted by the fixed-point engine."""

    code: str
    functions: Tuple[str, ...]
    iterations: int
    message: str


@dataclass(frozen=True)
class FixedPointResult(Generic[FactT]):
    facts: Mapping[str, FactT]
    diagnostics: Tuple[FixedPointDiagnostic, ...]
    iterations_by_scc: Mapping[Tuple[str, ...], int]


class FiniteLattice(ABC, Generic[FactT]):
    """Executable contract required by :class:`SCCFixedPointEngine`.

    ``max_height`` is a finite upper bound on the ascending-chain height for
    one fact.  ``join`` must be commutative, associative, and idempotent.
    ``unknown`` returns a conservative top-like value for a symbol when an
    analysis limit is reached.
    """

    max_height: int

    @abstractmethod
    def bottom(self, symbol: str) -> FactT:
        raise NotImplementedError

    @abstractmethod
    def join(self, left: FactT, right: FactT) -> FactT:
        raise NotImplementedError

    @abstractmethod
    def unknown(self, symbol: str, current: FactT) -> FactT:
        raise NotImplementedError


class SCCFixedPointEngine(Generic[FactT]):
    """Evaluate monotone facts in deterministic callee-before-caller SCC order."""

    def __init__(self, graph, lattice: FiniteLattice[FactT], config: Optional[FixedPointConfig] = None) -> None:
        if not isinstance(getattr(lattice, "max_height", None), int) or lattice.max_height < 1:
            raise ValueError("fixed-point domains must declare a positive finite max_height")
        self.graph = graph
        self.lattice = lattice
        self.config = config or FixedPointConfig()

    def run(self, transfer) -> FixedPointResult[FactT]:
        names = tuple(function.name for function in self.graph.functions)
        facts: Dict[str, FactT] = {name: self.lattice.bottom(name) for name in names}
        diagnostics = []
        iteration_counts: Dict[Tuple[str, ...], int] = {}

        for raw_component in self.graph.bottom_up_sccs:
            component = tuple(sorted(raw_component))
            recursive = len(component) > 1 or any(name in self.graph.callees(name) for name in component)
            budget = self.config.max_iterations_per_scc if recursive else 1
            converged = not recursive
            rounds = 0

            for round_number in range(1, budget + 1):
                rounds = round_number
                # Jacobi-style updates make results independent of function
                # iteration order within an SCC.
                snapshot = dict(facts)
                updates: Dict[str, FactT] = {}
                changed = False
                for name in component:
                    candidate = transfer(name, snapshot, self.config)
                    joined = self.lattice.join(snapshot[name], candidate)
                    updates[name] = joined
                    if joined != snapshot[name]:
                        changed = True
                facts.update(updates)

                if recursive and not changed:
                    converged = True
                    break

            iteration_counts[component] = rounds
            if not converged:
                for name in component:
                    facts[name] = self.lattice.unknown(name, facts[name])
                diagnostics.append(
                    FixedPointDiagnostic(
                        code="CONVERGENCE_LIMIT",
                        functions=component,
                        iterations=rounds,
                        message=(
                            "summary fixed-point did not converge within "
                            f"{self.config.max_iterations_per_scc} iterations; "
                            "affected facts were degraded to conservative unknown"
                        ),
                    )
                )

        return FixedPointResult(
            facts=dict(sorted(facts.items())),
            diagnostics=tuple(diagnostics),
            iterations_by_scc=dict(sorted(iteration_counts.items())),
        )
