"""Reduce generated configuration profiles by modeled branch behavior."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence, Any

from ..models import ConfigProfile
from .configuration_space import WitnessStatus, derive_branch_witnesses
from .directives import parse_conditional_directives
from .expressions import Defined, Expression, Predicate, Variable, conjunction, expression_atoms, negate
from .robdd import AnalysisLimitExceeded, BDD, ResourceLimits


@dataclass(frozen=True)
class ConfigReductionStats:
    """Deterministic accounting for generated profile reduction."""

    candidate_count: int
    retained_count: int
    equivalent_removed: int
    unreachable_removed: int

    @property
    def removed_count(self) -> int:
        return self.candidate_count - self.retained_count


@dataclass(frozen=True)
class ConfigReductionResult:
    """Retained generated profiles plus reduction accounting."""

    profiles: tuple[ConfigProfile, ...]
    stats: ConfigReductionStats


def _profile_key(profile: ConfigProfile) -> tuple:
    return (
        tuple(sorted((str(k), repr(v)) for k, v in profile.flags.items())),
        profile.name,
    )


def _known_macro_value(flags: Mapping[str, Any], name: str) -> bool | None:
    if name not in flags:
        return False
    value = flags[name]
    if value is False:
        return False
    if value is None or value is True:
        return True
    if isinstance(value, int):
        return value != 0
    return None


def _profile_constraint(expression: Expression, flags: Mapping[str, Any]) -> Expression:
    terms: list[Expression] = []
    for atom in expression_atoms(expression):
        known: bool | None
        if isinstance(atom, Defined):
            known = atom.name in flags and flags[atom.name] is not False
        elif isinstance(atom, Variable):
            known = _known_macro_value(flags, atom.name)
        elif isinstance(atom, Predicate):
            known = None
        else:
            known = None
        if known is not None:
            terms.append(atom if known else negate(atom))
    return conjunction(*terms)


def _branch_possible(
    expression: Expression,
    profile: ConfigProfile,
    limits: ResourceLimits | None,
) -> bool | None:
    constrained = conjunction(expression, _profile_constraint(expression, profile.flags))
    try:
        bdd = BDD(expression_atoms(constrained), limits=limits)
        return bdd.build(constrained) != 0
    except AnalysisLimitExceeded:
        return None


def reduce_generated_profiles(
    sources: Iterable[str],
    profiles: Sequence[ConfigProfile],
    *,
    limits: ResourceLimits | None = None,
) -> ConfigReductionResult:
    """Deduplicate generated profiles by modeled conditional-region behavior.

    Profiles are sorted by effective flag-map and name before reduction, making
    representative choice independent of input ordering. A profile signature is
    the set of reachable modeled branches across all supplied source strings.
    Opaque predicates remain free Boolean atoms. If malformed structure or a
    resource limit prevents a safe equivalence proof, that profile is retained
    conservatively instead of being merged.

    This helper is intentionally for generated/derived profiles. Explicit user
    profiles should bypass it so user-requested scans remain authoritative.
    """

    ordered_profiles = sorted(profiles, key=_profile_key)
    candidates = len(ordered_profiles)
    if candidates <= 1:
        return ConfigReductionResult(
            tuple(ordered_profiles),
            ConfigReductionStats(candidates, candidates, 0, 0),
        )

    branch_expressions: list[tuple[int, int, Expression]] = []
    unsafe = False
    for source_index, source in enumerate(sources):
        tree = parse_conditional_directives(source)
        for witness in derive_branch_witnesses(tree, limits=limits):
            if witness.status in (WitnessStatus.UNSUPPORTED, WitnessStatus.LIMIT_EXCEEDED):
                unsafe = True
                continue
            if witness.status is WitnessStatus.SATISFIABLE and witness.effective_condition is not None:
                branch_expressions.append((
                    source_index,
                    witness.branch.directive.source_range.start.offset,
                    witness.effective_condition,
                ))

    if unsafe or not branch_expressions:
        # Exact duplicate flag maps are still safe to collapse because ConfigProfile
        # equality itself is defined by effective flags, not presentation name.
        seen_flags: set[ConfigProfile] = set()
        retained: list[ConfigProfile] = []
        for profile in ordered_profiles:
            if profile in seen_flags:
                continue
            seen_flags.add(profile)
            retained.append(profile)
        removed = candidates - len(retained)
        return ConfigReductionResult(
            tuple(retained),
            ConfigReductionStats(candidates, len(retained), removed, 0),
        )

    signatures: dict[tuple[tuple[int, int], ...], ConfigProfile] = {}
    conservative: list[ConfigProfile] = []
    empty_profiles: list[ConfigProfile] = []

    for profile in ordered_profiles:
        active: list[tuple[int, int]] = []
        indeterminate = False
        for source_index, offset, expression in branch_expressions:
            possible = _branch_possible(expression, profile, limits)
            if possible is None:
                indeterminate = True
                break
            if possible:
                active.append((source_index, offset))
        if indeterminate:
            conservative.append(profile)
            continue
        signature = tuple(active)
        if not signature:
            empty_profiles.append(profile)
            continue
        signatures.setdefault(signature, profile)

    retained = list(signatures.values()) + conservative
    unreachable_removed = 0
    if empty_profiles:
        if retained:
            unreachable_removed = len(empty_profiles)
        else:
            retained.append(empty_profiles[0])
            unreachable_removed = len(empty_profiles) - 1

    retained.sort(key=_profile_key)
    equivalent_removed = candidates - len(retained) - unreachable_removed
    return ConfigReductionResult(
        tuple(retained),
        ConfigReductionStats(
            candidates,
            len(retained),
            max(0, equivalent_removed),
            unreachable_removed,
        ),
    )


__all__ = [
    "ConfigReductionStats",
    "ConfigReductionResult",
    "reduce_generated_profiles",
]
