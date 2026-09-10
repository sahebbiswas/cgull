"""Reduce generated configuration profiles by modeled branch behavior."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from ..models import ConfigProfile
from .configuration_space import WitnessStatus, derive_branch_witnesses
from .directives import parse_conditional_directives
from .expressions import Defined, Expression, Predicate, Variable, expression_atoms
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


@dataclass(frozen=True)
class _BranchModel:
    source_index: int
    offset: int
    bdd: BDD
    root: int


def _flags_key(profile: ConfigProfile) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(key), repr(value)) for key, value in profile.flags.items()))


def _profile_key(profile: ConfigProfile) -> tuple:
    return (_flags_key(profile), profile.name)


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


def _atom_value(atom, flags: Mapping[str, Any]) -> bool | None:
    if isinstance(atom, Defined):
        return atom.name in flags and flags[atom.name] is not False
    if isinstance(atom, Variable):
        return _known_macro_value(flags, atom.name)
    if isinstance(atom, Predicate):
        # Opaque value-bearing conditions remain free symbolic predicates.
        return None
    return None


def _branch_possible(model: _BranchModel, profile: ConfigProfile) -> bool:
    """Evaluate a profile as a partial assignment over one compiled BDD.

    Known macro atoms follow one edge. Opaque/unknown atoms existentially follow
    either edge, answering whether the modeled branch can be active without
    inventing a concrete integer value for an opaque predicate.
    """

    memo: dict[int, bool] = {0: False, 1: True}

    def possible(node: int) -> bool:
        cached = memo.get(node)
        if cached is not None:
            return cached
        item = model.bdd.nodes[node]
        assert item is not None
        variable, low, high = item
        value = _atom_value(model.bdd.atoms[variable], profile.flags)
        if value is None:
            result = possible(low) or possible(high)
        else:
            result = possible(high if value else low)
        memo[node] = result
        return result

    return possible(model.root)


def _duplicate_only_result(
    ordered_profiles: Sequence[ConfigProfile],
) -> ConfigReductionResult:
    """Conservatively collapse only identical effective flag maps."""

    seen_flags: set[tuple[tuple[str, str], ...]] = set()
    retained: list[ConfigProfile] = []
    for profile in ordered_profiles:
        key = _flags_key(profile)
        if key in seen_flags:
            continue
        seen_flags.add(key)
        retained.append(profile)
    candidates = len(ordered_profiles)
    removed = candidates - len(retained)
    return ConfigReductionResult(
        tuple(retained),
        ConfigReductionStats(candidates, len(retained), removed, 0),
    )


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
    Each effective branch condition is compiled to a BDD once and reused for all
    profiles. Opaque predicates remain free Boolean atoms. If malformed structure
    or a resource limit prevents a safe equivalence proof, reduction falls back
    to exact flag-map deduplication rather than dropping a potentially distinct
    generated variant.

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
            if (
                witness.status is WitnessStatus.SATISFIABLE
                and witness.effective_condition is not None
            ):
                branch_expressions.append(
                    (
                        source_index,
                        witness.branch.directive.source_range.start.offset,
                        witness.effective_condition,
                    )
                )

    if unsafe or not branch_expressions:
        return _duplicate_only_result(ordered_profiles)

    models: list[_BranchModel] = []
    try:
        for source_index, offset, expression in branch_expressions:
            bdd = BDD(expression_atoms(expression), limits=limits)
            models.append(_BranchModel(source_index, offset, bdd, bdd.build(expression)))
    except AnalysisLimitExceeded:
        return _duplicate_only_result(ordered_profiles)

    signatures: dict[tuple[tuple[int, int], ...], ConfigProfile] = {}
    empty_profiles: list[ConfigProfile] = []

    for profile in ordered_profiles:
        active = tuple(
            (model.source_index, model.offset)
            for model in models
            if _branch_possible(model, profile)
        )
        if not active:
            empty_profiles.append(profile)
            continue
        signatures.setdefault(active, profile)

    retained = list(signatures.values())
    # An empty signature is still a valid configuration: it scans unconditional
    # source while activating no modeled conditional branch. Keep one stable
    # representative of that equivalence class so unconditional-vs-conditional
    # finding attribution remains meaningful after reduction.
    if empty_profiles:
        retained.append(empty_profiles[0])

    retained.sort(key=_profile_key)
    unreachable_removed = 0
    equivalent_removed = candidates - len(retained)
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
