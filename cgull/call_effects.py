"""Declarative call-effect models shared by CFG analyses.

The model deliberately describes effects rather than rule policy. Built-ins
cover C/POSIX functions historically hard-coded by CFG summary logic; project
models replace built-ins by function name.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Mapping, Optional, Tuple


class CallEffectConfigError(ValueError):
    """Raised for malformed or contradictory call-effect definitions."""


class ReturnEffect(str, Enum):
    NONE = "none"
    ALLOCATION = "allocation"


@dataclass(frozen=True)
class CallEffectModel:
    function: str
    return_effect: ReturnEffect = ReturnEffect.NONE
    deallocates: FrozenSet[int] = frozenset()
    output_parameters: FrozenSet[int] = frozenset()
    format_argument: Optional[int] = None
    size_relationships: Tuple[Tuple[int, int], ...] = ()
    sanitizes: FrozenSet[int] = frozenset()

    def __post_init__(self) -> None:
        if not self.function or not self.function.isidentifier():
            raise ValueError(f"invalid C function identifier '{self.function}'")
        indexes = set(self.deallocates) | set(self.output_parameters) | set(self.sanitizes)
        if self.format_argument is not None:
            indexes.add(self.format_argument)
        for data_index, size_index in self.size_relationships:
            indexes.add(data_index)
            indexes.add(size_index)
        if any(isinstance(index, bool) or not isinstance(index, int) or index < 0 for index in indexes):
            raise ValueError("argument positions must be non-negative integers")
        contradictory = self.deallocates & self.output_parameters
        if contradictory:
            positions = ", ".join(str(i) for i in sorted(contradictory))
            raise ValueError(
                f"argument position(s) {positions} cannot be both deallocated and output parameters"
            )
        contradictory = self.deallocates & self.sanitizes
        if contradictory:
            positions = ", ".join(str(i) for i in sorted(contradictory))
            raise ValueError(
                f"argument position(s) {positions} cannot be both deallocated and sanitized"
            )


@dataclass(frozen=True)
class CallEffectRegistry:
    effects: Mapping[str, CallEffectModel]

    def for_function(self, function: Optional[str]) -> Optional[CallEffectModel]:
        return self.effects.get(function) if function else None

    def merged(self, overrides: Mapping[str, CallEffectModel]) -> "CallEffectRegistry":
        merged = dict(self.effects)
        merged.update(overrides)
        return CallEffectRegistry(effects=dict(sorted(merged.items())))


def _effect(function: str, **kwargs) -> CallEffectModel:
    return CallEffectModel(function=function, **kwargs)


_BUILTIN_EFFECTS = {
    model.function: model
    for model in (
        _effect("malloc", return_effect=ReturnEffect.ALLOCATION, size_relationships=((0, 0),)),
        _effect("calloc", return_effect=ReturnEffect.ALLOCATION, size_relationships=((0, 1),)),
        _effect("realloc", return_effect=ReturnEffect.ALLOCATION, deallocates=frozenset({0}), size_relationships=((0, 1),)),
        _effect("aligned_alloc", return_effect=ReturnEffect.ALLOCATION, size_relationships=((0, 1),)),
        _effect("strdup", return_effect=ReturnEffect.ALLOCATION),
        _effect("strndup", return_effect=ReturnEffect.ALLOCATION, size_relationships=((0, 1),)),
        _effect("valloc", return_effect=ReturnEffect.ALLOCATION, size_relationships=((0, 0),)),
        _effect("pvalloc", return_effect=ReturnEffect.ALLOCATION, size_relationships=((0, 0),)),
        _effect("memalign", return_effect=ReturnEffect.ALLOCATION, size_relationships=((0, 1),)),
        _effect("free", deallocates=frozenset({0})),
        _effect("cfree", deallocates=frozenset({0})),
        _effect("vfree", deallocates=frozenset({0})),
        _effect("scanf", format_argument=0, output_parameters=frozenset({1})),
        _effect("sscanf", format_argument=1, output_parameters=frozenset({2})),
        _effect("fscanf", format_argument=1, output_parameters=frozenset({2})),
        _effect("read", output_parameters=frozenset({1}), size_relationships=((1, 2),)),
        _effect("recv", output_parameters=frozenset({1}), size_relationships=((1, 2),)),
        _effect("recvfrom", output_parameters=frozenset({1}), size_relationships=((1, 2),)),
    )
}

BUILTIN_CALL_EFFECTS = CallEffectRegistry(effects=dict(sorted(_BUILTIN_EFFECTS.items())))


def parse_call_effects(raw: object) -> CallEffectRegistry:
    """Parse project overrides and merge them over the built-in registry."""
    if raw in (None, []):
        return BUILTIN_CALL_EFFECTS
    if not isinstance(raw, list):
        raise CallEffectConfigError("[semantic_models].effects must be an array of tables")

    overrides: Dict[str, CallEffectModel] = {}
    allowed = {
        "function", "returns", "deallocates", "outputs", "format_argument",
        "size_relationships", "sanitizes",
    }
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise CallEffectConfigError(f"[semantic_models].effects[{index}] must be a table")
        keys = {str(k) for k in entry}
        unknown = keys - allowed
        if unknown:
            raise CallEffectConfigError(
                f"call effect model has unknown key(s): {', '.join(sorted(unknown))}"
            )
        if "function" not in entry:
            raise CallEffectConfigError("call effect model missing required key: function")
        function = str(entry["function"]).strip()
        if function in overrides:
            raise CallEffectConfigError(f"duplicate call effect model for function '{function}'")
        try:
            returns = ReturnEffect(str(entry.get("returns", "none")).strip().lower())
            deallocates = _indexes(entry.get("deallocates", []), "deallocates")
            outputs = _indexes(entry.get("outputs", []), "outputs")
            sanitizes = _indexes(entry.get("sanitizes", []), "sanitizes")
            fmt = entry.get("format_argument")
            if fmt is not None and (isinstance(fmt, bool) or not isinstance(fmt, int) or fmt < 0):
                raise ValueError("format_argument must be a non-negative integer")
            relationships_raw = entry.get("size_relationships", [])
            if not isinstance(relationships_raw, list):
                raise ValueError("size_relationships must be a list of [data_arg, size_arg] pairs")
            relationships = []
            for pair in relationships_raw:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise ValueError("size_relationships entries must be [data_arg, size_arg] pairs")
                if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in pair):
                    raise ValueError("size_relationship argument positions must be non-negative integers")
                relationships.append((pair[0], pair[1]))
            overrides[function] = CallEffectModel(
                function=function,
                return_effect=returns,
                deallocates=deallocates,
                output_parameters=outputs,
                format_argument=fmt,
                size_relationships=tuple(relationships),
                sanitizes=sanitizes,
            )
        except ValueError as exc:
            raise CallEffectConfigError(f"call effect '{function}': {exc}") from exc
    return BUILTIN_CALL_EFFECTS.merged(overrides)


def _indexes(raw: object, name: str) -> FrozenSet[int]:
    if not isinstance(raw, list):
        raise ValueError(f"{name} must be a list of argument positions")
    result = set()
    for value in raw:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must contain non-negative integer argument positions")
        if value in result:
            raise ValueError(f"{name} contains duplicate argument position {value}")
        result.add(value)
    return frozenset(result)
