"""Rule-neutral semantic models for embedded trust boundaries.

The model layer deliberately describes only call semantics.  It does not infer
platform behavior from function names and it does not mutate CFG/dataflow
facts.  Rules and future dataflow passes can query the same per-TU session and
apply the declared provenance/validation requirements conservatively.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, Iterable, Mapping, Optional, Tuple

from .cfg.model import CFGCall


class ValidationProperty(str, Enum):
    BOUNDS_CHECKED = "bounds_checked"
    AUTHENTICATED = "authenticated"
    SIGNATURE_VERIFIED = "signature_verified"
    AUTHORIZED = "authorized"
    VERSION_CHECKED = "version_checked"


class SemanticLocationKind(str, Enum):
    RETURN = "return"
    ARGUMENT = "argument"
    OUTPUT_ARGUMENT = "output_argument"


@dataclass(frozen=True)
class SemanticLocation:
    """A value/location participating in a modeled call.

    ``argument`` and ``output_argument`` use zero-based C argument indexes.
    ``output_argument`` denotes the object written through an output pointer,
    while ``argument`` denotes the argument value itself.
    """

    kind: SemanticLocationKind
    argument_index: Optional[int] = None

    def __post_init__(self) -> None:
        if self.kind is SemanticLocationKind.RETURN:
            if self.argument_index is not None:
                raise ValueError("return location cannot have an argument index")
            return
        if self.argument_index is None or self.argument_index < 0:
            raise ValueError(f"{self.kind.value} requires a non-negative argument index")

    @classmethod
    def parse(cls, value: str) -> "SemanticLocation":
        text = str(value).strip().lower()
        if text == "return":
            return cls(SemanticLocationKind.RETURN)
        for prefix, kind in (
            ("arg:", SemanticLocationKind.ARGUMENT),
            ("out:", SemanticLocationKind.OUTPUT_ARGUMENT),
        ):
            if text.startswith(prefix):
                raw_index = text[len(prefix):]
                if not raw_index.isdigit():
                    raise ValueError(f"invalid semantic location '{value}'")
                return cls(kind, int(raw_index))
        raise ValueError(
            f"invalid semantic location '{value}'; expected 'return', 'arg:N', or 'out:N'"
        )


class SuccessConditionKind(str, Enum):
    RETURN_ZERO = "return_zero"
    RETURN_NONZERO = "return_nonzero"
    RETURN_EQUALS = "return_equals"


@dataclass(frozen=True)
class SuccessCondition:
    kind: SuccessConditionKind
    value: Optional[int] = None

    def __post_init__(self) -> None:
        if self.kind is SuccessConditionKind.RETURN_EQUALS:
            if self.value is None:
                raise ValueError("return_equals success condition requires an integer value")
        elif self.value is not None:
            raise ValueError(f"{self.kind.value} does not accept a comparison value")

    @classmethod
    def parse(cls, value: object) -> "SuccessCondition":
        if isinstance(value, str):
            try:
                return cls(SuccessConditionKind(value.strip().lower()))
            except ValueError as exc:
                raise ValueError(
                    "unsupported success condition; expected return_zero, return_nonzero, "
                    "or { return_equals = INTEGER }"
                ) from exc
        if isinstance(value, Mapping) and set(value) == {"return_equals"}:
            raw = value["return_equals"]
            if isinstance(raw, bool) or not isinstance(raw, int):
                raise ValueError("return_equals success value must be an integer")
            return cls(SuccessConditionKind.RETURN_EQUALS, raw)
        raise ValueError(
            "unsupported success condition; expected return_zero, return_nonzero, "
            "or { return_equals = INTEGER }"
        )


@dataclass(frozen=True)
class SourceModel:
    function: str
    outputs: Tuple[SemanticLocation, ...]

    def __post_init__(self) -> None:
        _validate_function_name(self.function)
        if not self.outputs:
            raise ValueError("source model must declare at least one output location")


@dataclass(frozen=True)
class ValidatorModel:
    function: str
    target: SemanticLocation
    property: ValidationProperty
    success: SuccessCondition

    def __post_init__(self) -> None:
        _validate_function_name(self.function)


@dataclass(frozen=True)
class SinkRequirement:
    location: SemanticLocation
    properties: FrozenSet[ValidationProperty]

    def __post_init__(self) -> None:
        if not self.properties:
            raise ValueError("sink requirement must declare at least one validation property")


@dataclass(frozen=True)
class SinkModel:
    function: str
    requirements: Tuple[SinkRequirement, ...]

    def __post_init__(self) -> None:
        _validate_function_name(self.function)
        if not self.requirements:
            raise ValueError("sink model must declare at least one requirement")


@dataclass(frozen=True)
class CallSemanticModel:
    source: Optional[SourceModel] = None
    validator: Optional[ValidatorModel] = None
    sink: Optional[SinkModel] = None

    @property
    def is_modeled(self) -> bool:
        return self.source is not None or self.validator is not None or self.sink is not None


@dataclass(frozen=True)
class SemanticModelRegistry:
    """Immutable lookup registry shared by analyses in one scan/session."""

    sources: Mapping[str, SourceModel] = field(default_factory=dict)
    validators: Mapping[str, ValidatorModel] = field(default_factory=dict)
    sinks: Mapping[str, SinkModel] = field(default_factory=dict)

    def for_function(self, function: Optional[str]) -> CallSemanticModel:
        if not function:
            return CallSemanticModel()
        return CallSemanticModel(
            source=self.sources.get(function),
            validator=self.validators.get(function),
            sink=self.sinks.get(function),
        )

    def for_call(self, call: CFGCall) -> CallSemanticModel:
        # Indirect/unresolved calls are intentionally never trusted by spelling.
        if call.is_indirect or not call.direct_callee:
            return CallSemanticModel()
        return self.for_function(call.direct_callee)

    def source_for(self, call: CFGCall) -> Optional[SourceModel]:
        return self.for_call(call).source

    def validator_for(self, call: CFGCall) -> Optional[ValidatorModel]:
        return self.for_call(call).validator

    def sink_for(self, call: CFGCall) -> Optional[SinkModel]:
        return self.for_call(call).sink


EMPTY_SEMANTIC_MODELS = SemanticModelRegistry()


@dataclass(frozen=True)
class TUAnalysisSession:
    """Shared per-translation-unit analysis state.

    Rules should query ``semantic_models`` through this object rather than
    reparsing project configuration.  Additional shared TU facts can be added
    here without changing the semantic-model contract.
    """

    ast_context: object
    semantic_models: SemanticModelRegistry = EMPTY_SEMANTIC_MODELS

    @classmethod
    def from_config(cls, ast_context: object, config: object) -> "TUAnalysisSession":
        registry = getattr(config, "semantic_models", EMPTY_SEMANTIC_MODELS)
        if not isinstance(registry, SemanticModelRegistry):
            registry = EMPTY_SEMANTIC_MODELS
        return cls(ast_context=ast_context, semantic_models=registry)

    def model_for_call(self, call: CFGCall) -> CallSemanticModel:
        return self.semantic_models.for_call(call)


class SemanticModelConfigError(ValueError):
    pass


def parse_semantic_models(raw: object) -> SemanticModelRegistry:
    """Parse the ``[semantic_models]`` TOML section."""

    if raw in (None, {}):
        return EMPTY_SEMANTIC_MODELS
    if not isinstance(raw, Mapping):
        raise SemanticModelConfigError("[semantic_models] must be a table")

    unknown = set(raw) - {"sources", "validators", "sinks"}
    if unknown:
        raise SemanticModelConfigError(
            f"unknown [semantic_models] key(s): {', '.join(sorted(str(k) for k in unknown))}"
        )

    sources: Dict[str, SourceModel] = {}
    validators: Dict[str, ValidatorModel] = {}
    sinks: Dict[str, SinkModel] = {}

    for entry in _model_entries(raw, "sources"):
        _require_keys(entry, "source", required={"function", "outputs"})
        function = _function(entry["function"], "source")
        outputs_raw = entry["outputs"]
        if not isinstance(outputs_raw, list) or not outputs_raw:
            raise SemanticModelConfigError(f"source '{function}' outputs must be a non-empty list")
        try:
            outputs = []
            seen_locations = set()
            for output_raw in outputs_raw:
                location = SemanticLocation.parse(output_raw)
                if location in seen_locations:
                    raise ValueError(f"duplicate output location '{output_raw}'")
                seen_locations.add(location)
                outputs.append(location)
            model = SourceModel(function, tuple(outputs))
        except ValueError as exc:
            raise SemanticModelConfigError(f"source '{function}': {exc}") from exc
        _insert_unique(sources, function, model, "source")

    for entry in _model_entries(raw, "validators"):
        _require_keys(
            entry,
            "validator",
            required={"function", "target", "property", "success"},
        )
        function = _function(entry["function"], "validator")
        try:
            target = SemanticLocation.parse(entry["target"])
            prop = ValidationProperty(str(entry["property"]).strip().lower())
            success = SuccessCondition.parse(entry["success"])
            model = ValidatorModel(function, target, prop, success)
        except ValueError as exc:
            raise SemanticModelConfigError(f"validator '{function}': {exc}") from exc
        _insert_unique(validators, function, model, "validator")

    for entry in _model_entries(raw, "sinks"):
        _require_keys(entry, "sink", required={"function", "requirements"})
        function = _function(entry["function"], "sink")
        req_raw = entry["requirements"]
        if not isinstance(req_raw, Mapping) or not req_raw:
            raise SemanticModelConfigError(
                f"sink '{function}' requirements must be a non-empty location-to-properties table"
            )
        requirements = []
        seen_locations = set()
        for location_raw, properties_raw in req_raw.items():
            if not isinstance(properties_raw, list) or not properties_raw:
                raise SemanticModelConfigError(
                    f"sink '{function}' requirement '{location_raw}' must be a non-empty list"
                )
            try:
                location = SemanticLocation.parse(str(location_raw))
                if location in seen_locations:
                    raise ValueError(f"duplicate requirement for location '{location_raw}'")
                seen_locations.add(location)
                properties = frozenset(
                    ValidationProperty(str(prop).strip().lower()) for prop in properties_raw
                )
                requirements.append(SinkRequirement(location, properties))
            except ValueError as exc:
                raise SemanticModelConfigError(f"sink '{function}': {exc}") from exc
        _insert_unique(sinks, function, SinkModel(function, tuple(requirements)), "sink")

    return SemanticModelRegistry(sources=sources, validators=validators, sinks=sinks)


def _model_entries(raw: Mapping[object, object], key: str) -> Iterable[Mapping[object, object]]:
    entries = raw.get(key, [])
    if entries == []:
        return ()
    if not isinstance(entries, list):
        raise SemanticModelConfigError(f"[semantic_models].{key} must be an array of tables")
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise SemanticModelConfigError(
                f"[semantic_models].{key}[{index}] must be a table"
            )
    return entries


def _require_keys(
    entry: Mapping[object, object],
    kind: str,
    *,
    required: set[str],
) -> None:
    keys = {str(k) for k in entry}
    missing = required - keys
    unknown = keys - required
    if missing:
        raise SemanticModelConfigError(
            f"{kind} model missing required key(s): {', '.join(sorted(missing))}"
        )
    if unknown:
        raise SemanticModelConfigError(
            f"{kind} model has unknown key(s): {', '.join(sorted(unknown))}"
        )


def _function(value: object, kind: str) -> str:
    function = str(value).strip()
    try:
        _validate_function_name(function)
    except ValueError as exc:
        raise SemanticModelConfigError(f"invalid {kind} function '{value}'") from exc
    return function


def _validate_function_name(function: str) -> None:
    if not function or not function.isidentifier():
        raise ValueError(f"invalid C function identifier '{function}'")


def _insert_unique(target: Dict[str, object], function: str, model: object, kind: str) -> None:
    if function in target:
        raise SemanticModelConfigError(f"duplicate {kind} model for function '{function}'")
    target[function] = model
