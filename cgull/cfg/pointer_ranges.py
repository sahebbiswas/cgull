"""Rule-neutral pointer origin, offset, and accessible-range facts.

This domain is intentionally conservative. It records a symbolic pointer
origin, a relative byte offset from that origin, the pointer element stride,
and the bytes that are proven accessible immediately before/after the current
pointer value. Unknown or unsupported transformations discard accessibility
proofs rather than manufacturing safety.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Dict, Mapping, Optional, Tuple

from pycparser import c_ast

from .construction import find_function_def
from .size_facts import SizeFact
from .value_facts import ValueProvenance, _canonical_location, join_provenance


class PointerProvenance(str, Enum):
    LOCAL_OBJECT = "local_object"
    ALLOCATION = "allocation"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OffsetInterval:
    lower: Optional[int] = None
    upper: Optional[int] = None

    @classmethod
    def exact(cls, value: int) -> "OffsetInterval":
        value = int(value)
        return cls(value, value)

    @property
    def is_exact(self) -> bool:
        return self.lower is not None and self.lower == self.upper

    @property
    def exact_value(self) -> Optional[int]:
        return self.lower if self.is_exact else None

    @property
    def is_unknown(self) -> bool:
        return self.lower is None or self.upper is None

    def shifted(self, amount: int) -> "OffsetInterval":
        if self.is_unknown:
            return OffsetInterval()
        return OffsetInterval(self.lower + amount, self.upper + amount)


@dataclass(frozen=True)
class PointerRangeFact:
    origin: Optional[str] = None
    offset: OffsetInterval = OffsetInterval()
    lower_bound: Optional[int] = None
    upper_bound: Optional[int] = None
    element_width: Optional[int] = None
    provenance: PointerProvenance = PointerProvenance.UNKNOWN
    value_provenance: ValueProvenance = ValueProvenance.UNKNOWN
    degradations: frozenset[str] = frozenset()

    @classmethod
    def object(
        cls,
        origin: str,
        extent: int,
        *,
        element_width: int = 1,
    ) -> "PointerRangeFact":
        extent = max(0, int(extent))
        return cls(
            origin=_canonical_location(origin),
            offset=OffsetInterval.exact(0),
            lower_bound=0,
            upper_bound=extent,
            element_width=max(1, int(element_width)),
            provenance=PointerProvenance.LOCAL_OBJECT,
            value_provenance=ValueProvenance.TRUSTED,
        )

    @property
    def is_unknown(self) -> bool:
        return self.origin is None and self.offset.is_unknown

    @property
    def has_accessible_range(self) -> bool:
        return self.lower_bound is not None and self.upper_bound is not None

    def shifted(self, amount: int) -> "PointerRangeFact":
        """Shift by a byte amount while preserving only already-proven range."""
        amount = int(amount)
        new_offset = self.offset.shifted(amount)
        if self.lower_bound is None or self.upper_bound is None:
            return replace(self, offset=new_offset)

        if amount < -self.lower_bound or amount > self.upper_bound:
            return replace(
                self,
                offset=new_offset,
                lower_bound=None,
                upper_bound=None,
                degradations=self.degradations | {"OUTSIDE_PROVEN_RANGE"},
            )
        return replace(
            self,
            offset=new_offset,
            lower_bound=self.lower_bound + amount,
            upper_bound=self.upper_bound - amount,
        )

    def shifted_elements(self, count: int) -> "PointerRangeFact":
        """Shift by C pointer elements, degrading if the element width is unknown."""
        if self.element_width is None:
            return self.unknown_offset("UNKNOWN_ELEMENT_WIDTH")
        return self.shifted(int(count) * self.element_width)

    def unknown_offset(self, reason: str = "UNKNOWN_OFFSET") -> "PointerRangeFact":
        return replace(
            self,
            offset=OffsetInterval(),
            lower_bound=None,
            upper_bound=None,
            degradations=self.degradations | {reason},
        )


def join_pointer_facts(left: PointerRangeFact, right: PointerRangeFact) -> PointerRangeFact:
    """Join reachable paths without strengthening any safety proof."""
    if left == right:
        return left
    same_origin = left.origin is not None and left.origin == right.origin
    if same_origin and not left.offset.is_unknown and not right.offset.is_unknown:
        offset = OffsetInterval(
            min(left.offset.lower, right.offset.lower),
            max(left.offset.upper, right.offset.upper),
        )
    else:
        offset = OffsetInterval()

    lower = (
        min(left.lower_bound, right.lower_bound)
        if same_origin and left.lower_bound is not None and right.lower_bound is not None
        else None
    )
    upper = (
        min(left.upper_bound, right.upper_bound)
        if same_origin and left.upper_bound is not None and right.upper_bound is not None
        else None
    )
    provenance = (
        left.provenance
        if same_origin and left.provenance is right.provenance
        else PointerProvenance.UNKNOWN
    )
    element_width = (
        left.element_width
        if same_origin and left.element_width == right.element_width
        else None
    )
    return PointerRangeFact(
        origin=left.origin if same_origin else None,
        offset=offset,
        lower_bound=lower,
        upper_bound=upper,
        element_width=element_width,
        provenance=provenance,
        value_provenance=join_provenance(
            left.value_provenance, right.value_provenance
        ),
        degradations=left.degradations | right.degradations,
    )


class PointerRangeFunctionResult:
    def __init__(self, snapshots: Mapping[int, Mapping[str, PointerRangeFact]]) -> None:
        self._snapshots = {line: dict(facts) for line, facts in snapshots.items()}

    def query(self, location: str, line: Optional[int] = None) -> PointerRangeFact:
        """Return the latest fact recorded no later than ``line``."""
        location = _canonical_location(location)
        if not self._snapshots:
            return PointerRangeFact()
        if line is None:
            line = max(self._snapshots)
        eligible = [candidate for candidate in self._snapshots if candidate <= line]
        if not eligible:
            return PointerRangeFact()
        return self._snapshots[max(eligible)].get(location, PointerRangeFact())


@dataclass(frozen=True)
class TranslationUnitPointerRangeResult:
    function_results: Mapping[str, PointerRangeFunctionResult]

    def function(self, name: str) -> Optional[PointerRangeFunctionResult]:
        return self.function_results.get(name)

    def query(
        self, function: str, location: str, line: Optional[int] = None
    ) -> PointerRangeFact:
        result = self.function(function)
        return result.query(location, line) if result is not None else PointerRangeFact()


@dataclass
class _State:
    facts: Dict[str, PointerRangeFact]

    def copy(self) -> "_State":
        return _State(dict(self.facts))


def analyze_translation_unit_pointer_ranges(
    ast_ctx,
    *,
    size_analysis=None,
    value_analysis=None,
) -> TranslationUnitPointerRangeResult:
    """Build conservative intraprocedural pointer facts for every function."""
    results: Dict[str, PointerRangeFunctionResult] = {}
    for fn in getattr(ast_ctx, "functions", ()):
        name = getattr(fn, "name", None)
        if not name:
            continue
        funcdef = find_function_def(getattr(ast_ctx, "pycparser_ast", None), name)
        if funcdef is None:
            continue
        params = tuple(p.name for p in fn.parameters if p.name)
        state = _State({})
        extents = (
            getattr(size_analysis, "parameter_extents", {}).get(name, ())
            if size_analysis
            else ()
        )
        values = (
            getattr(value_analysis, "parameter_facts", {}).get(name, ())
            if value_analysis
            else ()
        )
        parameter_widths = _parameter_element_widths(funcdef)
        for index, param in enumerate(params):
            canonical = _canonical_location(param)
            extent = extents[index] if index < len(extents) else SizeFact()
            value = values[index] if index < len(values) else None
            vp = getattr(value, "provenance", ValueProvenance.UNKNOWN)
            provenance = (
                PointerProvenance.EXTERNAL
                if vp is ValueProvenance.UNTRUSTED
                else PointerProvenance.UNKNOWN
            )
            element_width = parameter_widths.get(param)
            if extent.exact_value is not None:
                state.facts[canonical] = PointerRangeFact(
                    origin=canonical,
                    offset=OffsetInterval.exact(0),
                    lower_bound=0,
                    upper_bound=extent.exact_value,
                    element_width=element_width,
                    provenance=provenance,
                    value_provenance=vp,
                )
            elif provenance is PointerProvenance.EXTERNAL:
                state.facts[canonical] = PointerRangeFact(
                    origin=canonical,
                    offset=OffsetInterval.exact(0),
                    element_width=element_width,
                    provenance=provenance,
                    value_provenance=vp,
                )
        snapshots: Dict[int, Dict[str, PointerRangeFact]] = {}
        _analyze_statement(funcdef.body, state, snapshots)
        results[name] = PointerRangeFunctionResult(snapshots)
    return TranslationUnitPointerRangeResult(dict(sorted(results.items())))


def _record(node, state: _State, snapshots) -> None:
    coord = getattr(node, "coord", None)
    line = getattr(coord, "line", 0) or 0
    if line:
        snapshots[line] = dict(state.facts)


def _analyze_statement(node, state: _State, snapshots) -> _State:
    if node is None:
        return state
    if isinstance(node, c_ast.Compound):
        current = state
        for item in list(node.block_items or ()):
            current = _analyze_statement(item, current, snapshots)
        return current
    if isinstance(node, c_ast.DeclList):
        current = state
        for decl in node.decls or ():
            current = _analyze_statement(decl, current, snapshots)
        return current
    if isinstance(node, c_ast.Decl):
        _transfer_decl(node, state)
        _record(node, state, snapshots)
        return state
    if isinstance(node, c_ast.Assignment):
        _transfer_assignment(node, state)
        _record(node, state, snapshots)
        return state
    if isinstance(node, c_ast.If):
        left = _analyze_statement(node.iftrue, state.copy(), snapshots)
        right = (
            _analyze_statement(node.iffalse, state.copy(), snapshots)
            if node.iffalse
            else state.copy()
        )
        joined = _join_states(left, right)
        _record(node, joined, snapshots)
        return joined
    if isinstance(node, (c_ast.While, c_ast.DoWhile, c_ast.For)):
        if isinstance(node, c_ast.For) and node.init is not None:
            state = _analyze_statement(node.init, state, snapshots)
        entry = state.copy()
        current = entry.copy()
        converged = False
        unstable = set()
        for _ in range(8):
            previous = current
            body = _analyze_statement(node.stmt, current.copy(), snapshots)
            if isinstance(node, c_ast.For) and isinstance(node.next, c_ast.Assignment):
                _transfer_assignment(node.next, body)
            joined = _join_states(entry, body)
            unstable = {
                key
                for key in set(previous.facts) | set(joined.facts)
                if previous.facts.get(key) != joined.facts.get(key)
            }
            current = joined
            if not unstable:
                converged = True
                break
        if not converged:
            for key in unstable:
                fact = current.facts.get(key)
                if fact is not None:
                    current.facts[key] = fact.unknown_offset("LOOP_NOT_CONVERGED")
        _record(node, current, snapshots)
        return current
    _record(node, state, snapshots)
    return state


def _join_states(left: _State, right: _State) -> _State:
    facts: Dict[str, PointerRangeFact] = {}
    for key in set(left.facts) | set(right.facts):
        if key in left.facts and key in right.facts:
            facts[key] = join_pointer_facts(left.facts[key], right.facts[key])
        else:
            facts[key] = PointerRangeFact(
                degradations=frozenset({"PATH_INCOMPLETE"})
            )
    return _State(facts)


def _transfer_decl(node: c_ast.Decl, state: _State) -> None:
    name = getattr(node, "name", None)
    if not name:
        return
    canonical = _canonical_location(name)
    extent, width = _array_extent_and_width(getattr(node, "type", None))
    if extent is not None:
        state.facts[canonical] = PointerRangeFact.object(
            canonical, extent, element_width=width
        )
        return
    if node.init is None:
        return
    fact = _expression_fact(node.init, state)
    declared_width = _pointer_element_width(getattr(node, "type", None))
    if declared_width is not None and fact.origin is not None:
        fact = replace(fact, element_width=declared_width)
    state.facts[canonical] = fact


def _transfer_assignment(node: c_ast.Assignment, state: _State) -> None:
    target = _location(node.lvalue)
    if not target:
        return
    target = _canonical_location(target)
    if node.op in {"+=", "-="}:
        old = state.facts.get(target, PointerRangeFact())
        amount = _constant_int(node.rvalue)
        if amount is None:
            state.facts[target] = old.unknown_offset("UNSUPPORTED_ARITHMETIC")
        else:
            count = amount if node.op == "+=" else -amount
            state.facts[target] = old.shifted_elements(count)
        return
    state.facts[target] = _expression_fact(node.rvalue, state)


def _expression_fact(node, state: _State) -> PointerRangeFact:
    if node is None:
        return PointerRangeFact()
    if isinstance(node, c_ast.ID):
        return state.facts.get(_canonical_location(node.name), PointerRangeFact())
    if isinstance(node, c_ast.Cast):
        return _expression_fact(node.expr, state)
    if isinstance(node, c_ast.UnaryOp) and node.op == "&":
        return _expression_fact(node.expr, state)
    if isinstance(node, c_ast.ArrayRef):
        base = _expression_fact(node.name, state)
        index = _constant_int(node.subscript)
        if index is None:
            return base.unknown_offset("UNKNOWN_INDEX")
        return base.shifted_elements(index)
    if isinstance(node, c_ast.BinaryOp) and node.op in {"+", "-"}:
        base = _expression_fact(node.left, state)
        amount = _constant_int(node.right)
        if amount is None:
            return base.unknown_offset("UNSUPPORTED_ARITHMETIC")
        count = amount if node.op == "+" else -amount
        return base.shifted_elements(count)
    if isinstance(node, c_ast.FuncCall):
        callee = _location(node.name)
        if callee in {"malloc", "calloc", "realloc"}:
            args = list(getattr(getattr(node, "args", None), "exprs", ()) or ())
            extent = None
            if callee == "calloc" and len(args) >= 2:
                a, b = _constant_int(args[0]), _constant_int(args[1])
                extent = a * b if a is not None and b is not None else None
            elif args:
                extent = _constant_int(args[-1])
            coord = getattr(node, "coord", None)
            origin = f"allocation@{getattr(coord, 'line', 0) or 0}"
            return PointerRangeFact(
                origin=origin,
                offset=OffsetInterval.exact(0),
                lower_bound=0 if extent is not None else None,
                upper_bound=max(0, extent) if extent is not None else None,
                provenance=PointerProvenance.ALLOCATION,
                value_provenance=ValueProvenance.TRUSTED,
            )
    return PointerRangeFact(degradations=frozenset({"UNSUPPORTED_TRANSFORM"}))


_INTEGER_CONSTANT_TYPES = {
    "int",
    "long",
    "long int",
    "long long",
    "long long int",
    "signed",
    "signed int",
    "signed long",
    "signed long int",
    "signed long long",
    "signed long long int",
    "unsigned",
    "unsigned int",
    "unsigned long",
    "unsigned long int",
    "unsigned long long",
    "unsigned long long int",
}


def _constant_int(node) -> Optional[int]:
    if isinstance(node, c_ast.Constant) and node.type in _INTEGER_CONSTANT_TYPES:
        value = node.value.rstrip("uUlL")
        if not value:
            return None
        try:
            return int(value, 0)
        except ValueError:
            return None
    if isinstance(node, c_ast.UnaryOp) and node.op in {"+", "-"}:
        value = _constant_int(node.expr)
        if value is not None:
            return value if node.op == "+" else -value
    return None


def _location(node) -> Optional[str]:
    if isinstance(node, c_ast.ID):
        return node.name
    if isinstance(node, c_ast.StructRef):
        base = _location(node.name)
        field = getattr(node.field, "name", None)
        return f"{base}{node.type}{field}" if base and field else None
    return None


def _array_extent_and_width(type_node) -> Tuple[Optional[int], int]:
    node = type_node
    while isinstance(node, c_ast.TypeDecl):
        node = node.type
    if not isinstance(node, c_ast.ArrayDecl):
        return None, 1
    count = _constant_int(node.dim)
    width = _type_width(node.type)
    return (count * width if count is not None else None), width


def _pointer_element_width(type_node) -> Optional[int]:
    node = type_node
    while isinstance(node, c_ast.TypeDecl):
        node = node.type
    if isinstance(node, c_ast.PtrDecl):
        return _type_width(node.type)
    return None


def _parameter_element_widths(funcdef) -> Dict[str, int]:
    result: Dict[str, int] = {}
    args = getattr(getattr(funcdef.decl, "type", None), "args", None)
    for param in list(getattr(args, "params", ()) or ()):
        name = getattr(param, "name", None)
        width = _pointer_element_width(getattr(param, "type", None))
        if name and width is not None:
            result[name] = width
    return result


def _type_width(type_node) -> int:
    node = type_node
    while isinstance(node, c_ast.TypeDecl):
        node = node.type
    if isinstance(node, c_ast.PtrDecl):
        return 8
    if isinstance(node, c_ast.ArrayDecl):
        return _type_width(node.type)
    if isinstance(node, c_ast.IdentifierType):
        names = tuple(node.names or ())
        if "char" in names:
            return 1
        if "short" in names:
            return 2
        if "long" in names and names.count("long") > 1:
            return 8
        if "long" in names:
            return 8
        return 4
    return 1


__all__ = [
    "OffsetInterval",
    "PointerProvenance",
    "PointerRangeFact",
    "PointerRangeFunctionResult",
    "TranslationUnitPointerRangeResult",
    "analyze_translation_unit_pointer_ranges",
    "join_pointer_facts",
]
