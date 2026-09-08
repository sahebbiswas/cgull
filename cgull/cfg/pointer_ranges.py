"""Rule-neutral pointer origin, offset, and accessible-range facts.

This domain is intentionally conservative. It records a symbolic pointer
origin, a relative byte offset from that origin, the pointer element stride,
and the bytes that are proven accessible immediately before/after the current
pointer value. Unknown or unsupported transformations discard accessibility
proofs rather than manufacturing safety.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Dict, Mapping, Optional, Tuple

from pycparser import c_ast

from .construction import find_function_def
from .size_facts import SizeFact
from .pointer_guards import (
    GuardedInterval, invalidate_pointer_guards, join_guarded_intervals,
    refine_pointer_comparison, _volatile_type,
)
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
    validated_intervals: Tuple[Tuple[int, int], ...] = ()
    object_extent: Optional[int] = None
    guarded_intervals: Tuple[GuardedInterval, ...] = ()

    @property
    def proven_intervals(self) -> Tuple[Tuple[int, int], ...]:
        """Validator and enclosing-guard evidence, in origin-relative bytes."""
        return self.validated_intervals + tuple((p.lower, p.upper) for p in self.guarded_intervals)

    @property
    def backward_accessible_extent(self) -> Optional[int]:
        if not self.offset.is_exact:
            return self.lower_bound
        bounds = [self.offset.lower - p.lower for p in self.guarded_intervals
                  if p.lower <= self.offset.lower <= p.upper]
        if self.lower_bound is not None:
            bounds.append(self.lower_bound)
        return max(bounds) if bounds else None

    @property
    def forward_accessible_extent(self) -> Optional[int]:
        if not self.offset.is_exact:
            return self.upper_bound
        bounds = [p.upper - self.offset.lower for p in self.guarded_intervals
                  if p.lower <= self.offset.lower <= p.upper]
        if self.upper_bound is not None:
            bounds.append(self.upper_bound)
        return max(bounds) if bounds else None

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
            object_extent=extent,
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

    def definitely_outside(self, access_width: int = 0) -> bool:
        """Prove every possible offset violates the object interval.

        Width zero denotes formation, including the legal one-past address.
        Accessible capacities alone are lower guarantees, not object extents.
        """
        if self.object_extent is None or self.offset.is_unknown:
            return False
        return self.offset.upper < 0 or self.offset.lower + access_width > self.object_extent

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


def _intersect_intervals(
    left: Tuple[Tuple[int, int], ...],
    right: Tuple[Tuple[int, int], ...],
) -> Tuple[Tuple[int, int], ...]:
    """Keep only byte ranges validated on both reachable paths."""
    intersections = set()
    for left_start, left_end in left:
        for right_start, right_end in right:
            start = max(left_start, right_start)
            end = min(left_end, right_end)
            if start < end:
                intersections.add((start, end))
    return tuple(sorted(intersections))


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
        guarded_intervals=join_guarded_intervals(left.guarded_intervals, right.guarded_intervals) if same_origin else (),
        validated_intervals=(
            _intersect_intervals(left.validated_intervals, right.validated_intervals)
            if same_origin
            else ()
        ),
        origin=left.origin if same_origin else None,
        object_extent=left.object_extent if same_origin and left.object_extent == right.object_extent else None,
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
    def __init__(
        self,
        snapshots: Mapping[int, Mapping[str, PointerRangeFact]],
        final_facts: Optional[Mapping[str, PointerRangeFact]] = None,
        events=(),
    ) -> None:
        self.events = tuple(events)
        self._snapshots = {line: dict(facts) for line, facts in snapshots.items()}
        self._final_facts = dict(final_facts) if final_facts is not None else None

    def query(self, location: str, line: Optional[int] = None) -> PointerRangeFact:
        """Return the final fact, or the latest fact no later than ``line``."""
        location = _canonical_location(location)
        if line is None and self._final_facts is not None:
            return self._final_facts.get(location, PointerRangeFact())
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


@dataclass(frozen=True)
class PointerRangeEvent:
    node: object
    fact: PointerRangeFact
    access_width: Optional[int] = 0
    write: bool = False
    is_access: bool = False


class _Snapshots(dict):
    def __init__(self):
        super().__init__()
        self.events = []
        self.suppress_events = False
        self.semantic_models = None


@dataclass
class _State:
    facts: Dict[str, PointerRangeFact]
    typedefs: dict = field(default_factory=dict)
    types: dict = field(default_factory=dict)
    terminated: bool = False
    semantic_models: object = None
    constants: dict = field(default_factory=dict)

    def copy(self) -> "_State":
        return _State(dict(self.facts), dict(self.typedefs), dict(self.types), self.terminated, self.semantic_models, dict(self.constants))


def analyze_translation_unit_pointer_ranges(
    ast_ctx,
    *,
    size_analysis=None,
    value_analysis=None,
    semantic_models=None,
) -> TranslationUnitPointerRangeResult:
    """Build conservative intraprocedural pointer facts for every function."""
    results: Dict[str, PointerRangeFunctionResult] = {}
    typedefs = {n.name: n.type for n in ast_ctx.pycparser_ast.ext if isinstance(n, c_ast.Typedef)}

    class StructCollector(c_ast.NodeVisitor):
        def visit_FuncDef(self, node):
            return  # Function-local tags must not leak into other functions.

        def visit_Struct(self, node):
            if node.name and node.decls:
                typedefs["struct:" + node.name] = node
            self.generic_visit(node)

        def visit_Union(self, node):
            if node.name and node.decls:
                typedefs["union:" + node.name] = node
            self.generic_visit(node)

    StructCollector().visit(ast_ctx.pycparser_ast)

    for fn in getattr(ast_ctx, "functions", ()):
        name = getattr(fn, "name", None)
        if not name:
            continue
        funcdef = find_function_def(getattr(ast_ctx, "pycparser_ast", None), name)
        if funcdef is None:
            continue
        params = tuple(p.name for p in fn.parameters if p.name)
        state = _State({}, dict(typedefs))
        state.semantic_models = semantic_models
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
        for param in getattr(getattr(funcdef.decl.type, "args", None), "params", ()) or ():
            if getattr(param, "name", None):
                state.types[param.name] = _resolve_type(param.type, state.typedefs)
        parameter_widths = {param: _pointer_element_width(typ) for param, typ in state.types.items()}
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
            elif isinstance(_unwrap_type(state.types.get(param)), (c_ast.PtrDecl, c_ast.ArrayDecl)):
                state.facts[canonical] = PointerRangeFact(
                    origin=canonical,
                    offset=OffsetInterval.exact(0),
                    element_width=element_width,
                    provenance=provenance,
                    value_provenance=vp,
                )
        snapshots = _Snapshots()
        snapshots.semantic_models = semantic_models
        snapshots.suppress_events = not _supports_definite_events(funcdef, state.typedefs)
        final_state = _analyze_statement(funcdef.body, state, snapshots)
        results[name] = PointerRangeFunctionResult(snapshots, final_state.facts, snapshots.events)
    return TranslationUnitPointerRangeResult(dict(sorted(results.items())))


def _record(node, state: _State, snapshots) -> None:
    coord = getattr(node, "coord", None)
    line = getattr(coord, "line", 0) or 0
    if line:
        snapshots[line] = dict(state.facts)


def _analyze_statement(node, state: _State, snapshots) -> _State:
    if node is None or state.terminated:
        return state
    if isinstance(node, c_ast.Compound):
        current = state
        for item in list(node.block_items or ()):
            current = _analyze_statement(item, current, snapshots)
            if isinstance(item, (c_ast.Return, c_ast.Break, c_ast.Continue)):
                break
        return current
    if isinstance(node, c_ast.DeclList):
        current = state
        for decl in node.decls or ():
            current = _analyze_statement(decl, current, snapshots)
        return current
    if isinstance(node, c_ast.Typedef):
        state.typedefs[node.name] = node.type
        return state
    if isinstance(node, c_ast.Decl):
        _observe(node.init, state, snapshots)
        _transfer_decl(node, state)
        _record(node, state, snapshots)
        return state
    if isinstance(node, c_ast.Assignment):
        _observe(node, state, snapshots)
        _transfer_assignment(node, state)
        _record(node, state, snapshots)
        return state
    if isinstance(node, c_ast.UnaryOp) and node.op in {"p++", "p--", "++", "--"}:
        _observe(node, state, snapshots)
        _transfer_unary_update(node, state)
        _record(node, state, snapshots)
        return state
    if isinstance(node, c_ast.If):
        _observe(node.cond, state, snapshots)
        true_state, false_state = state.copy(), state.copy()
        _validate_condition(node.cond, true_state, snapshots.semantic_models, True)
        _validate_condition(node.cond, false_state, snapshots.semantic_models, False)
        left = _analyze_statement(node.iftrue, true_state, snapshots)
        right = (
            _analyze_statement(node.iffalse, false_state, snapshots)
            if node.iffalse
            else false_state
        )
        joined = _join_states(left, right)
        _record(node, joined, snapshots)
        return joined
    if isinstance(node, (c_ast.While, c_ast.DoWhile, c_ast.For)):
        if isinstance(node, c_ast.For) and node.init is not None:
            state = _analyze_statement(node.init, state, snapshots)
        # Any loop iteration (including a condition/step expression) can
        # invalidate a dominating enclosing-range proof. Kill dependencies
        # before computing the loop invariant; never publish first-trip safety.
        _invalidate_address_taken(node, state)

        class LoopMutations(c_ast.NodeVisitor):
            def visit_Assignment(self, update):
                target = _location(update.lvalue)
                if target:
                    invalidate_pointer_guards(state, _canonical_location(target))
                self.generic_visit(update)

            def visit_UnaryOp(self, update):
                if update.op in {"p++", "p--", "++", "--"}:
                    target = _location(update.expr)
                    if target:
                        invalidate_pointer_guards(state, _canonical_location(target))
                self.generic_visit(update)

        LoopMutations().visit(node)
        previous_suppression = snapshots.suppress_events
        snapshots.suppress_events = True
        entry = state.copy()
        current = entry.copy()
        converged = False
        unstable = set()
        for _ in range(8):
            previous = current
            body = _analyze_statement(node.stmt, current.copy(), snapshots)
            if isinstance(node, c_ast.For) and node.next is not None:
                body = _analyze_statement(node.next, body, snapshots)
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
        snapshots.suppress_events = previous_suppression
        _record(node, current, snapshots)
        return current
    _observe(node, state, snapshots)
    if isinstance(node, c_ast.Return):
        state.terminated = True
    _record(node, state, snapshots)
    return state


def _join_states(left: _State, right: _State) -> _State:
    if left.terminated:
        return right
    if right.terminated:
        return left
    facts: Dict[str, PointerRangeFact] = {}
    for key in set(left.facts) | set(right.facts):
        if key in left.facts and key in right.facts:
            facts[key] = join_pointer_facts(left.facts[key], right.facts[key])
        else:
            facts[key] = PointerRangeFact(
                degradations=frozenset({"PATH_INCOMPLETE"})
            )
    return _State(facts, dict(left.typedefs), dict(left.types), semantic_models=left.semantic_models,
                  constants={k: v for k, v in left.constants.items() if right.constants.get(k) == v})


def _transfer_decl(node: c_ast.Decl, state: _State) -> None:
    name = getattr(node, "name", None)
    if not name:
        return
    canonical = _canonical_location(name)
    invalidate_pointer_guards(state, canonical)
    state.types[name] = _resolve_type(node.type, state.typedefs)
    extent, width = _array_extent_and_width(_resolve_type(getattr(node, "type", None), state.typedefs))
    if extent is not None and width is not None:
        state.facts[canonical] = PointerRangeFact.object(
            canonical, extent, element_width=width
        )
        return
    declared_width = _pointer_element_width(_resolve_type(getattr(node, "type", None), state.typedefs))
    if not isinstance(_unwrap_type(state.types[name]), c_ast.PtrDecl):
        _remember_constant(name, node.init, state)
        return
    fact = _expression_fact(node.init, state)
    fact = replace(fact, element_width=declared_width)
    state.facts[canonical] = fact


def _transfer_assignment(node: c_ast.Assignment, state: _State) -> None:
    target = _location(node.lvalue)
    if not target:
        return
    target = _canonical_location(target)
    invalidate_pointer_guards(state, target)
    if not isinstance(_unwrap_type(state.types.get(target)), c_ast.PtrDecl):
        if node.op == "=":
            _remember_constant(target, node.rvalue, state)
        return
    if node.op in {"+=", "-="}:
        old = state.facts.get(target, PointerRangeFact())
        amount = _constant_size(node.rvalue, state)
        if amount is None:
            state.facts[target] = old.unknown_offset("UNSUPPORTED_ARITHMETIC")
        else:
            count = amount if node.op == "+=" else -amount
            state.facts[target] = old.shifted_elements(count)
        return
    fact = _expression_fact(node.rvalue, state)
    old = state.facts.get(target)
    if old is not None and old.element_width is not None:
        fact = replace(fact, element_width=old.element_width)
    state.facts[target] = fact


def _transfer_unary_update(node: c_ast.UnaryOp, state: _State) -> None:
    target = _location(node.expr)
    if not target:
        return
    target = _canonical_location(target)
    invalidate_pointer_guards(state, target)
    old = state.facts.get(target)
    if old is None:
        return
    count = 1 if node.op in {"p++", "++"} else -1
    state.facts[target] = old.shifted_elements(count)


def _expression_fact(node, state: _State) -> PointerRangeFact:
    if node is None:
        return PointerRangeFact()
    if isinstance(node, c_ast.ID):
        return state.facts.get(_canonical_location(node.name), PointerRangeFact())
    if isinstance(node, c_ast.Cast):
        width = _pointer_element_width(_resolve_type(node.to_type.type, state.typedefs))
        if not isinstance(_unwrap_type(_resolve_type(node.to_type.type, state.typedefs)), c_ast.PtrDecl):
            return PointerRangeFact()
        return replace(_expression_fact(node.expr, state), element_width=width)
    if isinstance(node, c_ast.UnaryOp) and node.op == "&":
        if isinstance(node.expr, c_ast.ArrayRef):
            return _index_address(node.expr, state)
        if isinstance(node.expr, c_ast.UnaryOp) and node.expr.op == "*":
            return _expression_fact(node.expr.expr, state)
        return PointerRangeFact()
    if isinstance(node, c_ast.ArrayRef):
        return PointerRangeFact()
    if isinstance(node, c_ast.BinaryOp) and node.op in {"+", "-"}:
        amount = _constant_size(node.right, state)
        if amount is not None:
            base = _expression_fact(node.left, state)
            count = amount if node.op == "+" else -amount
            return base.shifted_elements(count)
        if node.op == "+":
            amount = _constant_size(node.left, state)
            if amount is not None:
                base = _expression_fact(node.right, state)
                return base.shifted_elements(amount)
        base = _expression_fact(node.left, state)
        return base.unknown_offset("UNSUPPORTED_ARITHMETIC")
    if isinstance(node, c_ast.FuncCall):
        callee = _location(node.name)
        registry = state.semantic_models
        source = registry.sources.get(callee) if registry else None
        if source and any(output.kind.value == "return" for output in source.outputs):
            coord = getattr(node, "coord", None)
            return PointerRangeFact(origin=f"{callee}@{getattr(coord, 'line', 0)}:{getattr(coord, 'column', 0)}", offset=OffsetInterval.exact(0), provenance=PointerProvenance.EXTERNAL, value_provenance=ValueProvenance.UNTRUSTED)
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
                object_extent=extent if extent is not None and extent >= 0 else None,
                offset=OffsetInterval.exact(0),
                lower_bound=0 if extent is not None else None,
                upper_bound=max(0, extent) if extent is not None else None,
                provenance=PointerProvenance.ALLOCATION,
                value_provenance=ValueProvenance.TRUSTED,
            )
    return PointerRangeFact(degradations=frozenset({"UNSUPPORTED_TRANSFORM"}))


def _resolve_type(node, typedefs, seen=frozenset()):
    from copy import copy

    if isinstance(node, (c_ast.Struct, c_ast.Union)):
        key = None
        if node.name:
            key = ("struct:" if isinstance(node, c_ast.Struct) else "union:") + node.name
            if key in seen:
                return node
        source = node if node.decls else (typedefs.get(key, node) if key else node)
        result = copy(source)
        if source.decls:
            result.decls = []
            next_seen = seen | {key} if key else seen
            for member in source.decls:
                resolved = copy(member)
                resolved.type = _resolve_type(member.type, typedefs, next_seen)
                result.decls.append(resolved)
        return result
    if isinstance(node, c_ast.IdentifierType) and len(node.names) == 1:
        name = node.names[0]
        if name in typedefs and name not in seen:
            return _resolve_type(typedefs[name], typedefs, seen | {name})
    if isinstance(node, (c_ast.TypeDecl, c_ast.PtrDecl, c_ast.ArrayDecl)):
        result = copy(node)
        result.type = _resolve_type(node.type, typedefs, seen)
        return result
    return node


def _supports_definite_events(funcdef, typedefs):
    """Exclude control/alias effects the current statement walk cannot model."""
    supported = True
    names = set(typedefs)

    def walk(node, parent=None):
        nonlocal supported
        if node is None:
            return
        if isinstance(node, (c_ast.Goto, c_ast.Label, c_ast.Switch)):
            supported = False
        if isinstance(node, (c_ast.Decl, c_ast.Typedef)) and node.name:
            if node.name in names:
                supported = False  # lexical shadowing needs scoped identities
            names.add(node.name)
        if isinstance(node, c_ast.Assignment) or (
            isinstance(node, c_ast.UnaryOp) and node.op in {"p++", "p--", "++", "--"}
        ):
            if not isinstance(parent, (c_ast.Compound, c_ast.If, c_ast.For, c_ast.While, c_ast.DoWhile)):
                supported = False
        for _, child in node.children():
            walk(child, node)

    walk(funcdef)
    return supported


def _index_address(node, state):
    base = _expression_fact(node.name, state)
    index = _constant_size(node.subscript, state)
    return base.unknown_offset("UNKNOWN_INDEX") if index is None else base.shifted_elements(index)


def _invalidate_address_taken(node, state):
    """Drop facts that may be invalidated through an escaped address."""
    if node is None:
        return

    class Visitor(c_ast.NodeVisitor):
        def visit_UnaryOp(self, candidate):
            if candidate.op == "&":
                target = _location(candidate.expr)
                if target:
                    canonical = _canonical_location(target)
                    invalidate_pointer_guards(state, canonical)
                    fact = state.facts.get(canonical)
                    typ = _unwrap_type(state.types.get(target))
                    if fact is not None and isinstance(typ, c_ast.PtrDecl):
                        # The pointer object itself may be overwritten through
                        # the escaped pointer-to-pointer. Preserve only its
                        # static element width; all value-bound range evidence
                        # is stale until a later explicit assignment/refinement.
                        state.facts[canonical] = PointerRangeFact(
                            element_width=fact.element_width,
                            degradations=fact.degradations | {"ADDRESS_ESCAPED"},
                        )
                return
            self.generic_visit(candidate)

    Visitor().visit(node)


def _observe(node, state, snapshots):
    """Record use-site facts before transfer, independent of source-line layout."""
    if node is None:
        return
    _invalidate_address_taken(node, state)
    if snapshots.suppress_events:
        return

    class Visitor(c_ast.NodeVisitor):
        def emit(self, node, fact, access=False, write=False):
            width = fact.element_width if access else 0
            snapshots.events.append(PointerRangeEvent(node, fact, width, write, access))

        def access(self, node, write=False):
            if isinstance(node, c_ast.ArrayRef):
                self.emit(node, _index_address(node, state), True, write)
                self.visit(node.subscript)
            elif isinstance(node, c_ast.UnaryOp) and node.op == "*":
                self.emit(node, _expression_fact(node.expr, state), True, write)
            elif isinstance(node, c_ast.StructRef) and node.type == "->":
                fact, width = _member_access(node, state)
                snapshots.events.append(PointerRangeEvent(node, fact, width, write, True))
            else:
                self.visit(node)

        def visit_StructRef(self, node):
            if node.type == "->":
                self.access(node)
            else:
                self.visit(node.name)

        def visit_FuncCall(self, node):
            registry = snapshots.semantic_models
            name = _location(node.name)
            args = list(getattr(node.args, "exprs", ()) or ())
            effect = registry.call_effects.effects.get(name) if registry else None
            pairs = set(effect.size_relationships if effect else ())
            if name in {"memcpy", "memmove", "memcmp"}:
                pairs.update(((0, 2), (1, 2)))
            for data, size in sorted(pairs):
                if max(data, size) < len(args):
                    width = _constant_size(args[size], state)
                    if width is None or width > 0:
                        write = (name in {"memcpy", "memmove"} and data == 0) or bool(effect and data in effect.output_parameters)
                        snapshots.events.append(PointerRangeEvent(args[data], _expression_fact(args[data], state), width, write, True))
            self.generic_visit(node)

        def visit_ArrayRef(self, node):
            self.access(node)

        def visit_UnaryOp(self, node):
            if node.op in {"sizeof", "_Alignof"}:
                return
            if node.op == "&":
                self.emit(node, _expression_fact(node, state))
            elif node.op == "*":
                self.access(node)
            elif node.op in {"p++", "p--", "++", "--"}:
                self.access(node.expr, True)
                fact = _expression_fact(node.expr, state)
                self.emit(node, fact.shifted_elements(1 if "+" in node.op else -1))
            else:
                self.generic_visit(node)

        def visit_BinaryOp(self, node):
            if node.op in {"+", "-"}:
                self.emit(node, _expression_fact(node, state))
            self.generic_visit(node)

        def visit_Assignment(self, node):
            self.access(node.lvalue, True)
            if node.op in {"+=", "-="}:
                amount = _constant_size(node.rvalue, state)
                if amount is not None:
                    fact = _expression_fact(node.lvalue, state)
                    self.emit(node, fact.shifted_elements(amount if node.op == "+=" else -amount))
            self.visit(node.rvalue)

    Visitor().visit(node)


def _validate_condition(node, state, registry, truth):
    """Refine shared relational bounds and #272 validator success contracts.

    Split only edges that guarantee evaluation and success. In particular,
    repeated calls to the same API must never validate each other's arguments.
    """
    from .security_dataflow import _condition_guarantees_success
    if node is None:
        return
    if isinstance(node, c_ast.Cast):
        return _validate_condition(node.expr, state, registry, truth)
    if isinstance(node, c_ast.UnaryOp) and node.op == "!":
        return _validate_condition(node.expr, state, registry, not truth)
    if isinstance(node, c_ast.BinaryOp) and node.op in {"&&", "||"}:
        if (node.op == "&&" and truth) or (node.op == "||" and not truth):
            _validate_condition(node.left, state, registry, truth)
            _validate_condition(node.right, state, registry, truth)
        return
    refine_pointer_comparison(node, state, truth)
    if registry is None:
        return
    call = node if isinstance(node, c_ast.FuncCall) else None
    if isinstance(node, c_ast.BinaryOp) and node.op in {"==", "!="}:
        if isinstance(node.left, c_ast.FuncCall) and _constant_int(node.right) is not None:
            call = node.left
        elif isinstance(node.right, c_ast.FuncCall) and _constant_int(node.left) is not None:
            call = node.right
    if call is None or not isinstance(call.name, c_ast.ID):
        return
    model = registry.validators.get(call.name.name)
    if model is None or model.length is None:
        return
    from ..semantic_models import SuccessConditionKind
    if isinstance(node, c_ast.BinaryOp):
        constant = node.right if call is node.left else node.left
        value = _constant_int(constant)
        if model.success.kind is SuccessConditionKind.RETURN_EQUALS and value != model.success.value:
            return
        if model.success.kind is SuccessConditionKind.RETURN_NONZERO and value != 0 and (node.op == "!=") == truth:
            return
        if model.success.kind is SuccessConditionKind.RETURN_ZERO and value != 0:
            return
    if not _condition_guarantees_success(node, model.function, model.success)[0 if truth else 1]:
        return
    args = list(getattr(call.args, "exprs", ()) or ())
    target, length = model.target.argument_index, model.length.argument_index
    if max(target, length) >= len(args):
        return
    fact = _expression_fact(args[target], state)
    size = _constant_size(args[length], state)
    if fact.origin is None or not fact.offset.is_exact or size is None or size < 0:
        return
    interval = (fact.offset.lower, fact.offset.lower + size)
    for key, alias in list(state.facts.items()):
        if alias.origin == fact.origin:
            state.facts[key] = replace(alias, validated_intervals=tuple(sorted(set(alias.validated_intervals) | {interval})))


def _unwrap_type(node):
    while isinstance(node, c_ast.TypeDecl):
        node = node.type
    return node


def _expression_type(node, state):
    if isinstance(node, c_ast.ID):
        return state.types.get(node.name)
    if isinstance(node, c_ast.Cast):
        return _resolve_type(node.to_type.type, state.typedefs)
    if isinstance(node, c_ast.UnaryOp) and node.op == "*":
        base = _expression_type(node.expr, state)
        return base.type if isinstance(base, c_ast.PtrDecl) else None
    return None


def _remember_constant(name, node, state):
    if _volatile_type(state.types.get(name)):
        return
    value = _constant_size(node, state)
    typ = _unwrap_type(state.types.get(name))
    names = getattr(typ, "names", ())
    width = _type_width(typ)
    if value is None or width is None or not any(n in names for n in ("int", "short", "long", "signed", "unsigned")):
        return
    bits = width * 8
    lower, upper = (0, (1 << bits) - 1) if "unsigned" in names else (-(1 << (bits - 1)), (1 << (bits - 1)) - 1)
    if lower <= value <= upper:
        state.constants[name] = value


def _constant_size(node, state):
    if isinstance(node, c_ast.ID):
        return state.constants.get(node.name)
    if isinstance(node, c_ast.UnaryOp) and node.op == "sizeof":
        typ = _resolve_type(node.expr.type, state.typedefs) if isinstance(node.expr, c_ast.Typename) else _expression_type(node.expr, state)
        return _type_width(typ)
    return _constant_int(node)


def _member_access(node, state):
    fact = _expression_fact(node.name, state)
    typ = _expression_type(node.name, state)
    typ = _unwrap_type(typ)
    typ = typ.type if isinstance(typ, c_ast.PtrDecl) else None
    while isinstance(typ, c_ast.TypeDecl):
        typ = typ.type
    layout = _aggregate_layout(typ)
    if layout is not None and node.field.name in layout[2]:
        offset, width = layout[2][node.field.name]
        return fact.shifted(offset), width
    return fact.unknown_offset("UNKNOWN_MEMBER_LAYOUT"), None


def _type_alignment(node):
    node = _unwrap_type(node)
    if isinstance(node, c_ast.ArrayDecl):
        return _type_alignment(node.type)
    if isinstance(node, (c_ast.Struct, c_ast.Union)):
        layout = _aggregate_layout(node)
        return layout[1] if layout is not None else None
    return _type_width(node)


def _aggregate_layout(node):
    """Natural aggregate layout under the domain's existing scalar width model.

    Bitfields, incomplete and flexible-array layouts remain unknown.
    """
    if not isinstance(node, (c_ast.Struct, c_ast.Union)) or not node.decls:
        return None
    size, alignment, members = 0, 1, {}
    for member in node.decls:
        if member.bitsize is not None:
            return None
        width, align = _type_width(member.type), _type_alignment(member.type)
        if width is None or align is None or align <= 0:
            return None
        alignment = max(alignment, align)
        offset = 0 if isinstance(node, c_ast.Union) else (size + align - 1) // align * align
        members[member.name] = (offset, width)
        size = max(size, offset + width)
    return (size + alignment - 1) // alignment * alignment, alignment, members


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


def _array_extent_and_width(type_node) -> Tuple[Optional[int], Optional[int]]:
    node = type_node
    while isinstance(node, c_ast.TypeDecl):
        node = node.type
    if not isinstance(node, c_ast.ArrayDecl):
        return None, None
    count = _constant_int(node.dim)
    width = _type_width(node.type)
    if count is None or width is None:
        return None, width
    return count * width, width


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


def _type_width(type_node) -> Optional[int]:
    node = type_node
    while isinstance(node, c_ast.TypeDecl):
        node = node.type
    if isinstance(node, c_ast.PtrDecl):
        return 8
    if isinstance(node, c_ast.ArrayDecl):
        count = _constant_int(node.dim)
        element_width = _type_width(node.type)
        if count is None or element_width is None:
            return None
        return count * element_width
    if isinstance(node, (c_ast.Struct, c_ast.Union)):
        layout = _aggregate_layout(node)
        return layout[0] if layout is not None else None
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
        if any(n in names for n in ("int", "signed", "unsigned", "float")):
            return 4
        if "double" in names:
            return 8
        if "_Bool" in names:
            return 1
        return None
    return None


__all__ = [
    "OffsetInterval",
    "PointerProvenance",
    "PointerRangeFact",
    "PointerRangeEvent",
    "PointerRangeFunctionResult",
    "TranslationUnitPointerRangeResult",
    "analyze_translation_unit_pointer_ranges",
    "join_pointer_facts",
]
