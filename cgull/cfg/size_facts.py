"""Bounded interprocedural buffer-size facts.

The domain intentionally models only constants, finite lower/upper bounds and
formal-parameter relationships. Unsupported arithmetic is degraded to
UNKNOWN; it is never used to prove a buffer operation safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Mapping, Optional, Tuple

from pycparser import c_ast

from .call_graph import build_translation_unit_call_graph
from .construction import find_function_def
from .fixed_point import FixedPointConfig, FixedPointDiagnostic


class SizeSafety(str, Enum):
    SAFE = "safe"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SizeFact:
    """One bounded integer/extent fact.

    ``parameter_index`` denotes an unresolved relationship to the named
    function's formal parameter. Bounds are inclusive and measured in bytes
    for buffer extents.
    """

    lower: Optional[int] = None
    upper: Optional[int] = None
    parameter_index: Optional[int] = None
    degradations: FrozenSet[str] = frozenset()

    @classmethod
    def exact(cls, value: int) -> "SizeFact":
        value = max(0, int(value))
        return cls(lower=value, upper=value)

    @classmethod
    def parameter(cls, index: int) -> "SizeFact":
        return cls(parameter_index=index)

    @property
    def is_exact(self) -> bool:
        return self.lower is not None and self.lower == self.upper

    @property
    def exact_value(self) -> Optional[int]:
        return self.lower if self.is_exact else None

    @property
    def is_unknown(self) -> bool:
        return self.lower is None and self.upper is None and self.parameter_index is None

    def with_upper(self, upper: int) -> "SizeFact":
        upper = max(0, int(upper))
        lower = self.lower
        if lower is not None and lower > upper:
            return SizeFact(degradations=self.degradations | {"INFEASIBLE_GUARD"})
        return SizeFact(
            lower=lower,
            upper=upper,
            parameter_index=self.parameter_index,
            degradations=self.degradations,
        )

    def with_lower(self, lower: int) -> "SizeFact":
        lower = max(0, int(lower))
        upper = self.upper
        if upper is not None and lower > upper:
            return SizeFact(degradations=self.degradations | {"INFEASIBLE_GUARD"})
        return SizeFact(
            lower=lower,
            upper=upper,
            parameter_index=self.parameter_index,
            degradations=self.degradations,
        )


def join_size_facts(left: SizeFact, right: SizeFact) -> SizeFact:
    """Conservative union of possible values from two reachable paths/callers."""
    if left == right:
        return left
    relation = left.parameter_index if left.parameter_index == right.parameter_index else None
    lower = (
        min(left.lower, right.lower)
        if left.lower is not None and right.lower is not None
        else None
    )
    upper = (
        max(left.upper, right.upper)
        if left.upper is not None and right.upper is not None
        else None
    )
    return SizeFact(
        lower=lower,
        upper=upper,
        parameter_index=relation,
        degradations=left.degradations | right.degradations,
    )


def classify_size(size: SizeFact, capacity: SizeFact) -> SizeSafety:
    """Classify a requested size against a known destination capacity."""
    if size.upper is not None and capacity.lower is not None and size.upper <= capacity.lower:
        return SizeSafety.SAFE
    if size.lower is not None and capacity.upper is not None and size.lower > capacity.upper:
        return SizeSafety.UNSAFE
    return SizeSafety.UNKNOWN


@dataclass(frozen=True)
class SizeCallFact:
    caller: str
    callee: str
    line: int
    extents: Tuple[SizeFact, ...]
    sizes: Tuple[SizeFact, ...]

    def classify(self, *, buffer_arg: int, size_arg: int) -> SizeSafety:
        if buffer_arg >= len(self.extents) or size_arg >= len(self.sizes):
            return SizeSafety.UNKNOWN
        return classify_size(self.sizes[size_arg], self.extents[buffer_arg])


@dataclass(frozen=True)
class TranslationUnitSizeResult:
    parameter_extents: Mapping[str, Tuple[SizeFact, ...]]
    parameter_sizes: Mapping[str, Tuple[SizeFact, ...]]
    calls: Tuple[SizeCallFact, ...]
    diagnostics: Tuple[FixedPointDiagnostic, ...] = ()

    def calls_to(self, callee: str) -> Tuple[SizeCallFact, ...]:
        return tuple(call for call in self.calls if call.callee == callee)


@dataclass
class _State:
    extents: Dict[str, SizeFact]
    sizes: Dict[str, SizeFact]
    struct_types: Dict[str, str]

    def copy(self) -> "_State":
        return _State(dict(self.extents), dict(self.sizes), dict(self.struct_types))


def analyze_translation_unit_size_dataflow(
    ast_ctx,
    *,
    fixed_point_config: Optional[FixedPointConfig] = None,
    call_graph=None,
) -> TranslationUnitSizeResult:
    """Propagate bounded size/extents through direct calls and simple aliases."""
    config = fixed_point_config or FixedPointConfig()
    graph = call_graph or build_translation_unit_call_graph(ast_ctx)
    fn_meta = {
        fn.name: fn
        for fn in getattr(ast_ctx, "functions", ())
        if getattr(fn, "name", None)
    }
    parameter_names = {
        name: tuple(p.name for p in fn.parameters if p.name)
        for name, fn in fn_meta.items()
    }
    incoming_extents: Dict[str, list] = {
        name: [None] * len(parameter_names.get(name, ())) for name in fn_meta
    }
    incoming_sizes: Dict[str, list] = {
        name: [None] * len(parameter_names.get(name, ())) for name in fn_meta
    }
    diagnostics = []
    calls_by_site: Dict[Tuple[str, str, int], SizeCallFact] = {}
    struct_members = _collect_struct_member_extents(getattr(ast_ctx, "pycparser_ast", None))

    for name in sorted(fn_meta):
        if not graph.callers(name):
            incoming_extents[name] = [SizeFact() for _ in incoming_extents[name]]
            incoming_sizes[name] = [SizeFact() for _ in incoming_sizes[name]]

    for component in reversed(graph.bottom_up_sccs):
        component = tuple(sorted(component))
        recursive = len(component) > 1 or any(name in graph.callees(name) for name in component)
        budget = config.max_iterations_per_scc if recursive else 1
        converged = not recursive

        for _round in range(1, budget + 1):
            changed = False
            for name in component:
                params = parameter_names.get(name, ())
                ext_entry = {
                    param: fact
                    for param, fact in zip(params, incoming_extents.get(name, ()))
                    if fact is not None
                }
                size_entry = {
                    param: fact
                    for param, fact in zip(params, incoming_sizes.get(name, ()))
                    if fact is not None
                }
                call_facts = _analyze_function(
                    ast_ctx,
                    name,
                    ext_entry,
                    size_entry,
                    struct_members,
                )
                for call in call_facts:
                    key = (call.caller, call.callee, call.line)
                    old_call = calls_by_site.get(key)
                    calls_by_site[key] = call if old_call is None else _join_call(old_call, call)
                    if call.callee not in incoming_extents:
                        continue
                    changed |= _merge_actuals(
                        incoming_extents[call.callee], call.extents, call.callee in component
                    )
                    changed |= _merge_actuals(
                        incoming_sizes[call.callee], call.sizes, call.callee in component
                    )
            if recursive and not changed:
                converged = True
                break

        if recursive and not converged:
            degraded = SizeFact(degradations=frozenset({"CONVERGENCE_LIMIT"}))
            for name in component:
                incoming_extents[name] = [degraded for _ in incoming_extents[name]]
                incoming_sizes[name] = [degraded for _ in incoming_sizes[name]]
            diagnostics.append(
                FixedPointDiagnostic(
                    code="CONVERGENCE_LIMIT",
                    functions=component,
                    iterations=budget,
                    message=(
                        "caller-to-formal size propagation did not converge within "
                        f"{budget} iterations; affected size facts were degraded to unknown"
                    ),
                )
            )

    public_extents = {
        name: tuple(fact if fact is not None else SizeFact() for fact in facts)
        for name, facts in sorted(incoming_extents.items())
    }
    public_sizes = {
        name: tuple(fact if fact is not None else SizeFact() for fact in facts)
        for name, facts in sorted(incoming_sizes.items())
    }
    return TranslationUnitSizeResult(
        parameter_extents=public_extents,
        parameter_sizes=public_sizes,
        calls=tuple(calls_by_site[key] for key in sorted(calls_by_site)),
        diagnostics=tuple(diagnostics),
    )


def _merge_actuals(target, actuals, count_change):
    changed = False
    for index, fact in enumerate(actuals[: len(target)]):
        old = target[index]
        new = fact if old is None else join_size_facts(old, fact)
        if new != old:
            target[index] = new
            changed = changed or count_change
    return changed


def _join_call(left: SizeCallFact, right: SizeCallFact) -> SizeCallFact:
    return SizeCallFact(
        caller=left.caller,
        callee=left.callee,
        line=left.line,
        extents=tuple(join_size_facts(a, b) for a, b in zip(left.extents, right.extents)),
        sizes=tuple(join_size_facts(a, b) for a, b in zip(left.sizes, right.sizes)),
    )


def _analyze_function(ast_ctx, name, ext_entry, size_entry, struct_members):
    funcdef = find_function_def(getattr(ast_ctx, "pycparser_ast", None), name)
    if funcdef is None:
        return ()
    state = _State(dict(ext_entry), dict(size_entry), {})
    calls = []
    _analyze_statement(funcdef.body, state, calls, name, struct_members)
    return tuple(calls)


def _analyze_statement(node, state, calls, caller, struct_members):
    if node is None:
        return state
    kind = type(node).__name__
    if kind == "Compound":
        current = state
        for item in list(getattr(node, "block_items", ()) or ()):
            current = _analyze_statement(item, current, calls, caller, struct_members)
        return current
    if kind == "DeclList":
        current = state
        for decl in list(getattr(node, "decls", ()) or ()):
            current = _analyze_statement(decl, current, calls, caller, struct_members)
        return current
    if kind == "Decl":
        _transfer_decl(node, state, struct_members)
        _record_calls(node.init, state, calls, caller, struct_members)
        return state
    if kind == "Assignment":
        _transfer_assignment(node, state, struct_members)
        _record_calls(node.rvalue, state, calls, caller, struct_members)
        return state
    if kind == "If":
        _record_calls(node.cond, state, calls, caller, struct_members)
        true_state = state.copy()
        false_state = state.copy()
        _refine_condition(node.cond, true_state, truth=True, struct_members=struct_members)
        _refine_condition(node.cond, false_state, truth=False, struct_members=struct_members)
        true_out = _analyze_statement(node.iftrue, true_state, calls, caller, struct_members)
        false_out = (
            _analyze_statement(node.iffalse, false_state, calls, caller, struct_members)
            if node.iffalse
            else false_state
        )
        return _join_states(true_out, false_out)
    if kind in {"While", "DoWhile", "For"}:
        if kind == "For":
            state = _analyze_statement(
                getattr(node, "init", None), state, calls, caller, struct_members
            )
        cond = getattr(node, "cond", None)
        _record_calls(cond, state, calls, caller, struct_members)
        body_state = state.copy()
        _refine_condition(cond, body_state, truth=True, struct_members=struct_members)
        body = getattr(node, "stmt", None)
        body_out = _analyze_statement(body, body_state, calls, caller, struct_members)
        if kind == "For":
            next_node = getattr(node, "next", None)
            _record_calls(next_node, body_out, calls, caller, struct_members)
            if type(next_node).__name__ == "Assignment":
                _transfer_assignment(next_node, body_out, struct_members)
        return _join_states(state, body_out)
    _record_calls(node, state, calls, caller, struct_members)
    return state


def _join_states(left: _State, right: _State) -> _State:
    extents = {}
    for key in set(left.extents) | set(right.extents):
        if key in left.extents and key in right.extents:
            extents[key] = join_size_facts(left.extents[key], right.extents[key])
        else:
            extents[key] = SizeFact(degradations=frozenset({"PATH_INCOMPLETE"}))
    sizes = {}
    for key in set(left.sizes) | set(right.sizes):
        if key in left.sizes and key in right.sizes:
            sizes[key] = join_size_facts(left.sizes[key], right.sizes[key])
        else:
            sizes[key] = SizeFact(degradations=frozenset({"PATH_INCOMPLETE"}))
    struct_types = {
        key: value
        for key, value in left.struct_types.items()
        if right.struct_types.get(key) == value
    }
    return _State(extents, sizes, struct_types)


def _transfer_decl(node, state, struct_members):
    name = getattr(node, "name", None)
    if not name:
        return
    struct_name = _decl_struct_name(getattr(node, "type", None))
    if struct_name:
        state.struct_types[name] = struct_name
    extent = _decl_array_extent(getattr(node, "type", None))
    if extent is not None:
        state.extents[name] = SizeFact.exact(extent)
    init = getattr(node, "init", None)
    if init is not None:
        alias = _extent_fact(init, state, struct_members)
        if not alias.is_unknown:
            state.extents[name] = alias
        state.sizes[name] = _scalar_fact(init, state, struct_members)


def _transfer_assignment(node, state, struct_members):
    target = _location(node.lvalue)
    if not target:
        return
    extent = _extent_fact(node.rvalue, state, struct_members)
    if not extent.is_unknown:
        state.extents[target] = extent
    else:
        state.extents.pop(target, None)
    state.sizes[target] = _scalar_fact(node.rvalue, state, struct_members)


def _record_calls(node, state, calls, caller, struct_members):
    if node is None:
        return
    if type(node).__name__ == "FuncCall":
        callee = _direct_callee(node)
        if callee:
            args = list(getattr(getattr(node, "args", None), "exprs", ()) or ())
            calls.append(
                SizeCallFact(
                    caller=caller,
                    callee=callee,
                    line=getattr(getattr(node, "coord", None), "line", 0) or 0,
                    extents=tuple(_extent_fact(arg, state, struct_members) for arg in args),
                    sizes=tuple(_scalar_fact(arg, state, struct_members) for arg in args),
                )
            )
        for arg in list(getattr(getattr(node, "args", None), "exprs", ()) or ()):
            _record_calls(arg, state, calls, caller, struct_members)
        return
    for _, child in node.children():
        _record_calls(child, state, calls, caller, struct_members)


def _refine_condition(node, state, *, truth, struct_members):
    if node is None or type(node).__name__ != "BinaryOp":
        return
    op = getattr(node, "op", None)
    if op == "&&" and truth:
        _refine_condition(node.left, state, truth=True, struct_members=struct_members)
        _refine_condition(node.right, state, truth=True, struct_members=struct_members)
        return
    if op == "||" and not truth:
        _refine_condition(node.left, state, truth=False, struct_members=struct_members)
        _refine_condition(node.right, state, truth=False, struct_members=struct_members)
        return
    if op not in {"<", "<=", ">", ">="}:
        return
    left_name = _location(node.left)
    right_name = _location(node.right)
    left = _scalar_fact(node.left, state, struct_members)
    right = _scalar_fact(node.right, state, struct_members)
    if left_name and right.is_exact:
        _refine_named_bound(state, left_name, op, right.exact_value, truth)
    elif right_name and left.is_exact:
        reverse = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[op]
        _refine_named_bound(state, right_name, reverse, left.exact_value, truth)


def _refine_named_bound(state, name, op, bound, truth):
    if bound is None:
        return
    fact = state.sizes.get(name, SizeFact())
    if truth:
        if op == "<=":
            state.sizes[name] = fact.with_upper(bound)
        elif op == "<":
            state.sizes[name] = fact.with_upper(max(0, bound - 1))
        elif op == ">=":
            state.sizes[name] = fact.with_lower(bound)
        elif op == ">":
            state.sizes[name] = fact.with_lower(bound + 1)
    else:
        inverse = {"<=": ">", "<": ">=", ">=": "<", ">": "<="}[op]
        _refine_named_bound(state, name, inverse, bound, True)


def _extent_fact(node, state, struct_members):
    node = _unwrap(node)
    if node is None:
        return SizeFact()
    kind = type(node).__name__
    if kind == "ID":
        return state.extents.get(node.name, SizeFact())
    if kind == "StructRef":
        location = _location(node)
        if location in state.extents:
            return state.extents[location]
        base = _location(node.name)
        field = getattr(getattr(node, "field", None), "name", None)
        struct_name = state.struct_types.get(base or "")
        if struct_name and field:
            extent = struct_members.get((struct_name, field))
            return SizeFact.exact(extent) if extent is not None else SizeFact()
    if kind == "UnaryOp" and getattr(node, "op", None) == "&":
        return _extent_fact(node.expr, state, struct_members)
    if kind == "ArrayRef":
        return SizeFact(degradations=frozenset({"ARRAY_ELEMENT_NOT_BUFFER"}))
    if kind == "BinaryOp":
        return SizeFact(degradations=frozenset({"POINTER_ARITHMETIC"}))
    return SizeFact()


def _scalar_fact(node, state, struct_members):
    node = _unwrap(node)
    if node is None:
        return SizeFact()
    kind = type(node).__name__
    if kind == "Constant" and getattr(node, "type", None) in {
        "int",
        "unsigned int",
        "long",
        "unsigned long",
        "long long",
        "unsigned long long",
    }:
        value = _parse_int(getattr(node, "value", ""))
        return SizeFact.exact(value) if value is not None and value >= 0 else SizeFact()
    if kind == "ID":
        return state.sizes.get(node.name, SizeFact())
    if kind == "UnaryOp" and getattr(node, "op", None) == "sizeof":
        return _extent_fact(node.expr, state, struct_members)
    if kind == "TernaryOp":
        return join_size_facts(
            _scalar_fact(node.iftrue, state, struct_members),
            _scalar_fact(node.iffalse, state, struct_members),
        )
    if kind == "BinaryOp":
        return SizeFact(degradations=frozenset({"UNSUPPORTED_ARITHMETIC"}))
    return SizeFact()


def _unwrap(node):
    while node is not None and type(node).__name__ == "Cast":
        node = node.expr
    return node


def _location(node):
    node = _unwrap(node)
    if node is None:
        return None
    kind = type(node).__name__
    if kind == "ID":
        return str(node.name)
    if kind == "StructRef":
        base = _location(node.name)
        field = getattr(getattr(node, "field", None), "name", None)
        if base and field:
            return f"{base}.{field}"
    return None


def _direct_callee(node):
    name = getattr(node, "name", None)
    return str(name.name) if type(name).__name__ == "ID" else None


def _parse_int(value):
    text = str(value).strip().lower()
    while text.endswith(("u", "l")):
        text = text[:-1]
    try:
        return int(text, 0)
    except ValueError:
        return None


def _decl_array_extent(type_node):
    node = type_node
    multiplier = 1
    saw_array = False
    while node is not None:
        kind = type(node).__name__
        if kind == "ArrayDecl":
            dim = _constant_dimension(getattr(node, "dim", None))
            if dim is None:
                return None
            multiplier *= dim
            saw_array = True
            node = node.type
            continue
        if kind == "TypeDecl":
            width = _scalar_type_width(getattr(node, "type", None))
            if width is None or not saw_array:
                return None
            return multiplier * width
        node = getattr(node, "type", None)
    return None


def _constant_dimension(node):
    node = _unwrap(node)
    if type(node).__name__ != "Constant":
        return None
    value = _parse_int(getattr(node, "value", ""))
    return value if value is not None and value >= 0 else None


def _scalar_type_width(node):
    if type(node).__name__ != "IdentifierType":
        return None
    names = tuple(getattr(node, "names", ()) or ())
    if "char" in names:
        return 1
    if "short" in names:
        return 2
    if "long" in names and names.count("long") > 1:
        return 8
    if "long" in names:
        return 8
    if "int" in names or names == ("unsigned",) or names == ("signed",):
        return 4
    return None


def _decl_struct_name(type_node):
    node = type_node
    while node is not None:
        if type(node).__name__ == "Struct":
            return getattr(node, "name", None)
        node = getattr(node, "type", None)
    return None


def _collect_struct_member_extents(ast_root):
    result = {}
    if ast_root is None:
        return result

    class Visitor(c_ast.NodeVisitor):
        def visit_Struct(self, node):
            if node.name and node.decls:
                for decl in node.decls:
                    extent = _decl_array_extent(getattr(decl, "type", None))
                    if extent is not None and getattr(decl, "name", None):
                        result[(str(node.name), str(decl.name))] = extent
            self.generic_visit(node)

    Visitor().visit(ast_root)
    return result
