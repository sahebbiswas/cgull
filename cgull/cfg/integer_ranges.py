"""Conservative integer range provenance over the structured CFG.

The domain records closed integer intervals before CFG events, propagates
constant/range assignments, and refines successor states with simple branch
conditions.  Facts are merged across all reaching paths, so a guard only
survives when it constrains every path to the queried event.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, Mapping, Optional, Tuple

from ..ast_analyzer.integer_types import _resolved_scalar_type, get_integer_type_byte_size
from .construction import build_cfg, find_function_def


__all__ = [
    "IntegerRange",
    "IntegerRangeAnalysis",
    "analyze_integer_ranges",
    "integer_type_range",
]


@dataclass(frozen=True)
class IntegerRange:
    """Inclusive integer interval; ``None`` denotes an unbounded endpoint."""

    lower: Optional[int] = None
    upper: Optional[int] = None

    @property
    def is_singleton(self) -> bool:
        return self.lower is not None and self.lower == self.upper

    def intersect(self, other: "IntegerRange") -> Optional["IntegerRange"]:
        lower = _max_lower(self.lower, other.lower)
        upper = _min_upper(self.upper, other.upper)
        if lower is not None and upper is not None and lower > upper:
            return None
        return IntegerRange(lower, upper)

    def hull(self, other: "IntegerRange") -> "IntegerRange":
        return IntegerRange(_min_lower(self.lower, other.lower), _max_upper(self.upper, other.upper))

    def fits_within(self, destination: "IntegerRange") -> bool:
        if self.lower is None or self.upper is None:
            return False
        if destination.lower is not None and self.lower < destination.lower:
            return False
        if destination.upper is not None and self.upper > destination.upper:
            return False
        return True


def _max_lower(left: Optional[int], right: Optional[int]) -> Optional[int]:
    if left is None:
        return right
    if right is None:
        return left
    return max(left, right)


def _min_upper(left: Optional[int], right: Optional[int]) -> Optional[int]:
    if left is None:
        return right
    if right is None:
        return left
    return min(left, right)


def _min_lower(left: Optional[int], right: Optional[int]) -> Optional[int]:
    if left is None or right is None:
        return None
    return min(left, right)


def _max_upper(left: Optional[int], right: Optional[int]) -> Optional[int]:
    if left is None or right is None:
        return None
    return max(left, right)


def integer_type_range(type_name: str, ast_ctx=None) -> Optional[IntegerRange]:
    """Return the representable range for a known integer type.

    Plain ``char`` and ``time_t`` are intentionally left unresolved because
    their signedness is implementation-defined. Width is taken from the same
    target-aware helper used by integer narrowing detection.
    """

    resolved = _resolved_scalar_type(type_name, ast_ctx)
    width_bytes = get_integer_type_byte_size(type_name, ast_ctx)
    if not resolved or width_bytes is None:
        return None

    normalized = resolved.lower()
    if normalized in {"char", "time_t"}:
        return None
    unsigned = (
        normalized.startswith("unsigned")
        or normalized.startswith("uint")
        or normalized in {"size_t", "uintptr_t"}
    )
    signed = (
        normalized.startswith("signed")
        or normalized.startswith("int")
        or normalized.startswith("short")
        or normalized.startswith("long")
        or normalized in {"ssize_t", "intptr_t", "ptrdiff_t"}
    )
    if not unsigned and not signed:
        return None

    bits = width_bytes * 8
    if unsigned:
        return IntegerRange(0, (1 << bits) - 1)
    return IntegerRange(-(1 << (bits - 1)), (1 << (bits - 1)) - 1)


_LIMIT_RE = re.compile(r"^(U?INT)(8|16|32|64)_(MIN|MAX)$")


def _named_integer_limit(name: str, ast_ctx=None) -> Optional[int]:
    match = _LIMIT_RE.fullmatch(name)
    if match:
        family, bits_text, bound = match.groups()
        bits = int(bits_text)
        if family == "UINT":
            return 0 if bound == "MIN" else (1 << bits) - 1
        return -(1 << (bits - 1)) if bound == "MIN" else (1 << (bits - 1)) - 1

    aliases = {
        "SIZE_MAX": "size_t",
        "SSIZE_MAX": "ssize_t",
        "UINTPTR_MAX": "uintptr_t",
        "INTPTR_MAX": "intptr_t",
        "PTRDIFF_MAX": "ptrdiff_t",
    }
    type_name = aliases.get(name)
    if not type_name:
        return None
    bounds = integer_type_range(type_name, ast_ctx)
    return bounds.upper if bounds is not None else None


def _parse_integer_literal(value: str) -> Optional[int]:
    text = value.strip()
    # Remove common C integer suffixes without touching hexadecimal digits.
    text = re.sub(r"(?i)(?:u(?:ll|l)?|(?:ll|l)u?)$", "", text)
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if text.lower().startswith("0b"):
            return int(text, 2)
        if len(text) > 1 and text.startswith("0") and text.isdigit():
            return int(text, 8)
        return int(text, 10)
    except ValueError:
        return None


def _c_div(left: int, right: int) -> int:
    quotient = abs(left) // abs(right)
    return -quotient if (left < 0) != (right < 0) else quotient


def _constant_binary(op: str, left: int, right: int) -> Optional[int]:
    try:
        if op == "+":
            return left + right
        if op == "-":
            return left - right
        if op == "*":
            return left * right
        if op == "/" and right != 0:
            return _c_div(left, right)
        if op == "%" and right != 0:
            return left - _c_div(left, right) * right
        if op == "<<" and right >= 0:
            return left << right
        if op == ">>" and right >= 0:
            return left >> right
        if op == "&":
            return left & right
        if op == "|":
            return left | right
        if op == "^":
            return left ^ right
    except (OverflowError, ValueError):
        return None
    return None


def _location_name(node) -> Optional[str]:
    if node is not None and type(node).__name__ == "ID":
        return str(node.name)
    return None


def _expression_range(node, state: Mapping[str, IntegerRange], ast_ctx=None, fn=None) -> Optional[IntegerRange]:
    if node is None:
        return None
    kind = type(node).__name__
    if kind == "Cast":
        return _expression_range(node.expr, state, ast_ctx, fn)
    if kind == "ID":
        named = _named_integer_limit(str(node.name), ast_ctx)
        if named is not None:
            return IntegerRange(named, named)
        fact = state.get(str(node.name))
        static_type = ast_ctx.infer_expr_type(node, fn) if ast_ctx is not None and fn is not None else None
        static_range = integer_type_range(static_type, ast_ctx) if static_type else None
        if fact is None:
            return static_range
        if static_range is None:
            return fact
        return fact.intersect(static_range)
    if kind == "Constant":
        value = _parse_integer_literal(str(getattr(node, "value", "")))
        return IntegerRange(value, value) if value is not None else None
    if kind == "UnaryOp":
        operand = _expression_range(node.expr, state, ast_ctx, fn)
        if operand is None:
            return None
        op = getattr(node, "op", None)
        if op == "+":
            return operand
        if op == "-":
            lower = -operand.upper if operand.upper is not None else None
            upper = -operand.lower if operand.lower is not None else None
            return IntegerRange(lower, upper)
        if operand.is_singleton and op == "~":
            value = ~operand.lower
            return IntegerRange(value, value)
        if operand.is_singleton and op == "!":
            value = int(not operand.lower)
            return IntegerRange(value, value)
        return None
    if kind == "BinaryOp":
        left = _expression_range(node.left, state, ast_ctx, fn)
        right = _expression_range(node.right, state, ast_ctx, fn)
        if left is None or right is None:
            return None
        op = getattr(node, "op", None)
        if left.is_singleton and right.is_singleton:
            value = _constant_binary(op, left.lower, right.lower)
            if value is not None:
                return IntegerRange(value, value)
        if op == "+" and None not in (left.lower, left.upper, right.lower, right.upper):
            return IntegerRange(left.lower + right.lower, left.upper + right.upper)
        if op == "-" and None not in (left.lower, left.upper, right.lower, right.upper):
            return IntegerRange(left.lower - right.upper, left.upper - right.lower)
        return None
    if kind == "TernaryOp":
        left = _expression_range(node.iftrue, state, ast_ctx, fn)
        right = _expression_range(node.iffalse, state, ast_ctx, fn)
        if left is None or right is None:
            return None
        return left.hull(right)
    return None


def _comparison_constraint(node, truth: bool, ast_ctx=None, fn=None) -> Dict[str, IntegerRange]:
    if node is None or type(node).__name__ != "BinaryOp":
        return {}
    op = getattr(node, "op", None)
    if op not in {"<", "<=", ">", ">=", "==", "!="}:
        return {}

    left_name = _location_name(node.left)
    right_name = _location_name(node.right)
    if left_name and not right_name:
        value_range = _expression_range(node.right, {}, ast_ctx, fn)
        variable = left_name
        orientation = op
    elif right_name and not left_name:
        value_range = _expression_range(node.left, {}, ast_ctx, fn)
        variable = right_name
        orientation = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}[op]
    else:
        return {}
    if value_range is None or not value_range.is_singleton:
        return {}
    value = value_range.lower

    if not truth:
        orientation = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}[orientation]
    if orientation == "<":
        return {variable: IntegerRange(upper=value - 1)}
    if orientation == "<=":
        return {variable: IntegerRange(upper=value)}
    if orientation == ">":
        return {variable: IntegerRange(lower=value + 1)}
    if orientation == ">=":
        return {variable: IntegerRange(lower=value)}
    if orientation == "==":
        return {variable: IntegerRange(value, value)}
    # ``!=`` produces a non-convex domain, which this interval lattice cannot
    # represent without becoming unsound. Leave it unknown.
    return {}


def _merge_constraints(left: Mapping[str, IntegerRange], right: Mapping[str, IntegerRange]) -> Dict[str, IntegerRange]:
    result = dict(left)
    for name, interval in right.items():
        prior = result.get(name)
        if prior is None:
            result[name] = interval
        else:
            combined = prior.intersect(interval)
            if combined is not None:
                result[name] = combined
    return result


def _condition_constraints(node, truth: bool, ast_ctx=None, fn=None) -> Dict[str, IntegerRange]:
    if node is None:
        return {}
    kind = type(node).__name__
    if kind == "UnaryOp" and getattr(node, "op", None) == "!":
        return _condition_constraints(node.expr, not truth, ast_ctx, fn)
    if kind == "BinaryOp":
        op = getattr(node, "op", None)
        if op == "&&" and truth:
            return _merge_constraints(
                _condition_constraints(node.left, True, ast_ctx, fn),
                _condition_constraints(node.right, True, ast_ctx, fn),
            )
        if op == "||" and not truth:
            return _merge_constraints(
                _condition_constraints(node.left, False, ast_ctx, fn),
                _condition_constraints(node.right, False, ast_ctx, fn),
            )
        return _comparison_constraint(node, truth, ast_ctx, fn)
    return {}


def _apply_constraints(
    state: Mapping[str, IntegerRange], constraints: Mapping[str, IntegerRange], ast_ctx=None, fn=None
) -> Optional[Dict[str, IntegerRange]]:
    result = dict(state)
    for name, constraint in constraints.items():
        current = result.get(name)
        if current is None and ast_ctx is not None and fn is not None:
            try:
                from pycparser import c_ast

                current = _expression_range(c_ast.ID(name), result, ast_ctx, fn)
            except ImportError:
                current = None
        combined = constraint if current is None else current.intersect(constraint)
        if combined is None:
            return None
        result[name] = combined
    return result


def _merge_states(left: Mapping[str, IntegerRange], right: Mapping[str, IntegerRange]) -> Dict[str, IntegerRange]:
    # A fact missing on either path is unknown on the join. Keeping only the
    # intersection of keys is what makes guard suppression dominance-safe.
    return {name: left[name].hull(right[name]) for name in left.keys() & right.keys()}


def _event_condition(event):
    node = getattr(event, "_ast_node", None)
    if node is None:
        return None
    if event.kind in {"if_cond", "while_cond", "do_cond", "for_cond"}:
        return getattr(node, "cond", None)
    return None


def _descendants(root):
    if root is None:
        return
    yield root
    for _, child in root.children():
        yield from _descendants(child)


class IntegerRangeAnalysis:
    """Range facts for one function's structured CFG."""

    def __init__(self, ast_ctx, function, cfg, facts_before: Mapping[int, Mapping[str, IntegerRange]]) -> None:
        self.ast_ctx = ast_ctx
        self.function = function
        self.cfg = cfg
        self._facts_before = facts_before
        self._ast_to_node: Dict[int, int] = {}
        for node_id, event in cfg.nodes.items():
            root = _event_condition(event) if event.kind.endswith("_cond") else getattr(event, "_ast_node", None)
            for child in _descendants(root):
                self._ast_to_node.setdefault(id(child), node_id)

    def range_before(self, location: str, node_id: int) -> Optional[IntegerRange]:
        return self._facts_before.get(node_id, {}).get(location)

    def range_for_expression(self, expression, at_node=None) -> Optional[IntegerRange]:
        node_id = self._ast_to_node.get(id(at_node if at_node is not None else expression))
        if node_id is None:
            node_id = self._ast_to_node.get(id(expression))
        state = self._facts_before.get(node_id, {}) if node_id is not None else {}
        return _expression_range(expression, state, self.ast_ctx, self.function)

    def proves_expression_fits(self, expression, destination_type: str, at_node=None) -> bool:
        destination = integer_type_range(destination_type, self.ast_ctx)
        source = self.range_for_expression(expression, at_node)
        return destination is not None and source is not None and source.fits_within(destination)


def _transfer_event(event, state: Mapping[str, IntegerRange], ast_ctx, fn) -> Dict[str, IntegerRange]:
    result = dict(state)
    node = getattr(event, "_ast_node", None)
    if node is None:
        return result
    kind = type(node).__name__
    if kind == "Decl" and getattr(node, "name", None):
        if getattr(node, "init", None) is None:
            result.pop(str(node.name), None)
        else:
            fact = _expression_range(node.init, state, ast_ctx, fn)
            if fact is None:
                result.pop(str(node.name), None)
            else:
                result[str(node.name)] = fact
    elif kind == "Assignment":
        target = _location_name(getattr(node, "lvalue", None))
        if target:
            if getattr(node, "op", None) == "=":
                fact = _expression_range(node.rvalue, state, ast_ctx, fn)
                if fact is None:
                    result.pop(target, None)
                else:
                    result[target] = fact
            else:
                result.pop(target, None)
    elif kind == "UnaryOp" and getattr(node, "op", None) in {"p++", "p--", "++", "--"}:
        target = _location_name(getattr(node, "expr", None))
        if target:
            current = _expression_range(node.expr, state, ast_ctx, fn)
            if current is None or current.lower is None or current.upper is None:
                result.pop(target, None)
            else:
                delta = 1 if "+" in node.op else -1
                result[target] = IntegerRange(current.lower + delta, current.upper + delta)
    return result


def analyze_integer_ranges(ast_ctx, function_name: str) -> Optional[IntegerRangeAnalysis]:
    """Analyze range provenance for ``function_name`` using its structured CFG."""

    fn = next((candidate for candidate in getattr(ast_ctx, "functions", ()) if candidate.name == function_name), None)
    funcdef = find_function_def(getattr(ast_ctx, "pycparser_ast", None), function_name)
    if fn is None or funcdef is None:
        return None
    cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, "line_map", None))
    if not cfg.nodes or cfg.entry is None:
        return IntegerRangeAnalysis(ast_ctx, fn, cfg, {})

    incoming: Dict[int, Dict[str, IntegerRange]] = {cfg.entry: {}}
    facts_before: Dict[int, Dict[str, IntegerRange]] = {}
    work = [cfg.entry]
    while work:
        node_id = work.pop(0)
        if node_id not in incoming:
            continue
        state = incoming[node_id]
        facts_before[node_id] = dict(state)
        event = cfg.nodes[node_id]
        outgoing = _transfer_event(event, state, ast_ctx, fn)
        condition = _event_condition(event)
        for index, successor in enumerate(event.successors):
            edge_state: Optional[Dict[str, IntegerRange]] = dict(outgoing)
            if condition is not None and index < 2:
                constraints = _condition_constraints(condition, index == 0, ast_ctx, fn)
                edge_state = _apply_constraints(edge_state, constraints, ast_ctx, fn)
            if edge_state is None:
                continue
            prior = incoming.get(successor)
            merged = edge_state if prior is None else _merge_states(prior, edge_state)
            if prior != merged:
                incoming[successor] = merged
                if successor not in work:
                    work.append(successor)

    return IntegerRangeAnalysis(ast_ctx, fn, cfg, facts_before)
