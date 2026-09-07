"""Conservative CFG-backed integer range provenance."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, Mapping, Optional

from ..ast_analyzer.integer_types import _resolved_scalar_type, get_integer_type_byte_size
from .construction import build_cfg, find_function_def

__all__ = ["IntegerRange", "IntegerRangeAnalysis", "analyze_integer_ranges", "integer_type_range"]


@dataclass(frozen=True)
class IntegerRange:
    """Inclusive interval; ``None`` means an unbounded endpoint."""

    lower: Optional[int] = None
    upper: Optional[int] = None

    @property
    def is_singleton(self) -> bool:
        return self.lower is not None and self.lower == self.upper

    def intersect(self, other: "IntegerRange") -> Optional["IntegerRange"]:
        lower = other.lower if self.lower is None else self.lower if other.lower is None else max(self.lower, other.lower)
        upper = other.upper if self.upper is None else self.upper if other.upper is None else min(self.upper, other.upper)
        if lower is not None and upper is not None and lower > upper:
            return None
        return IntegerRange(lower, upper)

    def hull(self, other: "IntegerRange") -> "IntegerRange":
        lower = None if self.lower is None or other.lower is None else min(self.lower, other.lower)
        upper = None if self.upper is None or other.upper is None else max(self.upper, other.upper)
        return IntegerRange(lower, upper)

    def fits_within(self, destination: "IntegerRange") -> bool:
        if self.lower is None or self.upper is None:
            return False
        if destination.lower is not None and self.lower < destination.lower:
            return False
        if destination.upper is not None and self.upper > destination.upper:
            return False
        return True


def _widen(previous: IntegerRange, current: IntegerRange) -> IntegerRange:
    """Widen moving endpoints so ascending chains converge conservatively."""

    lower = current.lower
    upper = current.upper
    if previous.lower is None or current.lower is None or current.lower < previous.lower:
        lower = None
    if previous.upper is None or current.upper is None or current.upper > previous.upper:
        upper = None
    return IntegerRange(lower, upper)


def integer_type_range(type_name: str, ast_ctx=None) -> Optional[IntegerRange]:
    resolved = _resolved_scalar_type(type_name, ast_ctx)
    width = get_integer_type_byte_size(type_name, ast_ctx)
    if not resolved or width is None:
        return None
    normalized = resolved.lower()
    if normalized in {"char", "time_t"}:
        return None
    unsigned = normalized.startswith(("unsigned", "uint")) or normalized in {"size_t", "uintptr_t"}
    signed = normalized.startswith(("signed", "int", "short", "long")) or normalized in {
        "ssize_t", "intptr_t", "ptrdiff_t"
    }
    if not unsigned and not signed:
        return None
    bits = width * 8
    return IntegerRange(0, (1 << bits) - 1) if unsigned else IntegerRange(-(1 << (bits - 1)), (1 << (bits - 1)) - 1)


def _portable_char_range(ast_ctx=None) -> Optional[IntegerRange]:
    """Nonnegative values representable with either plain-char signedness."""
    width = get_integer_type_byte_size("char", ast_ctx)
    return IntegerRange(0, (1 << (width * 8 - 1)) - 1) if width is not None else None


_LIMIT_RE = re.compile(r"^(U?INT)(8|16|32|64)_(MIN|MAX)$")


def _named_limit(name: str, ast_ctx=None) -> Optional[int]:
    match = _LIMIT_RE.fullmatch(name)
    if match:
        family, bits_text, bound = match.groups()
        bits = int(bits_text)
        if family == "UINT":
            return 0 if bound == "MIN" else (1 << bits) - 1
        return -(1 << (bits - 1)) if bound == "MIN" else (1 << (bits - 1)) - 1
    aliases = {
        "SCHAR_MAX": "signed char", "UCHAR_MAX": "unsigned char",
        "SHRT_MAX": "short", "USHRT_MAX": "unsigned short",
        "INT_MAX": "int", "UINT_MAX": "unsigned int",
        "LONG_MAX": "long", "ULONG_MAX": "unsigned long",
        "LLONG_MAX": "long long", "ULLONG_MAX": "unsigned long long",
        "SIZE_MAX": "size_t",
        "SSIZE_MAX": "ssize_t",
        "UINTPTR_MAX": "uintptr_t",
        "INTPTR_MAX": "intptr_t",
        "PTRDIFF_MAX": "ptrdiff_t",
    }
    bounds = integer_type_range(aliases[name], ast_ctx) if name in aliases else None
    return bounds.upper if bounds else None


def _literal(text: str) -> Optional[int]:
    if text.startswith("'"):
        import ast
        try:
            character = ast.literal_eval(text)
        except (SyntaxError, ValueError):
            return None
        # Multi-character and non-ASCII execution encodings are target-specific.
        if isinstance(character, str) and len(character) == 1 and ord(character) < 128:
            return ord(character)
        return None
    text = re.sub(r"(?i)(?:u(?:ll|l)?|(?:ll|l)u?)$", "", text.strip())
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
    q = abs(left) // abs(right)
    return -q if (left < 0) != (right < 0) else q


def _constant_binary(op: str, left: int, right: int) -> Optional[int]:
    if op == "+": return left + right
    if op == "-": return left - right
    if op == "*": return left * right
    if op == "/" and right: return _c_div(left, right)
    if op == "%" and right: return left - _c_div(left, right) * right
    if op == "<<" and right >= 0: return left << right
    if op == ">>" and right >= 0: return left >> right
    if op == "&": return left & right
    if op == "|": return left | right
    if op == "^": return left ^ right
    return None


def _name(node) -> Optional[str]:
    return str(node.name) if node is not None and type(node).__name__ == "ID" else None


def _expr_range(node, state: Mapping[str, IntegerRange], ast_ctx=None, fn=None) -> Optional[IntegerRange]:
    if node is None:
        return None
    kind = type(node).__name__
    if kind == "Cast":
        from ..ast_analyzer import _format_pycparser_expr
        destination = integer_type_range(_format_pycparser_expr(node.to_type), ast_ctx)
        source = _expr_range(node.expr, state, ast_ctx, fn)
        if destination is None and _resolved_scalar_type(_format_pycparser_expr(node.to_type), ast_ctx) == "char":
            portable = _portable_char_range(ast_ctx)
            return source if source is not None and portable is not None and source.fits_within(portable) else None
        return source if destination is not None and source is not None and source.fits_within(destination) else destination
    if kind == "ID":
        limit = _named_limit(str(node.name), ast_ctx)
        if limit is not None:
            return IntegerRange(limit, limit)
        fact = state.get(str(node.name))
        type_name = ast_ctx.infer_expr_type(node, fn) if ast_ctx is not None and fn is not None else None
        static = integer_type_range(type_name, ast_ctx) if type_name else None
        if fact is None:
            return static
        return fact if static is None else fact.intersect(static)
    if kind == "Constant":
        value = _literal(str(getattr(node, "value", "")))
        return IntegerRange(value, value) if value is not None else None
    if kind == "UnaryOp":
        value = _expr_range(node.expr, state, ast_ctx, fn)
        if value is None:
            return None
        if node.op == "+": return value
        if node.op == "-":
            return IntegerRange(-value.upper if value.upper is not None else None, -value.lower if value.lower is not None else None)
        if value.is_singleton and node.op == "~": return IntegerRange(~value.lower, ~value.lower)
        if value.is_singleton and node.op == "!":
            folded = int(not value.lower)
            return IntegerRange(folded, folded)
        return None
    if kind == "BinaryOp":
        left = _expr_range(node.left, state, ast_ctx, fn)
        right = _expr_range(node.right, state, ast_ctx, fn)
        if left is None or right is None:
            return None
        if left.is_singleton and right.is_singleton:
            folded = _constant_binary(node.op, left.lower, right.lower)
            if folded is not None:
                return IntegerRange(folded, folded)
        if node.op == "+" and None not in (left.lower, left.upper, right.lower, right.upper):
            return IntegerRange(left.lower + right.lower, left.upper + right.upper)
        if node.op == "-" and None not in (left.lower, left.upper, right.lower, right.upper):
            return IntegerRange(left.lower - right.upper, left.upper - right.lower)
        return None
    if kind == "TernaryOp":
        left = _expr_range(node.iftrue, state, ast_ctx, fn)
        right = _expr_range(node.iffalse, state, ast_ctx, fn)
        return left.hull(right) if left is not None and right is not None else None
    return None


def _comparison(node, truth: bool, ast_ctx=None, fn=None) -> Dict[str, IntegerRange]:
    if node is None or type(node).__name__ != "BinaryOp" or node.op not in {"<", "<=", ">", ">=", "==", "!="}:
        return {}
    left_name, right_name = _name(node.left), _name(node.right)
    left_value = _expr_range(node.left, {}, ast_ctx, fn)
    right_value = _expr_range(node.right, {}, ast_ctx, fn)
    if left_name and right_value is not None and right_value.is_singleton:
        variable, value, op = left_name, right_value.lower, node.op
    elif right_name and left_value is not None and left_value.is_singleton:
        variable, value = right_name, left_value.lower
        op = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}[node.op]
    else:
        return {}
    # A signed operand may be converted to unsigned by C's usual arithmetic
    # conversions. Mathematical bounds are not valid for that comparison.
    if ast_ctx is not None and fn is not None:
        variable_node = node.left if left_name == variable else node.right
        bound_node = node.right if left_name == variable else node.left
        variable_type = ast_ctx.infer_expr_type(variable_node, fn)
        bound_type = getattr(bound_node, "type", None) if type(bound_node).__name__ == "Constant" else ast_ctx.infer_expr_type(bound_node, fn)
        variable_range = integer_type_range(variable_type, ast_ctx) if variable_type else None
        if variable_type and _resolved_scalar_type(variable_type, ast_ctx) == "char":
            # Unknown plain char may be signed; unsigned comparisons cannot
            # establish nonnegativity on every supported target.
            variable_range = integer_type_range("signed char", ast_ctx)
        bound_range = integer_type_range(bound_type, ast_ctx) if isinstance(bound_type, str) else None
        if variable_range is not None and bound_range is not None and variable_range.lower < 0 and bound_range.lower == 0 and bound_range.upper > variable_range.upper:
            return {}
    if not truth:
        op = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}[op]
    if op == "<": return {variable: IntegerRange(upper=value - 1)}
    if op == "<=": return {variable: IntegerRange(upper=value)}
    if op == ">": return {variable: IntegerRange(lower=value + 1)}
    if op == ">=": return {variable: IntegerRange(lower=value)}
    if op == "==": return {variable: IntegerRange(value, value)}
    return {}


def _constraints(node, truth: bool, ast_ctx=None, fn=None) -> Dict[str, IntegerRange]:
    if node is None:
        return {}
    if type(node).__name__ == "UnaryOp" and node.op == "!":
        return _constraints(node.expr, not truth, ast_ctx, fn)
    if type(node).__name__ != "BinaryOp":
        return {}
    if node.op == "&&" and truth or node.op == "||" and not truth:
        result = _constraints(node.left, truth, ast_ctx, fn)
        for name, interval in _constraints(node.right, truth, ast_ctx, fn).items():
            prior = result.get(name)
            combined = interval if prior is None else prior.intersect(interval)
            if combined is not None:
                result[name] = combined
        return result
    return _comparison(node, truth, ast_ctx, fn)


def _apply(state: Mapping[str, IntegerRange], constraints: Mapping[str, IntegerRange], ast_ctx, fn) -> Optional[Dict[str, IntegerRange]]:
    result = dict(state)
    if constraints and ast_ctx is not None and fn is not None:
        from pycparser import c_ast
    for name, interval in constraints.items():
        current = result.get(name)
        if current is None and ast_ctx is not None and fn is not None:
            current = _expr_range(c_ast.ID(name), result, ast_ctx, fn)
        combined = interval if current is None else current.intersect(interval)
        if combined is None:
            return None
        result[name] = combined
    return result


def _merge(left: Mapping[str, IntegerRange], right: Mapping[str, IntegerRange]) -> Dict[str, IntegerRange]:
    return {name: left[name].hull(right[name]) for name in left.keys() & right.keys()}


def _condition(event):
    node = getattr(event, "_ast_node", None)
    if node is not None and type(node).__name__ == "If":
        def empty(branch):
            return branch is None or type(branch).__name__ == "EmptyStatement" or (
                type(branch).__name__ == "Compound" and not branch.block_items
            )
        # Both branches reach the same successor; this edge proves no bound.
        if empty(node.iftrue) and empty(node.iffalse):
            return None
    return getattr(node, "cond", None) if node is not None and event.kind in {"if_cond", "while_cond", "do_cond", "for_cond"} else None


def _descendants(root):
    if root is not None:
        yield root
        for _, child in root.children():
            yield from _descendants(child)


def _transfer(event, state: Mapping[str, IntegerRange], ast_ctx, fn, exposed=()) -> Dict[str, IntegerRange]:
    result = dict(state)
    node = getattr(event, "_ast_node", None)
    if node is None:
        return result
    kind = type(node).__name__
    written = None
    if kind == "Decl" and getattr(node, "name", None):
        written = str(node.name)
        fact = _expr_range(node.init, state, ast_ctx, fn) if getattr(node, "init", None) is not None else None
        result[str(node.name)] = fact if fact is not None else result.pop(str(node.name), None)
        if fact is None:
            result.pop(str(node.name), None)
    elif kind == "Assignment":
        target = _name(getattr(node, "lvalue", None))
        written = target
        if target:
            fact = _expr_range(node.rvalue, state, ast_ctx, fn) if node.op == "=" else None
            if fact is None: result.pop(target, None)
            else: result[target] = fact
    elif kind == "UnaryOp" and node.op in {"p++", "p--", "++", "--"}:
        target = _name(node.expr)
        written = target
        if target:
            current = _expr_range(node.expr, state, ast_ctx, fn)
            if current is None or current.lower is None or current.upper is None:
                result.pop(target, None)
            else:
                delta = 1 if "+" in node.op else -1
                result[target] = IntegerRange(current.lower + delta, current.upper + delta)
    if written and written in result:
        from pycparser import c_ast
        destination_type = ast_ctx.infer_expr_type(c_ast.ID(written), fn)
        if _resolved_scalar_type(destination_type, ast_ctx) == "char":
            portable = _portable_char_range(ast_ctx)
            # An out-of-range write can become negative on a signed-char target.
            # Drop its pre-conversion fact instead of proving nonnegativity from it.
            if portable is None or not result[written].fits_within(portable):
                result.pop(written, None)
    if getattr(event, "calls", ()) or (kind == "Assignment" and _name(node.lvalue) is None):
        for name in exposed:
            result.pop(name, None)
    return result


class IntegerRangeAnalysis:
    def __init__(self, ast_ctx, function, cfg, facts_before: Mapping[int, Mapping[str, IntegerRange]]) -> None:
        self.ast_ctx, self.function, self.cfg = ast_ctx, function, cfg
        self._facts_before = facts_before
        self._ast_to_node: Dict[int, int] = {}
        for node_id, event in cfg.nodes.items():
            root = _condition(event) if event.kind.endswith("_cond") else getattr(event, "_ast_node", None)
            for child in _descendants(root):
                self._ast_to_node.setdefault(id(child), node_id)

    def range_before(self, location: str, node_id: int) -> Optional[IntegerRange]:
        return self._facts_before.get(node_id, {}).get(location)

    def range_for_expression(self, expression, at_node=None) -> Optional[IntegerRange]:
        node_id = self._ast_to_node.get(id(at_node if at_node is not None else expression))
        if node_id is None:
            node_id = self._ast_to_node.get(id(expression))
        state = self._facts_before.get(node_id, {}) if node_id is not None else {}
        return _expr_range(expression, state, self.ast_ctx, self.function)

    def proves_expression_fits(self, expression, destination_type: str, at_node=None) -> bool:
        destination = integer_type_range(destination_type, self.ast_ctx)
        if destination is None and _resolved_scalar_type(destination_type, self.ast_ctx) == "char":
            # Values common to signed and unsigned plain-char models are portable.
            destination = _portable_char_range(self.ast_ctx)
        source = self.range_for_expression(expression, at_node)
        return destination is not None and source is not None and source.fits_within(destination)


def analyze_integer_ranges(ast_ctx, function_name: str) -> Optional[IntegerRangeAnalysis]:
    fn = next((candidate for candidate in getattr(ast_ctx, "functions", ()) if candidate.name == function_name), None)
    funcdef = find_function_def(getattr(ast_ctx, "pycparser_ast", None), function_name)
    if fn is None or funcdef is None:
        return None
    cfg = build_cfg(funcdef, line_map=getattr(ast_ctx, "line_map", None))
    if not cfg.nodes or cfg.entry is None:
        return IntegerRangeAnalysis(ast_ctx, fn, cfg, {})

    # Once an address escapes, a call or indirect write can invalidate its fact.
    exposed = set(getattr(ast_ctx, "global_variables", {}))
    for node in _descendants(funcdef):
        if type(node).__name__ == "UnaryOp" and node.op == "&" and _name(node.expr):
            exposed.add(_name(node.expr))

    incoming: Dict[int, Dict[str, IntegerRange]] = {cfg.entry: {}}
    facts_before: Dict[int, Dict[str, IntegerRange]] = {}
    processed: Dict[int, int] = {}
    work = [cfg.entry]
    while work:
        node_id = work.pop(0)
        processed[node_id] = processed.get(node_id, 0) + 1
        state = incoming[node_id]
        facts_before[node_id] = dict(state)
        event = cfg.nodes[node_id]
        outgoing = _transfer(event, state, ast_ctx, fn, exposed)
        condition = _condition(event)
        for index, successor in enumerate(event.successors):
            edge_state = dict(outgoing)
            if condition is not None and index < 2:
                edge_state = _apply(edge_state, _constraints(condition, index == 0, ast_ctx, fn), ast_ctx, fn)
            if edge_state is None:
                continue
            prior = incoming.get(successor)
            merged = edge_state if prior is None else _merge(prior, edge_state)
            if prior is not None and processed.get(successor, 0) >= 1:
                merged = {name: _widen(prior[name], merged[name]) for name in prior.keys() & merged.keys()}
            if prior != merged:
                incoming[successor] = merged
                if successor not in work:
                    work.append(successor)

    return IntegerRangeAnalysis(ast_ctx, fn, cfg, facts_before)