"""Immutable symbolic conditions, adapted from the CPRE expression model.

This module does not parse or evaluate C integer expressions. Bare macro truth,
macro definedness and opaque predicates are independent atoms. Normalization
applies local Boolean identities, not SAT solving or integer reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import TypeAlias


def _name(name: str) -> None:
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ValueError("expected a C macro identifier")


@dataclass(frozen=True)
class Constant:
    value: bool

    def __post_init__(self) -> None:
        if type(self.value) is not bool:
            raise ValueError("constant value must be a bool")


@dataclass(frozen=True)
class Variable:
    """Truth of a macro's value; distinct from whether it is defined."""

    name: str

    def __post_init__(self) -> None:
        _name(self.name)


@dataclass(frozen=True)
class Defined:
    """Whether a macro is defined, including when its value is zero."""

    name: str

    def __post_init__(self) -> None:
        _name(self.name)


@dataclass(frozen=True)
class Predicate:
    """Opaque C expression; text is preserved exactly, including literals."""

    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("predicate text must be a nonempty string")


@dataclass(frozen=True)
class Negation:
    operand: Expression

    def __post_init__(self) -> None:
        _check_expression(self.operand)


@dataclass(frozen=True)
class Conjunction:
    operands: tuple[Expression, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "operands", tuple(self.operands))
        for operand in self.operands:
            _check_expression(operand)


@dataclass(frozen=True)
class Disjunction:
    operands: tuple[Expression, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "operands", tuple(self.operands))
        for operand in self.operands:
            _check_expression(operand)


BooleanAtom: TypeAlias = Variable | Defined | Predicate
Expression: TypeAlias = Constant | BooleanAtom | Negation | Conjunction | Disjunction
TRUE = Constant(True)
FALSE = Constant(False)


def _check_expression(expression: Expression) -> None:
    if not isinstance(expression, (Constant, Variable, Defined, Predicate,
                                   Negation, Conjunction, Disjunction)):
        raise TypeError("expected a symbolic expression")


def _sort_key(expression: Expression) -> tuple:
    # Display text alone cannot distinguish Variable("A") from Predicate("A").
    if isinstance(expression, Constant):
        return ("constant", expression.value)
    if isinstance(expression, Variable):
        return ("variable", expression.name)
    if isinstance(expression, Defined):
        return ("defined", expression.name)
    if isinstance(expression, Predicate):
        return ("predicate", expression.text)
    if isinstance(expression, Negation):
        return ("not", _sort_key(expression.operand))
    return (
        "and" if isinstance(expression, Conjunction) else "or",
        tuple(_sort_key(item) for item in expression.operands),
    )


def negate(expression: Expression) -> Expression:
    expression = simplify(expression)
    if isinstance(expression, Constant):
        return Constant(not expression.value)
    if isinstance(expression, Negation):
        return expression.operand
    return Negation(expression)


def conjunction(*expressions: Expression) -> Expression:
    operands: list[Expression] = []
    for expression in expressions:
        expression = simplify(expression)
        if expression == FALSE:
            return FALSE
        if expression == TRUE:
            continue
        if isinstance(expression, Conjunction):
            operands.extend(expression.operands)
        else:
            operands.append(expression)
    unique = set(operands)
    if any(
        (operand.operand if isinstance(operand, Negation) else Negation(operand))
        in unique for operand in unique
    ):
        return FALSE
    filtered = [
        operand
        for operand in unique
        if not (
            isinstance(operand, Disjunction)
            and any(term in unique for term in operand.operands)
        )
    ]
    if not filtered:
        return TRUE
    if len(filtered) == 1:
        return filtered[0]
    return Conjunction(tuple(sorted(filtered, key=_sort_key)))


def disjunction(*expressions: Expression) -> Expression:
    operands: list[Expression] = []
    for expression in expressions:
        expression = simplify(expression)
        if expression == TRUE:
            return TRUE
        if expression == FALSE:
            continue
        if isinstance(expression, Disjunction):
            operands.extend(expression.operands)
        else:
            operands.append(expression)
    unique = set(operands)
    if any(
        (operand.operand if isinstance(operand, Negation) else Negation(operand))
        in unique for operand in unique
    ):
        return TRUE
    filtered = [
        operand
        for operand in unique
        if not (
            isinstance(operand, Conjunction)
            and any(term in unique for term in operand.operands)
        )
    ]
    if not filtered:
        return FALSE
    if len(filtered) == 1:
        return filtered[0]
    return Disjunction(tuple(sorted(filtered, key=_sort_key)))


def simplify(expression: Expression) -> Expression:
    """Apply Boolean identities, including complements and absorption."""

    _check_expression(expression)
    if isinstance(expression, (Constant, Variable, Defined, Predicate)):
        return expression
    if isinstance(expression, Negation):
        return negate(expression.operand)
    if isinstance(expression, Conjunction):
        return conjunction(*expression.operands)
    return disjunction(*expression.operands)


def _precedence(expression: Expression) -> int:
    if isinstance(expression, Predicate):
        # Predicate text may contain lower-precedence C operators. Treat it as
        # low precedence so embedding it in Boolean output adds parentheses.
        return 0
    if isinstance(expression, Disjunction):
        return 1
    if isinstance(expression, Conjunction):
        return 2
    if isinstance(expression, Negation):
        return 3
    return 4


def _format_expression(expression: Expression, parent_precedence: int = 0) -> str:
    """Format an expression using conventional preprocessor operators."""

    if isinstance(expression, Constant):
        text = "1" if expression.value else "0"
    elif isinstance(expression, Variable):
        text = expression.name
    elif isinstance(expression, Defined):
        text = f"defined({expression.name})"
    elif isinstance(expression, Predicate):
        text = expression.text
    elif isinstance(expression, Negation):
        text = f"!{_format_expression(expression.operand, _precedence(expression))}"
    else:
        operator = " && " if isinstance(expression, Conjunction) else " || "
        precedence = _precedence(expression)
        text = operator.join(
            _format_expression(item, precedence) for item in expression.operands
        )
    return f"({text})" if _precedence(expression) < parent_precedence else text


def expression_atoms(expression: Expression) -> set[BooleanAtom]:
    """Return Boolean flags and opaque predicates referenced by an expression."""

    if isinstance(expression, Constant):
        return set()
    if isinstance(expression, (Variable, Defined, Predicate)):
        return {expression}
    if isinstance(expression, Negation):
        return expression_atoms(expression.operand)
    result: set[BooleanAtom] = set()
    for operand in expression.operands:
        result.update(expression_atoms(operand))
    return result


def normalize(expression: Expression) -> Expression:
    """Canonicalize association/order, identities, duplicates and absorption.

    This is not a complete equivalence test. Opaque predicate text is never
    rewritten; callers that tokenize C expressions own any lexical normalization.
    """
    return simplify(expression)


def format_expression(expression: Expression) -> str:
    """Render normalized Boolean structure with safe predicate parentheses."""
    return _format_expression(normalize(expression))


def ordered_atoms(expression: Expression) -> tuple[BooleanAtom, ...]:
    """Enumerate unique atoms deterministically, including unsimplified atoms."""
    return tuple(sorted(expression_atoms(expression), key=_sort_key))


def expression_predicates(expression: Expression) -> set[str]:
    """Return opaque predicate text without interpreting identifiers inside it."""
    return {atom.text for atom in expression_atoms(expression)
            if isinstance(atom, Predicate)}


def expression_to_dict(expression: Expression) -> dict[str, object]:
    """Return a canonical, tagged JSON-compatible expression representation."""
    return _to_dict(normalize(expression))


def _to_dict(expression: Expression) -> dict[str, object]:
    if isinstance(expression, Constant):
        return {"kind": "constant", "value": expression.value}
    if isinstance(expression, (Variable, Defined)):
        return {"kind": "defined" if isinstance(expression, Defined) else "variable",
                "name": expression.name}
    if isinstance(expression, Predicate):
        return {"kind": "predicate", "text": expression.text}
    if isinstance(expression, Negation):
        return {"kind": "not", "operand": _to_dict(expression.operand)}
    return {"kind": "and" if isinstance(expression, Conjunction) else "or",
            "operands": [_to_dict(item) for item in expression.operands]}


def expression_from_dict(data: object) -> Expression:
    """Read tagged data and normalize it; reject malformed/unknown fields."""
    return normalize(_from_dict(data))


def _from_dict(data: object) -> Expression:
    if not isinstance(data, dict):
        raise ValueError("expression must be an object")
    kind = data.get("kind")
    if kind == "constant" and set(data) == {"kind", "value"}:
        return Constant(data["value"])
    if kind in ("variable", "defined") and set(data) == {"kind", "name"}:
        return (Variable if kind == "variable" else Defined)(data["name"])
    if kind == "predicate" and set(data) == {"kind", "text"}:
        return Predicate(data["text"])
    if kind == "not" and set(data) == {"kind", "operand"}:
        return Negation(_from_dict(data["operand"]))
    if kind in ("and", "or") and set(data) == {"kind", "operands"}:
        if not isinstance(data["operands"], list):
            raise ValueError("operands must be an array")
        cls = Conjunction if kind == "and" else Disjunction
        return cls(tuple(_from_dict(item) for item in data["operands"]))
    raise ValueError("unknown expression kind or invalid fields")
