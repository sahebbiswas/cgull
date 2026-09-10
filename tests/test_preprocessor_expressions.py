"""Behavioral contracts for the standalone symbolic preprocessor IR."""

from dataclasses import FrozenInstanceError
from itertools import permutations, product
import json
import os
import subprocess
import sys

import pytest

from cgull.preprocessor import (
    Constant, Variable, Defined, Predicate, Negation, Conjunction, Disjunction,
    TRUE, FALSE, negate, conjunction, disjunction, normalize, simplify,
    format_expression, expression_atoms, ordered_atoms, expression_predicates,
    expression_to_dict, expression_from_dict,
)

A, B, C = map(Variable, 'ABC')


@pytest.mark.parametrize('expression, expected', [
    (TRUE, '1'), (FALSE, '0'), (A, 'A'), (Defined('X'), 'defined(X)'),
    (Predicate('VERSION >= 3'), 'VERSION >= 3'),
    (Negation(A), '!A'), (Negation(Disjunction((B, A))), '!(A || B)'),
    (Negation(Predicate('X ? Y : Z')), '!(X ? Y : Z)'),
    (Conjunction((A, Disjunction((C, B)))), '(B || C) && A'),
    (Disjunction((C, Conjunction((B, A)))), 'A && B || C'),
    (Conjunction((A, Predicate('X, Y'))), '(X, Y) && A'),
    (Conjunction(()), '1'), (Disjunction(()), '0'),
])
def test_format(expression, expected):
    assert format_expression(expression) == expected


@pytest.mark.parametrize('expression, expected', [
    (Negation(TRUE), FALSE), (Negation(FALSE), TRUE),
    (Negation(Negation(A)), A),
    (Conjunction((TRUE, A, A)), A), (Conjunction((FALSE, A)), FALSE),
    (Disjunction((FALSE, A, A)), A), (Disjunction((TRUE, A)), TRUE),
    (Conjunction((A, Negation(A))), FALSE),
    (Disjunction((A, Negation(A))), TRUE),
    (Conjunction((A, Disjunction((A, B)))), A),
    (Disjunction((A, Conjunction((A, B, Disjunction((C, Negation(B))))))), A),
    (Conjunction((B, Conjunction((C, A)))), Conjunction((A, B, C))),
    (Disjunction((B, Disjunction((C, A)))), Disjunction((A, B, C))),
    (Conjunction(()), TRUE), (Disjunction(()), FALSE),
])
def test_cpre_normalization(expression, expected):
    assert normalize(expression) == expected
    assert simplify(expression) == expected
    assert normalize(normalize(expression)) == expected


def test_factories_and_atom_identity():
    atoms = (Variable('X'), Defined('X'), Predicate('X'))
    assert len(set(atoms)) == 3
    assert conjunction() == TRUE
    assert disjunction() == FALSE
    assert negate(TRUE) == FALSE
    # Defined-to-zero macros must not become contradictions.
    assert conjunction(atoms[1], negate(atoms[0])) != FALSE
    expr = Conjunction((TRUE, atoms[0], Negation(atoms[1]),
                        Disjunction((atoms[2], atoms[0]))))
    assert expression_atoms(expr) == set(atoms)
    assert ordered_atoms(expr) == (atoms[1], atoms[2], atoms[0])
    assert expression_predicates(expr) == {'X'}
    assert expression_atoms(TRUE) == set()


@pytest.mark.parametrize('cls', [Conjunction, Disjunction])
def test_permutations_and_mutable_input(cls):
    atoms = [A, Predicate('A'), Defined('A'), Negation(B)]
    expected = normalize(cls(tuple(atoms)))
    for items in permutations(atoms):
        expression = cls(items)
        assert normalize(expression) == expected
        assert expression_to_dict(expression) == expression_to_dict(expected)
        assert format_expression(expression) == format_expression(expected)
    expression = cls(atoms)
    old_hash = hash(expression)
    atoms.clear()
    assert len(expression.operands) == 4
    assert hash(expression) == old_hash


@pytest.mark.parametrize('expression, field', [
    (TRUE, 'value'), (A, 'name'), (Defined('A'), 'name'),
    (Predicate('A > 1'), 'text'), (Negation(A), 'operand'),
    (Conjunction((A, B)), 'operands'), (Disjunction((A, B)), 'operands'),
])
def test_immutable_hashable_and_serializable(expression, field):
    assert {expression: 1}[expression] == 1
    with pytest.raises(FrozenInstanceError):
        setattr(expression, field, None)
    data = json.loads(json.dumps(expression_to_dict(expression)))
    assert expression_from_dict(data) == normalize(expression)


def test_serialization_contract_and_opaque_preservation():
    text = 'CHECK("a  b", VERSION > 3)'
    expression = Conjunction((Variable('X'), Negation(Defined('X')), Predicate(text)))
    assert expression_to_dict(expression) == {
        'kind': 'and', 'operands': [
            {'kind': 'not', 'operand': {'kind': 'defined', 'name': 'X'}},
            {'kind': 'predicate', 'text': text},
            {'kind': 'variable', 'name': 'X'},
        ],
    }
    assert expression_from_dict(expression_to_dict(expression)) == normalize(expression)
    assert Predicate(text) != Predicate(text.replace('a  b', 'a b'))
    assert normalize(Conjunction((Predicate('N > 3'), Predicate('N <= 3')))) != FALSE


@pytest.mark.parametrize('data', [
    None, [], {}, {'kind': 'unknown'}, {'kind': []},
    {'kind': 'constant', 'value': 1}, {'kind': 'variable', 'name': ''},
    {'kind': 'defined', 'name': 'A B'}, {'kind': 'predicate', 'text': ' '},
    {'kind': 'variable', 'name': 1}, {'kind': 'predicate', 'text': None},
    {'kind': 'not', 'operand': None}, {'kind': 'or', 'operands': {}},
    {'kind': 'and', 'operands': [None]},
    {'kind': 'constant', 'value': True, 'extra': 1},
])
def test_invalid_serialized_data(data):
    with pytest.raises(ValueError):
        expression_from_dict(data)


@pytest.mark.parametrize('factory', [
    lambda: Constant(1), lambda: Variable('bad name'), lambda: Defined(''),
    lambda: Predicate(''), lambda: Negation('A'),
    lambda: Conjunction(('A',)), lambda: Disjunction(('A',)),
    lambda: normalize('A'),
])
def test_invalid_nodes(factory):
    with pytest.raises((TypeError, ValueError)):
        factory()


def _evaluate(expression, values):
    if isinstance(expression, Constant):
        return expression.value
    if isinstance(expression, (Variable, Defined, Predicate)):
        return values[expression]
    if isinstance(expression, Negation):
        return not _evaluate(expression.operand, values)
    results = (_evaluate(item, values) for item in expression.operands)
    return all(results) if isinstance(expression, Conjunction) else any(results)


def test_normalization_preserves_boolean_truth_tables():
    atoms = (A, Defined('A'), Predicate('A'))
    terms = [TRUE, FALSE, *atoms, *(Negation(atom) for atom in atoms)]
    terms += [cls(pair) for cls in (Conjunction, Disjunction)
              for pair in product(atoms, repeat=2)]
    for left, right in product(terms, repeat=2):
        for cls in (Conjunction, Disjunction):
            expression = cls((left, right, Negation(atoms[0])))
            normalized = normalize(expression)
            assert normalize(normalized) == normalized
            for bits in product((False, True), repeat=3):
                values = dict(zip(atoms, bits))
                assert _evaluate(expression, values) == _evaluate(normalized, values)


def test_determinism_across_hash_seeds():
    script = '''
import json
from cgull.preprocessor import *
expr = Disjunction(tuple({Variable('X'), Predicate('X'), Defined('X'),
                         Conjunction((Variable('B'), Negation(Variable('A'))))}))
print(format_expression(expr))
print(json.dumps(expression_to_dict(expr)))
print(repr(ordered_atoms(expr)))
'''
    outputs = [subprocess.check_output(
        [sys.executable, '-c', script], text=True,
        env={**os.environ, 'PYTHONHASHSEED': seed},
    ) for seed in ('1', '17', '123')]
    assert len(set(outputs)) == 1
