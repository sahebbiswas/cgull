"""Exact Boolean reasoning contracts for symbolic preprocessor conditions."""

import pytest

from cgull.preprocessor import (
    AnalysisLimitExceeded,
    BDD,
    Defined,
    Predicate,
    ResourceLimits,
    TRUE,
    Variable,
    conjunction,
    disjunction,
    equivalent,
    exact_simplify,
    implies,
    negate,
    satisfiable,
    witness_assignment,
)

A, B, C, D = map(Variable, "ABCD")


def _evaluate(expression, assignment):
    from cgull.preprocessor import Constant, Conjunction, Disjunction, Negation

    if isinstance(expression, Constant):
        return expression.value
    if isinstance(expression, (Variable, Defined, Predicate)):
        return assignment[expression]
    if isinstance(expression, Negation):
        return not _evaluate(expression.operand, assignment)
    values = (_evaluate(item, assignment) for item in expression.operands)
    return all(values) if isinstance(expression, Conjunction) else any(values)


def test_equivalence_is_semantic_not_structural_or_order_dependent():
    distributed = disjunction(conjunction(A, B), conjunction(A, C))
    factored = conjunction(A, disjunction(C, B))
    assert distributed != factored
    assert equivalent(distributed, factored)
    assert equivalent(disjunction(A, B), disjunction(B, A))
    assert not equivalent(conjunction(A, B), disjunction(A, B))


def test_tautology_contradiction_satisfiability_and_implication():
    tautology = disjunction(A, negate(A))
    contradiction = conjunction(A, negate(A))
    assert satisfiable(tautology)
    assert not satisfiable(contradiction)
    assert implies(conjunction(A, B), A)
    assert implies(contradiction, C)
    assert not implies(A, conjunction(A, B))


def test_nested_exact_queries_and_boolean_simplification():
    expression = disjunction(conjunction(A, B, disjunction(C, negate(D))), A)
    assert exact_simplify(expression) == A
    assert equivalent(expression, A)


def test_opaque_predicates_and_definedness_are_independent_atoms():
    opaque_gt = Predicate("VERSION > 3")
    opaque_le = Predicate("VERSION <= 3")
    defined_a = Defined("A")

    # The Boolean abstraction deliberately does not infer integer relationships.
    assert satisfiable(conjunction(opaque_gt, opaque_le))
    assert satisfiable(conjunction(defined_a, negate(A)))
    assert not implies(defined_a, A)
    assert not equivalent(Predicate("A"), A)


def test_witness_is_complete_valid_and_deterministic():
    opaque = Predicate("LEVEL >= 2")
    defined = Defined("FEATURE")
    expression = conjunction(
        disjunction(A, B),
        disjunction(defined, opaque),
        negate(C),
    )
    first = witness_assignment(expression)
    second = witness_assignment(expression)

    assert first is not None
    assert first == second
    assert tuple(first) == (defined, opaque, A, B, C)
    assert _evaluate(expression, first)
    # False-first traversal chooses the first satisfying lexicographic path.
    assert first == {
        defined: False,
        opaque: True,
        A: False,
        B: True,
        C: False,
    }


def test_unsatisfiable_expression_has_no_witness():
    assert witness_assignment(conjunction(A, negate(A))) is None


def test_resource_limits_have_conservative_public_fallbacks():
    expression = conjunction(A, B)
    limits = ResourceLimits(max_atoms=1)

    # No public helper may claim dead code, equivalence, or implication when the
    # exact engine could not complete.
    assert satisfiable(expression, limits=limits)
    assert not equivalent(expression, expression, limits=limits)
    assert not implies(expression, A, limits=limits)
    assert witness_assignment(expression, limits=limits) is None
    assert exact_simplify(expression, limits=limits) == expression


def test_low_level_bdd_reports_limit_kind_and_observed_value():
    with pytest.raises(AnalysisLimitExceeded) as excinfo:
        BDD((A, B), limits=ResourceLimits(max_atoms=1))
    assert excinfo.value.resource == "atoms"
    assert excinfo.value.limit == 1
    assert excinfo.value.observed == 2

    bdd = BDD((A,), limits=ResourceLimits(max_bdd_nodes=0, max_work=10))
    with pytest.raises(AnalysisLimitExceeded) as excinfo:
        bdd.build(A)
    assert excinfo.value.resource == "bdd_nodes"


def test_resource_limits_validate_configuration():
    for kwargs in (
        {"max_atoms": -1},
        {"max_bdd_nodes": -1},
        {"max_work": -1},
        {"max_atoms": 1.5},
        {"max_work": True},
    ):
        with pytest.raises(ValueError):
            ResourceLimits(**kwargs)


def test_work_budget_is_enforced():
    bdd = BDD((A,), limits=ResourceLimits(max_work=0))
    with pytest.raises(AnalysisLimitExceeded) as excinfo:
        bdd.build(A)
    assert excinfo.value.resource == "work"


def test_constant_witness_is_deterministic():
    assert witness_assignment(TRUE) == {}
