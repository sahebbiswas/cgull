"""Witness configurations for symbolic preprocessor branches."""

from cgull.preprocessor import (
    ResourceLimits,
    WitnessAssignment,
    WitnessStatus,
    derive_branch_witnesses,
    parse_conditional_directives,
)


def witnesses(source: str, **kwargs):
    return derive_branch_witnesses(parse_conditional_directives(source), **kwargs)


def test_if_elif_else_witnesses_exclude_prior_alternatives():
    results = witnesses("#if A\na\n#elif B\nb\n#else\nc\n#endif\n")

    assert [result.status for result in results] == [
        WitnessStatus.SATISFIABLE,
        WitnessStatus.SATISFIABLE,
        WitnessStatus.SATISFIABLE,
    ]
    assert results[0].assignments == (WitnessAssignment("macro_value", "A", True),)
    assert results[1].assignments == (
        WitnessAssignment("macro_value", "A", False),
        WitnessAssignment("macro_value", "B", True),
    )
    assert results[2].assignments == (
        WitnessAssignment("macro_value", "A", False),
        WitnessAssignment("macro_value", "B", False),
    )


def test_nested_branch_includes_parent_condition():
    results = witnesses("#ifdef OUTER\n#if INNER\nbody\n#endif\n#endif\n")

    assert len(results) == 2
    assert results[1].assignments == (
        WitnessAssignment("defined", "OUTER", True),
        WitnessAssignment("macro_value", "INNER", True),
    )


def test_contradictory_elif_is_unreachable_without_witness():
    results = witnesses("#if A\na\n#elif A\nb\n#endif\n")

    assert results[1].status is WitnessStatus.UNREACHABLE
    assert not results[1].has_witness
    assert results[1].assignments == ()


def test_opaque_predicate_is_explicit_not_fabricated_as_macro_value():
    result, = witnesses("#if VERSION >= 3\nbody\n#endif\n")

    assert result.status is WitnessStatus.SATISFIABLE
    assert result.assignments == (
        WitnessAssignment("predicate", "VERSION >= 3", True),
    )


def test_multiple_assignments_choose_stable_false_first_witness():
    source = "#if B || A\nbody\n#endif\n"
    first, = witnesses(source)
    second, = witnesses(source)

    expected = (
        WitnessAssignment("macro_value", "A", False),
        WitnessAssignment("macro_value", "B", True),
    )
    assert first.assignments == expected
    assert second.assignments == expected


def test_resource_limit_is_distinct_from_unreachable():
    result, = witnesses(
        "#if A || B\nbody\n#endif\n",
        limits=ResourceLimits(max_atoms=1),
    )

    assert result.status is WitnessStatus.LIMIT_EXCEEDED
    assert result.assignments == ()
    assert result.limit_resource == "atoms"
    assert result.limit_value == 1
    assert result.limit_observed == 2


def test_malformed_condition_marks_chain_unsupported():
    results = witnesses("#if\na\n#else\nb\n#endif\n")

    assert [result.status for result in results] == [
        WitnessStatus.UNSUPPORTED,
        WitnessStatus.UNSUPPORTED,
    ]
    assert all(result.effective_condition is None for result in results)


def test_unreachable_parent_makes_nested_branch_unreachable():
    results = witnesses("#if A && !A\n#if CHILD\nbody\n#endif\n#endif\n")

    assert [result.status for result in results] == [
        WitnessStatus.UNREACHABLE,
        WitnessStatus.UNREACHABLE,
    ]
