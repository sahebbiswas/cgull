from cgull.rules.preprocessor_simplification import PreprocessorSimplificationRule


def analyze(source: str):
    return PreprocessorSimplificationRule()._scan_source("test.c", source)


def test_absorption_is_reported():
    issues = analyze("#if A || (A && B)\nint x;\n#endif\n")
    assert len(issues) == 1
    issue = issues[0]
    assert issue.rule_id == "CGULL-055"
    assert issue.line_number == 1
    assert "A || (A && B)" in issue.message
    assert "to 'A'" in issue.message


def test_duplicate_term_is_reported():
    issues = analyze("#if A && A\nint x;\n#endif\n")
    assert len(issues) == 1
    assert "to 'A'" in issues[0].message


def test_parent_context_simplifies_nested_condition():
    source = "#if PARENT\n#  if PARENT && CHILD\nint x;\n#  endif\n#endif\n"
    issues = analyze(source)
    assert len(issues) == 1
    assert issues[0].line_number == 2
    assert "surrounding branch context" in issues[0].message
    assert "to 'CHILD'" in issues[0].message


def test_earlier_elif_context_can_simplify_condition():
    source = "#if A\nint a;\n#elif !A && B\nint b;\n#endif\n"
    issues = analyze(source)
    assert len(issues) == 1
    assert issues[0].line_number == 3
    assert "to 'B'" in issues[0].message


def test_reordered_equivalent_condition_is_not_reported():
    assert analyze("#if B || A\nint x;\n#endif\n") == []


def test_formatting_only_parentheses_are_not_reported():
    assert analyze("#if ((A))\nint x;\n#endif\n") == []


def test_unchanged_parent_is_not_reported_for_simplified_child():
    source = "#if PARENT\n#if PARENT && CHILD\nint x;\n#endif\n#endif\n"
    issues = analyze(source)
    assert len(issues) == 1
    assert issues[0].line_number == 2


def test_redundant_condition_is_left_to_reachability_rule():
    assert analyze("#if A\n#if A\nint x;\n#endif\n#endif\n") == []


def test_unreachable_condition_is_left_to_reachability_rule():
    assert analyze("#if A\n#if !A\nint x;\n#endif\n#endif\n") == []


def test_malformed_condition_stops_chain_reasoning_conservatively():
    source = "#if A\n#elif\n#elif A && A\n#endif\n"
    assert analyze(source) == []


def test_analysis_is_deterministic():
    source = "#if PARENT\n#if PARENT && CHILD\n#endif\n#endif\n"
    first = [(i.line_number, i.column_number, i.message) for i in analyze(source)]
    second = [(i.line_number, i.column_number, i.message) for i in analyze(source)]
    assert first == second
