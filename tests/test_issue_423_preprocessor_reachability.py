from cgull.rules.preprocessor_reachability import PreprocessorReachabilityRule


def analyze(source: str):
    return PreprocessorReachabilityRule()._scan_source("test.c", source)


def test_if_zero_is_unreachable_with_source_location():
    issues = analyze("  #if 0\nint x;\n#endif\n")
    assert len(issues) == 1
    issue = issues[0]
    assert issue.rule_id == "CGULL-054"
    assert issue.line_number == 1
    assert issue.column_number == 1
    assert "unreachable" in issue.message.lower()
    assert issue.code_snippet.strip() == "#if 0"


def test_shadowed_elif_is_unreachable():
    issues = analyze("#if A\nint a;\n#elif A && B\nint b;\n#endif\n")
    assert len(issues) == 1
    assert issues[0].line_number == 3
    assert "unreachable" in issues[0].message.lower()


def test_parent_context_makes_nested_branch_unreachable():
    issues = analyze("#if A\n#if !A\nint x;\n#endif\n#endif\n")
    assert len(issues) == 1
    assert issues[0].line_number == 2
    assert "effective condition" in issues[0].message


def test_parent_context_can_make_nested_condition_redundant():
    issues = analyze("#if A\n#if A\nint x;\n#endif\n#endif\n")
    assert len(issues) == 1
    assert issues[0].line_number == 2
    assert "redundant" in issues[0].message.lower()


def test_elif_condition_guaranteed_by_chain_is_redundant():
    issues = analyze("#if A\nint a;\n#elif !A\nint b;\n#endif\n")
    assert len(issues) == 1
    assert issues[0].line_number == 3
    assert "redundant" in issues[0].message.lower()


def test_mutually_satisfiable_branches_are_not_flagged():
    assert analyze("#if A\nint a;\n#elif B\nint b;\n#endif\n") == []


def test_else_shadowed_by_exhaustive_chain_is_unreachable():
    issues = analyze("#if A\nint a;\n#elif !A\nint b;\n#else\nint c;\n#endif\n")
    assert len(issues) == 2
    assert "redundant" in issues[0].message.lower()
    assert issues[1].line_number == 5
    assert "unreachable" in issues[1].message.lower()


def test_analysis_is_deterministic():
    source = "#if A\n#elif A && B\n#endif\n"
    first = [(i.line_number, i.column_number, i.message) for i in analyze(source)]
    second = [(i.line_number, i.column_number, i.message) for i in analyze(source)]
    assert first == second


def test_malformed_condition_stops_chain_reasoning_conservatively():
    source = "#if A\n#elif\n#elif A\n#endif\n"
    assert analyze(source) == []
