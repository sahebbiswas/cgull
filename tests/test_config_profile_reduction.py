"""Configuration-space reduction keeps branch coverage while dropping duplicate work."""

from cgull import AnalysisEngine, CGullScanner
from cgull.models import ConfigProfile
from cgull.preprocessor import reduce_generated_profiles
from cgull.rules.banned_functions import BannedFunctionsRule
from cgull.telemetry import telemetry_for


def _profile(name, *defined):
    return ConfigProfile(name=name, flags={flag: None for flag in defined})


def test_reduces_equivalent_exhaustive_variants_and_preserves_branch_coverage():
    source = """\
#if A
int a;
#elif B
int b;
#else
int fallback;
#endif
"""
    candidates = [
        _profile("none"),
        _profile("a", "A"),
        _profile("b", "B"),
        _profile("a-b", "A", "B"),
    ]

    result = reduce_generated_profiles([source], candidates)

    assert result.stats.candidate_count == 4
    assert result.stats.retained_count == 3
    assert result.stats.equivalent_removed == 1
    assert result.stats.unreachable_removed == 0
    assert [dict(p.flags) for p in result.profiles] == [{}, {"A": None}, {"B": None}]


def test_reduction_is_stable_across_candidate_input_order():
    source = "#if A\n#elif B\n#else\n#endif\n"
    candidates = [
        _profile("z", "A", "B"),
        _profile("a", "A"),
        _profile("b", "B"),
        _profile("none"),
    ]

    first = reduce_generated_profiles([source], candidates)
    second = reduce_generated_profiles([source], list(reversed(candidates)))

    assert first.profiles == second.profiles
    assert first.stats == second.stats
    assert [p.name for p in first.profiles] == ["none", "a", "b"]


def test_nested_parent_and_elif_exclusion_are_part_of_equivalence_signature():
    source = """\
#if A
# if B
int ab;
# else
int a_only;
# endif
#elif B
int b_only;
#endif
"""
    candidates = [
        _profile("none"),
        _profile("a", "A"),
        _profile("b", "B"),
        _profile("ab", "A", "B"),
    ]

    result = reduce_generated_profiles([source], candidates)

    # All four candidates have distinct modeled behavior here: the no-flag
    # configuration is the stable representative of the empty-signature class.
    assert result.stats.candidate_count == 4
    assert result.stats.retained_count == 4
    assert result.stats.removed_count == 0
    assert {frozenset(p.flags) for p in result.profiles} == {
        frozenset(),
        frozenset({"A"}),
        frozenset({"B"}),
        frozenset({"A", "B"}),
    }


def test_empty_branch_signature_is_deduplicated_not_discarded():
    source = "#if defined(A) && defined(B)\nint both;\n#endif\n"
    candidates = [
        _profile("none"),
        _profile("a", "A"),
        _profile("b", "B"),
        _profile("ab", "A", "B"),
    ]

    result = reduce_generated_profiles([source], candidates)

    assert result.stats.candidate_count == 4
    assert result.stats.retained_count == 2
    assert result.stats.equivalent_removed == 2
    assert result.stats.unreachable_removed == 0
    assert [dict(profile.flags) for profile in result.profiles] == [{}, {"A": None, "B": None}]


def test_opaque_predicates_are_not_fabricated_as_macro_values():
    source = "#if VERSION >= 3\nint modern;\n#else\nint old;\n#endif\n"
    candidates = [_profile("one"), _profile("two", "UNRELATED")]

    result = reduce_generated_profiles([source], candidates)

    # VERSION >= 3 remains a free symbolic predicate under both profiles, so
    # both candidates activate the same modeled region set. Deterministic
    # reduction may keep one, but it never invents a VERSION integer value.
    assert result.stats.retained_count == 1
    assert dict(result.profiles[0].flags) == {}


def test_malformed_conditions_disable_behavior_based_reduction_conservatively():
    source = "#if\nint malformed;\n#endif\n"
    candidates = [_profile("a", "A"), _profile("b", "B")]

    result = reduce_generated_profiles([source], candidates)

    assert result.stats.candidate_count == 2
    assert result.stats.retained_count == 2
    assert result.stats.removed_count == 0


def test_exact_duplicate_flag_maps_are_safe_even_without_modeled_branches():
    candidates = [ConfigProfile("z", {"A": None}), ConfigProfile("a", {"A": None})]

    result = reduce_generated_profiles(["int x;\n"], candidates)

    assert result.stats.candidate_count == 2
    assert result.stats.retained_count == 1
    assert result.stats.equivalent_removed == 1
    assert result.profiles[0].name == "a"


def test_generated_scan_reduces_actual_variant_count_without_losing_branch_findings():
    source = """\
void f(char *d, char *s) {
#if defined(A)
    strcpy(d, s);
#elif defined(B)
    strcat(d, s);
#else
    gets(d);
#endif
}
"""
    explicit = [
        _profile("none"),
        _profile("a", "A"),
        _profile("b", "B"),
        _profile("ab", "A", "B"),
    ]
    scanner = CGullScanner(
        rules=[BannedFunctionsRule()],
        engine_mode=AnalysisEngine.HYBRID,
    )

    full = scanner.scan_text(source, profiles=explicit)
    reduced = scanner.scan_text(
        source,
        config_strategy="exhaustive",
        exhaustive_threshold=10,
    )

    stats = reduced.config_reduction_stats
    assert (stats.candidate_count, stats.retained_count) == (4, 3)
    assert stats.equivalent_removed == 1
    assert telemetry_for(reduced).analyzed_lines == reduced.total_lines_of_code * 3
    assert telemetry_for(full).analyzed_lines == full.total_lines_of_code * 4
    assert {
        (issue.rule_id, issue.line_number, issue.code_snippet.strip())
        for issue in reduced.issues
    } == {
        (issue.rule_id, issue.line_number, issue.code_snippet.strip())
        for issue in full.issues
    }


def test_generated_reduction_preserves_conditional_reachable_under_label():
    source = """\
void f(char *d, char *s) {
#if defined(A) && defined(B)
    strcpy(d, s);
#endif
}
"""
    scanner = CGullScanner(
        rules=[BannedFunctionsRule()],
        engine_mode=AnalysisEngine.HYBRID,
    )

    result = scanner.scan_text(
        source,
        config_strategy="pairwise",
        exhaustive_threshold=10,
    )

    assert result.config_reduction_stats.candidate_count == 4
    assert result.config_reduction_stats.retained_count == 2
    assert len(result.issues) == 1
    assert result.issues[0].reachable_under == ["+A, B"]


def test_explicit_profiles_remain_authoritative_and_are_not_reduced():
    source = "#if defined(A)\nint a;\n#else\nint b;\n#endif\n"
    explicit = [
        _profile("none"),
        _profile("a", "A"),
        _profile("a-alias", "A"),
    ]
    scanner = CGullScanner(rules=[])

    result = scanner.scan_text(source, profiles=explicit)

    assert not hasattr(result, "config_reduction_stats")
    assert telemetry_for(result).analyzed_lines == result.total_lines_of_code * 3
