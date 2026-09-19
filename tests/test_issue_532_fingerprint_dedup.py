import copy
import json

from cgull.engine import CGullScanner, _deduplicate_issues_by_fingerprint, _merge_duplicate_issues
from cgull.models import Confidence, ConfigProfile, FixType, Issue, Severity
from cgull.reporter import ReportGenerator
from cgull.rules.banned_functions import BannedFunctionsRule
from cgull.rules.crypto_and_safety import NonConstantTimeMemoryComparisonRule


def _cgull_005_scanner():
    return CGullScanner(rules=[NonConstantTimeMemoryComparisonRule()])


def test_cgull_005_macro_raw_vs_resolved_emits_one_finding():
    source = """
#define LEVEL_NAME "LEVEL"

void use(const char *value);

int check_token(const char *token) {
    if (!strcmp(token, LEVEL_NAME)) {
        use(token);
        return 1;
    }
    return 0;
}
"""

    result = _cgull_005_scanner().scan_text(source, "macro_compare.c")
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-005"]

    assert len(issues) == 1
    assert issues[0].fingerprint
    assert result.total_issues_count == len(result.issues)

    sarif = json.loads(ReportGenerator.to_sarif(result))
    fingerprints = [
        row["partialFingerprints"]["cgullFingerprint/v1"]
        for row in sarif["runs"][0]["results"]
        if row["ruleId"] == "CGULL-005"
    ]
    assert len(fingerprints) == len(set(fingerprints))


def test_config_profiles_merge_message_variants_by_fingerprint():
    source = """
void use(const char *value);

int check_token(const char *token) {
    if (!strcmp(token, LEVEL_NAME)) {
        use(token);
        return 1;
    }
    return 0;
}
"""
    profiles = [
        ConfigProfile("level", {"LEVEL_NAME": '"LEVEL"'}),
        ConfigProfile("alternate", {"LEVEL_NAME": '"ALT"'}),
    ]

    result = _cgull_005_scanner().scan_text_profiles(
        source,
        profiles=profiles,
        file_path="profile_compare.c",
    )
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-005"]

    assert len(issues) == 1
    assert issues[0].reachable_under == ["unconditional"]
    assert len({issue.fingerprint for issue in issues}) == 1


def test_cgull_001_repeated_source_sites_remain_distinct_with_unique_fingerprints():
    source = """
void first(char *buf) {
    gets(buf);
}

void second(char *buf) {
    gets(buf);
}
"""
    scanner = CGullScanner(rules=[BannedFunctionsRule()])
    result = scanner.scan_text(source, "banned_calls.c")
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-001"]

    assert len(issues) == 2
    assert len({issue.fingerprint for issue in issues}) == 2
    assert {issue.line_number for issue in issues} == {3, 7}
    assert result.total_issues_count == len(result.issues)


def test_duplicate_merge_preserves_best_source_confidence_fix_and_reachability():
    coarse = Issue(
        rule_id="CGULL-999",
        rule_name="Synthetic",
        impact=Severity.HIGH,
        file_path="src/example.c",
        line_number=10,
        column_number=1,
        code_snippet="danger();",
        message="coarse",
        fingerprint="same",
        confidence=Confidence.FULL,
        fix_type=FixType.MANUAL_REVIEW,
        reachable_under=["+A"],
        related_tus=["a.c"],
    )
    precise = Issue(
        rule_id="CGULL-999",
        rule_name="Synthetic",
        impact=Severity.HIGH,
        file_path="src/example.c",
        line_number=10,
        column_number=7,
        code_snippet="danger();",
        message="precise",
        fingerprint="same",
        confidence=Confidence.FALLBACK,
        fix_type=FixType.SAFE_FIX,
        auto_fix_replacement="safe();",
        suggested_fix_replacement="consider_safe();",
        reachable_under=["+B"],
        related_tus=["b.c"],
    )

    merged = _merge_duplicate_issues(copy.deepcopy(coarse), copy.deepcopy(precise))
    reversed_merge = _merge_duplicate_issues(copy.deepcopy(precise), copy.deepcopy(coarse))

    assert merged.to_dict() == reversed_merge.to_dict()
    assert merged.column_number == 7
    assert merged.confidence == Confidence.FULL
    assert merged.fix_type == FixType.SAFE_FIX
    assert merged.auto_fix_replacement == "safe();"
    assert merged.suggested_fix_replacement == "consider_safe();"
    assert merged.reachable_under == ["+A", "+B"]
    assert merged.related_tus == ["a.c", "b.c"]


def test_coarse_same_line_occurrences_are_preserved_without_precise_coordinates():
    first = Issue(
        rule_id="CGULL-999",
        rule_name="Synthetic",
        impact=Severity.HIGH,
        file_path="src/example.c",
        line_number=10,
        column_number=1,
        code_snippet="danger(); danger();",
        message="same coarse finding",
        fingerprint="same",
        engine="AST",
    )
    second = copy.deepcopy(first)

    finalized = _deduplicate_issues_by_fingerprint([first, second])

    assert len(finalized) == 2
    assert len({issue.fingerprint for issue in finalized}) == 2


def test_coarse_same_line_cross_engine_rows_are_preserved_without_site_evidence():
    ast_issue = Issue(
        rule_id="CGULL-999",
        rule_name="Synthetic",
        impact=Severity.HIGH,
        file_path="src/example.c",
        line_number=10,
        column_number=1,
        code_snippet="danger(); danger();",
        message="AST coarse finding",
        fingerprint="same",
        engine="AST",
    )
    regex_issue = copy.deepcopy(ast_issue)
    regex_issue.engine = "Regex"
    regex_issue.message = "Regex coarse finding"

    finalized = _deduplicate_issues_by_fingerprint([ast_issue, regex_issue])

    assert len(finalized) == 2
    assert len({issue.fingerprint for issue in finalized}) == 2


def test_coarse_cross_tu_representations_merge_by_occurrence_multiplicity():
    def make_issue(tu):
        return Issue(
            rule_id="CGULL-999",
            rule_name="Synthetic",
            impact=Severity.HIGH,
            file_path="include/example.h",
            line_number=10,
            column_number=1,
            code_snippet="danger(); danger();",
            message="same coarse finding",
            fingerprint="same",
            engine="AST",
            related_tus=[tu],
        )

    standalone_first = make_issue("standalone")
    standalone_second = make_issue("standalone")
    standalone_first.related_tus = []
    standalone_second.related_tus = []

    issues = [
        standalone_first,
        standalone_second,
        make_issue("a.c"),
        make_issue("a.c"),
        make_issue("b.c"),
        make_issue("b.c"),
    ]

    finalized = _deduplicate_issues_by_fingerprint(issues)

    assert len(finalized) == 2
    assert len({issue.fingerprint for issue in finalized}) == 2
    assert all(issue.related_tus == ["a.c", "b.c"] for issue in finalized)


def test_mixed_precise_and_coarse_same_line_findings_stay_distinct_without_site_evidence():
    precise = Issue(
        rule_id="CGULL-999",
        rule_name="Synthetic",
        impact=Severity.HIGH,
        file_path="src/example.c",
        line_number=10,
        column_number=8,
        code_snippet="danger(); danger();",
        message="precise finding",
        fingerprint="same",
        engine="Regex",
    )
    coarse = copy.deepcopy(precise)
    coarse.column_number = 1
    coarse.message = "distinct coarse finding"
    coarse.engine = "AST"

    finalized = _deduplicate_issues_by_fingerprint([precise, coarse])

    assert len(finalized) == 2
    assert {issue.column_number for issue in finalized} == {1, 8}
    assert len({issue.fingerprint for issue in finalized}) == 2


def test_cgull_005_same_line_calls_keep_distinct_precise_occurrences():
    source = """
int check_token(const char *token) {
    return strcmp(token, "token") == 0 || strcmp(token, "token") == 0;
}
"""
    result = _cgull_005_scanner().scan_text(source, "same_line_compare.c")
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-005"]

    assert len(issues) == 2
    assert all(issue.column_number > 1 for issue in issues)
    assert len({issue.column_number for issue in issues}) == 2
    assert len({issue.fingerprint for issue in issues}) == 2


def test_matching_coarse_and_precise_rows_merge_by_multiplicity_without_losing_occurrences():
    def make_issue(column, engine):
        return Issue(
            rule_id="CGULL-999",
            rule_name="Synthetic",
            impact=Severity.HIGH,
            file_path="src/example.c",
            line_number=10,
            column_number=column,
            code_snippet="danger(); danger();",
            message="same logical finding",
            fingerprint="same",
            engine=engine,
        )

    issues = [
        make_issue(8, "Regex"),
        make_issue(20, "Regex"),
        make_issue(1, "AST"),
        make_issue(1, "AST"),
    ]

    finalized = _deduplicate_issues_by_fingerprint(issues)

    assert len(finalized) == 2
    assert {issue.column_number for issue in finalized} == {8, 20}
    assert len({issue.fingerprint for issue in finalized}) == 2


def test_cgull_005_column_mapping_ignores_literal_and_comment_lookalikes():
    source = """
int check_token(const char *token) {
    const char *note = "strcmp("; /* strcmp( */ return strcmp(token, "token") == 0;
}
"""
    result = _cgull_005_scanner().scan_text(source, "column_compare.c")
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-005"]

    assert len(issues) == 1
    source_line = source.splitlines()[2]
    assert issues[0].column_number == source_line.index("strcmp(token") + 1
