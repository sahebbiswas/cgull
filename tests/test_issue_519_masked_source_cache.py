from unittest.mock import patch

from cgull.rules.crypto_and_safety import ToctouFileAccessRule
from cgull.rules.misra_and_style import NakedControlFlowStatementsRule
from cgull.utils import mask_string_and_char_literals


def _scan_lines(rule, source_lines):
    full_code = "\n".join(source_lines)
    issues = []
    for line_number, line in enumerate(source_lines, 1):
        issues.extend(
            rule.scan_line(
                file_path="issue_519.c",
                line_number=line_number,
                line_content=line,
                full_code=full_code,
                source_lines=source_lines,
                masked_line_content=mask_string_and_char_literals(line),
            )
        )
    return issues


def test_multiline_line_rules_mask_source_once_per_stable_source():
    source_lines = [
        "int check_file(const char *path, int flag) {",
        "    if (flag)",
        "        access(path, 0);",
        "    open(path, 0);",
        "    return 0;",
        "}",
    ]

    real_mask = mask_string_and_char_literals
    mask_calls = 0

    def counted_mask(line):
        nonlocal mask_calls
        mask_calls += 1
        return real_mask(line)

    with patch("cgull.rules.base.mask_string_and_char_literals", side_effect=counted_mask):
        naked_issues = _scan_lines(NakedControlFlowStatementsRule(), source_lines)
        toctou_issues = _scan_lines(ToctouFileAccessRule(), source_lines)

    assert mask_calls == 2 * len(source_lines)
    assert any(issue.rule_id == "CGULL-013" and issue.line_number == 2 for issue in naked_issues)
    assert any(issue.rule_id == "CGULL-035" and issue.line_number == 4 for issue in toctou_issues)


def test_masked_source_cache_invalidates_for_a_new_source_list():
    first = ["if (ready)", "    run();"]
    second = list(first)
    rule = NakedControlFlowStatementsRule()
    real_mask = mask_string_and_char_literals
    mask_calls = 0

    def counted_mask(line):
        nonlocal mask_calls
        mask_calls += 1
        return real_mask(line)

    with patch("cgull.rules.base.mask_string_and_char_literals", side_effect=counted_mask):
        _scan_lines(rule, first)
        _scan_lines(rule, second)

    assert mask_calls == len(first) + len(second)


def test_masked_source_cache_invalidates_after_in_place_mutation():
    source_lines = ["if (ready)", "    run();"]
    rule = NakedControlFlowStatementsRule()
    real_mask = mask_string_and_char_literals
    mask_calls = 0

    def counted_mask(line):
        nonlocal mask_calls
        mask_calls += 1
        return real_mask(line)

    with patch("cgull.rules.base.mask_string_and_char_literals", side_effect=counted_mask):
        first_issues = _scan_lines(rule, source_lines)
        source_lines[1] = "    { run(); }"
        second_issues = _scan_lines(rule, source_lines)

    assert mask_calls == 2 * len(source_lines)
    assert any(issue.rule_id == "CGULL-013" for issue in first_issues)
    assert not any(issue.rule_id == "CGULL-013" for issue in second_issues)
