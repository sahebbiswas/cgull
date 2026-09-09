from pathlib import Path
from types import SimpleNamespace

from benchmarks.run_juliet_upstream import (
    DEFAULT_FLOW_VARIANTS,
    _function_matches_oracle,
    _issue_in_range,
    _testcase_oracles,
    discover_candidates,
    flow_variant,
    format_markdown,
    infer_oracles,
    normalize_cwe,
    select_all_cases,
    select_stratified_cases,
    testcase_members as juliet_testcase_members,
)


def _write_case(root: Path, cwe_dir: str, name: str) -> Path:
    directory = root / "testcases" / cwe_dir
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(
        "void sample_bad(void) {\n"
        "    int x = 0;\n"
        "}\n"
        "void sample_good(void) {\n"
        "    int x = 0;\n"
        "}\n",
        encoding="utf-8",
    )
    return path


def test_normalize_cwe_and_default_flow_contract():
    assert normalize_cwe("cwe121") == "CWE-121"
    assert normalize_cwe("CWE_122") == "CWE-122"
    assert DEFAULT_FLOW_VARIANTS[0] == "01"
    assert "54" in DEFAULT_FLOW_VARIANTS


def test_generic_bad_good_oracles_and_flow_variant(tmp_path):
    path = _write_case(
        tmp_path,
        "CWE121_Stack_Based_Buffer_Overflow",
        "CWE121_Stack_Based_Buffer_Overflow__foo_01.c",
    )
    assert flow_variant(path) == "01"
    assert infer_oracles(path) == [("sample_bad", True), ("sample_good", False)]


def test_stratified_selection_is_deterministic_and_bounded(tmp_path):
    cwe_dir = "CWE121_Stack_Based_Buffer_Overflow"
    first = _write_case(tmp_path, cwe_dir, "CWE121_Stack_Based_Buffer_Overflow__a_01.c")
    second = _write_case(tmp_path, cwe_dir, "CWE121_Stack_Based_Buffer_Overflow__b_01.c")
    flow2 = _write_case(tmp_path, cwe_dir, "CWE121_Stack_Based_Buffer_Overflow__a_02.c")

    selected = select_stratified_cases(tmp_path, ["CWE-121"], ["01", "02"], per_flow=1)
    assert selected == [("CWE-121", first), ("CWE-121", flow2)]

    assert select_all_cases(tmp_path, ["CWE-121"]) == [
        ("CWE-121", first),
        ("CWE-121", flow2),
        ("CWE-121", second),
    ]
    assert second not in [path for _, path in selected]


def test_split_file_discovery_only_returns_entry_stage(tmp_path):
    cwe_dir = "CWE369_Divide_by_Zero"
    entry = _write_case(tmp_path, cwe_dir, "CWE369_Divide_by_Zero__int_54a.c")
    _write_case(tmp_path, cwe_dir, "CWE369_Divide_by_Zero__int_54b.c")
    _write_case(tmp_path, cwe_dir, "CWE369_Divide_by_Zero__int_54c.c")

    assert discover_candidates(tmp_path, "CWE-369") == [entry]


def test_split_file_testcase_members_are_grouped(tmp_path):
    cwe_dir = "CWE369_Divide_by_Zero"
    entry = _write_case(tmp_path, cwe_dir, "CWE369_Divide_by_Zero__int_54a.c")
    sibling = _write_case(tmp_path, cwe_dir, "CWE369_Divide_by_Zero__int_54b.c")
    unrelated = _write_case(tmp_path, cwe_dir, "CWE369_Divide_by_Zero__int_61a.c")

    assert juliet_testcase_members(entry) == [entry, sibling]
    assert unrelated not in juliet_testcase_members(entry)


def test_split_file_oracles_supplement_missing_bad_root_without_counting_sibling_good_helpers(tmp_path):
    cwe_dir = "CWE194_Unexpected_Sign_Extension"
    entry = _write_case(tmp_path, cwe_dir, "CWE194_Unexpected_Sign_Extension__foo_54a.c")
    sibling = _write_case(tmp_path, cwe_dir, "CWE194_Unexpected_Sign_Extension__foo_54b.c")
    entry.write_text(
        "void goodG2B(void) {\n"
        "    int x = 0;\n"
        "}\n",
        encoding="utf-8",
    )
    sibling.write_text(
        "void sample_bad(void) {\n"
        "    int x = 0;\n"
        "}\n"
        "void goodG2BSink(void) {\n"
        "    int x = 0;\n"
        "}\n",
        encoding="utf-8",
    )

    assert _testcase_oracles(entry) == [("goodG2B", False), ("sample_bad", True)]
    assert discover_candidates(tmp_path, "CWE-194") == [entry]


def test_entry_bad_oracle_remains_authoritative_for_split_group(tmp_path):
    cwe_dir = "CWE194_Unexpected_Sign_Extension"
    entry = _write_case(tmp_path, cwe_dir, "CWE194_Unexpected_Sign_Extension__foo_54a.c")
    sibling = _write_case(tmp_path, cwe_dir, "CWE194_Unexpected_Sign_Extension__foo_54b.c")
    sibling.write_text(
        "void sibling_bad(void) {\n"
        "    int x = 0;\n"
        "}\n",
        encoding="utf-8",
    )

    assert _testcase_oracles(entry) == [("sample_bad", True), ("sample_good", False)]


def test_oracle_family_matches_delegated_sink_names():
    assert _function_matches_oracle("CWE369_example_54b_badSink", "bad")
    assert _function_matches_oracle("badSink", "bad")
    assert _function_matches_oracle("CWE369_example_54b_goodG2BSink", "goodG2B")
    assert not _function_matches_oracle("notbadSink", "bad")
    assert not _function_matches_oracle("CWE369_example_54b_goodG2BSink", "bad")
    assert not _function_matches_oracle("CWE369_example_54b_goodB2GSink", "goodG2B")


def test_issue_without_line_number_is_not_attributed_to_function():
    assert _issue_in_range(SimpleNamespace(line_number=None), 1, 10) is False
    assert _issue_in_range(SimpleNamespace(line_number=5), 1, 10) is True
    assert _issue_in_range(SimpleNamespace(line_number=11), 1, 10) is False


def test_issue_file_path_is_member_aware_and_handles_missing_or_relative_paths(tmp_path):
    member = tmp_path / "flow54b.c"
    member.write_text("void sink(void) {}\n", encoding="utf-8")

    assert _issue_in_range(
        SimpleNamespace(line_number=1, file_path=None),
        1,
        1,
        file_path=member,
    ) is False
    assert _issue_in_range(
        SimpleNamespace(line_number=1, file_path="flow54b.c"),
        1,
        1,
        file_path=member,
    ) is True
    assert _issue_in_range(
        SimpleNamespace(line_number=1, file_path="other.c"),
        1,
        1,
        file_path=member,
    ) is False


def test_markdown_report_exposes_per_cwe_metrics():
    report = {
        "selected_files": 2,
        "scanned_files": 3,
        "evaluated_functions": 4,
        "failed_files": [],
        "overall": {"tp": 1, "fp": 0, "tn": 2, "fn": 1, "precision": 1.0, "recall": 0.5, "f1": 0.6667},
        "by_cwe": {
            "CWE-121": {"tp": 1, "fp": 0, "tn": 2, "fn": 1, "precision": 1.0, "recall": 0.5, "f1": 0.6667}
        },
    }
    rendered = format_markdown(report)
    assert "Selected testcase entries: 2" in rendered
    assert "Scanned source files: 3" in rendered
    assert "| CWE | TP | FP | TN | FN | Precision | Recall | F1 |" in rendered
    assert "| CWE-121 | 1 | 0 | 2 | 1 | 1.0000 | 0.5000 | 0.6667 |" in rendered


def test_conversion_cwe_attribution_does_not_credit_narrowing_as_sign_extension():
    from benchmarks.run_juliet import is_issue_cwe_match
    from benchmarks.run_juliet_upstream import _result_detects_oracle

    issue = SimpleNamespace(rule_id="CGULL-049", cwe_id="CWE-197", line_number=2)
    result = SimpleNamespace(issues=[issue])
    ranges = {"sample_bad": (1, 4)}
    assert not is_issue_cwe_match(issue, "CWE-194", ["CGULL-049"])
    assert not _result_detects_oracle(result, ranges, {"CGULL-049"}, "sample_bad", cwe="CWE-194")
    issue.cwe_id = "CWE-194"
    assert is_issue_cwe_match(issue, "CWE-194", ["CGULL-049"])
    assert _result_detects_oracle(result, ranges, {"CGULL-049"}, "sample_bad", cwe="CWE-194")
