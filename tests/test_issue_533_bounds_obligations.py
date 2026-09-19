"""Semantic grouping and lossless reporting of unchecked array accesses."""
import json
from pathlib import Path

import jsonschema
import pytest

from cgull.ast_analyzer import CASTParser
from cgull.engine import CGullScanner
from cgull.reporter import ReportGenerator
from cgull.rules.types_and_arrays import ArrayIndexOutOfBoundsRule


def scan(body):
    return ArrayIndexOutOfBoundsRule().scan_ast("test.c", CASTParser().parse(body))


CODE = """void f(char *line, int count) {
    consume(line[count]);
    if (line[count] == ':')
        consume(line[count]);
    consume(line[count]);
}
"""


def test_repeated_accesses_keep_every_location():
    issues = scan(CODE)
    assert len(issues) == 1
    issue = issues[0]
    assert (issue.rule_id, issue.line_number, issue.column_number) == ("CGULL-007", 2, 13)
    assert [(p.line_number, p.column_number) for p in issue.related_locations] == [(3, 9), (4, 17), (5, 13)]


@pytest.mark.parametrize("body", [
    "a[i] = 1; b[i] = 2;",
    "a[i] = 1; i = next(); a[i] = 2;",
    "a[i] = 1; a = other(); a[i] = 2;",
    "a[i] = 1; if (i < 10) { a[i] = 2; }",
    "a[i] = 1; { int i = next(); a[i] = 2; }",
    "a[i] = 1; { char *a = other(); a[i] = 2; }",
    "a[i] = 1; change(&i); a[i] = 2;",
    "a[i+1] = 1; a[i+2] = 2;",
    "a[i] = 1; if (flag) i = next(); a[i] = 2;",
    "a[i] = 1; while (flag) { ++i; a[i] = 2; }",
])
def test_distinct_obligations_stay_separate(body):
    assert len(scan(f"void f(char *a, char *b, int i, int flag) {{ {body} }}")) == 2


def test_same_line_accesses_retain_columns():
    issues = scan("void f(char *a, int i) { consume(a[i], a[i]); }")
    assert len(issues) == 1
    assert len(issues[0].related_locations) == 1
    assert issues[0].column_number != issues[0].related_locations[0].column_number


def test_constants_remain_independent():
    issues = scan("void f(void) { char a[2];\na[3] = 1;\na[4] = 2; }")
    assert len(issues) == 2
    assert all(not issue.related_locations for issue in issues)


def test_fallback_keeps_independent_rows():
    ctx = CASTParser().parse(CODE)
    ctx.has_pycparser = False
    ctx.pycparser_ast = None
    assert len(ArrayIndexOutOfBoundsRule().scan_ast("test.c", ctx)) == 4


def test_reports_and_fingerprints():
    scanner = CGullScanner()
    result = scanner.scan_text(CODE, "test.c")
    result.issues = [issue for issue in result.issues if issue.rule_id == "CGULL-007"]
    assert len(result.issues) == 1
    payload = json.loads(ReportGenerator.to_json(result))
    assert len(payload["issues"][0]["related_locations"]) == 3
    sarif = json.loads(ReportGenerator.to_sarif(result))
    jsonschema.validate(sarif, json.loads((Path(__file__).parent / "sarif-2.1.0.json").read_text()))
    assert len(sarif["runs"][0]["results"][0]["relatedLocations"]) == 3
    for output in (ReportGenerator.to_markdown(result), ReportGenerator.to_terminal_text(result)):
        assert "Also affects 3 accesses" in output
    changed = scanner.scan_text(CODE.replace("    consume(line[count]);\n}", "}"), "test.c")
    issue = next(i for i in changed.issues if i.rule_id == "CGULL-007")
    assert issue.fingerprint == result.issues[0].fingerprint
    assert len(issue.related_locations) == 2


def test_tu_mapping_and_suppressed_primary(tmp_path):
    from cgull.models import AnalysisEngine, ScanConfig
    header = tmp_path / "accesses.h"
    header.write_text("consume(a[i]);\nconsume(a[i]);\n")
    source = tmp_path / "main.c"
    source.write_text('void f(char *a, int i) {\nconsume(a[i]); // cgull-ignore CGULL-007\n#include "accesses.h"\n}\n')
    config = ScanConfig.create(rules=[ArrayIndexOutOfBoundsRule()], engine_mode=AnalysisEngine.AST,
                               include_roots=[str(tmp_path)], mode="tu")
    result = CGullScanner(config=config).scan_path(str(source), jobs=1, quiet=True)
    issues = [i for i in result.issues if i.rule_id == "CGULL-007"]
    assert len(issues) == 1
    assert issues[0].file_path == "accesses.h"
    assert issues[0].line_number == 1
    assert [(loc.file_path, loc.line_number) for loc in issues[0].related_locations] == [("accesses.h", 2)]


def test_free_and_constant_accesses_on_same_line():
    assert len(scan("void f(char *a, int i) { a[i] = 0; free(a); a[i] = 0; }")) == 2
    issues = scan("void f(void) { char a[2]; a[3] = 0; a[3] = 0; }")
    assert len(issues) == 2
    assert issues[0].column_number != issues[1].column_number


def test_contract_filter_keeps_only_unproven_occurrences():
    # Exercise the extension hook independently of contract discovery: filtering
    # a primary must retain the later unproven access, with its actual snippet.
    from unittest.mock import patch
    from cgull.rules.types_and_arrays.array_index_constant_bounds import ArrayIndexOutOfBoundsRule as ExtendedRule
    with patch.object(ExtendedRule, "_contract_safe_accesses", return_value={(2, 13, "line", "count"), (4, 17, "line", "count")}):
        issues = ExtendedRule().scan_ast("test.c", CASTParser().parse(CODE))
    assert len(issues) == 1
    assert issues[0].line_number == 3
    assert [loc.line_number for loc in issues[0].related_locations] == [5]
    assert "if (line[count]" in issues[0].code_snippet


def test_suppressed_primary_in_memory_keeps_source_context():
    result = CGullScanner().scan_text(CODE.replace('consume(line[count]);', 'consume(line[count]); // cgull-ignore CGULL-007', 1), 'missing.c')
    issue = next(i for i in result.issues if i.rule_id == 'CGULL-007')
    assert issue.line_number == 3
    assert issue.code_snippet == "if (line[count] == ':')"


def test_duplicate_merge_preserves_related_locations():
    from copy import deepcopy
    from cgull.engine import _merge_duplicate_issues
    issue = scan(CODE)[0]
    other = deepcopy(issue)
    issue.related_locations = issue.related_locations[:1]
    other.related_locations = other.related_locations[1:]
    merged = _merge_duplicate_issues(issue, other)
    assert [loc.line_number for loc in merged.related_locations] == [3, 4, 5]


def test_new_proof_and_later_definition_split_groups():
    code = """void f(int i) {
        int a[8];
        consume(a[i]);
        consume(a[i]);
        if (i >= 0 && i < 8) { consume(a[i]); }
        i = other();
        consume(a[i]);
        consume(a[i]);
    }"""
    issues = scan(code)
    assert [(i.line_number, [loc.line_number for loc in i.related_locations]) for i in issues] == [(3, [4]), (7, [8])]
