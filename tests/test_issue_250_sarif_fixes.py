import json
import os

import jsonschema

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine, FixType
from cgull.reporter import ReportGenerator
from cgull.rules.banned_functions import BannedFunctionsRule, FormatStringRule
from cgull.rules.memory_management.uninitialized_pointers import UninitializedPointersRule


SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "sarif-2.1.0.json")
with open(SCHEMA_PATH, "r", encoding="utf-8") as _f:
    SARIF_SCHEMA = json.load(_f)


def _apply_single_line_sarif_replacement(source: str, replacement: dict) -> str:
    region = replacement["deletedRegion"]
    assert region["startLine"] == region["endLine"]
    lines = source.splitlines(keepends=True)
    index = region["startLine"] - 1
    original = lines[index]
    newline = "\n" if original.endswith("\n") else ""
    body = original[:-1] if newline else original
    start = region["startColumn"] - 1
    end = region["endColumn"] - 1
    lines[index] = body[:start] + replacement["insertedContent"]["text"] + body[end:] + newline
    return "".join(lines)


def test_sarif_subexpression_safe_fix_is_not_exposed_without_exact_span():
    scanner = CGullScanner(
        rules=[FormatStringRule()],
        engine_mode=AnalysisEngine.REGEX,
    )
    result = scanner.scan_text(
        "void f(char *user_input) {\n    printf(user_input);\n}\n",
        "src\\format.c",
    )
    issue = next(issue for issue in result.issues if issue.fix_type == FixType.SAFE_FIX)
    assert issue.auto_fix_replacement == 'printf("%s", user_input)'

    parsed = json.loads(ReportGenerator.to_sarif(result))
    jsonschema.validate(instance=parsed, schema=SARIF_SCHEMA)

    sarif_result = next(r for r in parsed["runs"][0]["results"] if r["ruleId"] == issue.rule_id)
    assert "fixes" not in sarif_result


def test_sarif_full_line_safe_fix_applies_exactly_and_validates_schema():
    source = "void f(void) {\n    int *p;\n    use(p);\n}\n"
    scanner = CGullScanner(
        rules=[UninitializedPointersRule()],
        engine_mode=AnalysisEngine.REGEX,
    )
    result = scanner.scan_text(source, "src\\pointer.c")
    issue = next(issue for issue in result.issues if issue.fix_type == FixType.SAFE_FIX)
    assert issue.code_snippet == "    int *p;"
    assert issue.auto_fix_replacement == "    int *p = NULL;"

    parsed = json.loads(ReportGenerator.to_sarif(result))
    jsonschema.validate(instance=parsed, schema=SARIF_SCHEMA)

    sarif_result = next(r for r in parsed["runs"][0]["results"] if r["ruleId"] == issue.rule_id)
    fix = sarif_result["fixes"][0]
    change = fix["artifactChanges"][0]
    assert change["artifactLocation"]["uri"] == "src/pointer.c"

    replacement = change["replacements"][0]
    region = replacement["deletedRegion"]
    assert region["startColumn"] == 1
    assert region["endColumn"] == len(issue.code_snippet) + 1
    assert _apply_single_line_sarif_replacement(source, replacement) == (
        "void f(void) {\n    int *p = NULL;\n    use(p);\n}\n"
    )


def test_sarif_suggested_fix_does_not_offer_one_click_replacement():
    scanner = CGullScanner(
        rules=[BannedFunctionsRule()],
        engine_mode=AnalysisEngine.REGEX,
    )
    result = scanner.scan_text(
        "void f(char *buf) {\n    gets(buf);\n}\n",
        "sample.c",
    )
    issue = next(issue for issue in result.issues if issue.fix_type == FixType.SUGGESTED_FIX)
    assert issue.auto_fix_replacement is None
    assert issue.suggested_fix_replacement is not None

    parsed = json.loads(ReportGenerator.to_sarif(result))
    jsonschema.validate(instance=parsed, schema=SARIF_SCHEMA)

    sarif_result = next(r for r in parsed["runs"][0]["results"] if r["ruleId"] == issue.rule_id)
    assert "fixes" not in sarif_result
