import json
import os

import jsonschema

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine, FixType
from cgull.reporter import ReportGenerator
from cgull.rules.banned_functions import BannedFunctionsRule, FormatStringRule


SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "sarif-2.1.0.json")
with open(SCHEMA_PATH, "r", encoding="utf-8") as _f:
    SARIF_SCHEMA = json.load(_f)


def test_sarif_safe_fix_populates_standard_fixes_array_and_validates_schema():
    scanner = CGullScanner(
        rules=[FormatStringRule()],
        engine_mode=AnalysisEngine.REGEX,
    )
    result = scanner.scan_text(
        "void f(char *user_input) {\n    printf(user_input);\n}\n",
        "src\\format.c",
    )
    issue = next(issue for issue in result.issues if issue.fix_type == FixType.SAFE_FIX)

    parsed = json.loads(ReportGenerator.to_sarif(result))
    jsonschema.validate(instance=parsed, schema=SARIF_SCHEMA)

    sarif_result = next(r for r in parsed["runs"][0]["results"] if r["ruleId"] == issue.rule_id)
    assert len(sarif_result["fixes"]) == 1

    fix = sarif_result["fixes"][0]
    assert fix["description"]["text"] == "Apply C-GULL mechanically safe fix"
    change = fix["artifactChanges"][0]
    assert change["artifactLocation"]["uri"] == "src/format.c"

    replacement = change["replacements"][0]
    assert replacement["insertedContent"]["text"] == issue.auto_fix_replacement
    region = replacement["deletedRegion"]
    assert region["startLine"] == issue.line_number
    assert region["startColumn"] == issue.column_number
    assert region["endLine"] == issue.line_number
    assert region["endColumn"] == issue.column_number + len(issue.code_snippet)


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
