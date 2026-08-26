"""
Tests for cgull.reporter.ReportGenerator across all four output formats.
"""

import json
import os
import tempfile
import unittest

import jsonschema

from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.reporter import ReportGenerator

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "sarif-2.1.0.json")
with open(SCHEMA_PATH, "r", encoding="utf-8") as _f:
    SARIF_SCHEMA = json.load(_f)


VULNERABLE_CODE = """
#include <stdio.h>
void f(char *src) {
    char buf[32];
    gets(buf);
}
"""

CLEAN_CODE = """
int noop(void) {
    int total = 0;
    total = total + 1;
    return total;
}
"""


class TestReportGeneratorJSON(unittest.TestCase):
    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_json_pretty_by_default(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_json(result)
        self.assertIn("\n", output)  # pretty-printed has newlines/indentation

    def test_json_compact_when_not_pretty(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_json(result, pretty=False)
        parsed = json.loads(output)
        self.assertIn("issues", parsed)

    def test_json_roundtrips_issue_fields(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        parsed = json.loads(ReportGenerator.to_json(result))
        self.assertEqual(parsed["schema_version"], "1")
        self.assertGreaterEqual(len(parsed["issues"]), 1)
        issue = parsed["issues"][0]
        for key in ("rule_id", "rule_name", "impact", "file_path", "line_number", "message", "cwe_id"):
            self.assertIn(key, issue)

    def test_json_clean_file_has_no_issues(self):
        result = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        parsed = json.loads(ReportGenerator.to_json(result))
        self.assertEqual(parsed["summary"]["total_issues_count"], 0)
        self.assertEqual(parsed["issues"], [])

    def test_json_reports_scan_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            broken = os.path.join(tmpdir, "broken.c")
            try:
                os.symlink(os.path.join(tmpdir, "nope"), broken)
            except OSError:
                self.skipTest("Symlinks not supported")
            result = self.scanner.scan_path(tmpdir)
            parsed = json.loads(ReportGenerator.to_json(result))
            self.assertEqual(parsed["summary"]["files_failed"], 1)
            self.assertEqual(len(parsed["scan_errors"]), 1)
            self.assertEqual(parsed["scan_errors"][0]["file_path"], "broken.c")


class TestReportGeneratorSARIF(unittest.TestCase):
    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_sarif_schema_validation_vulnerable_code(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        jsonschema.validate(instance=parsed, schema=SARIF_SCHEMA)

    def test_sarif_schema_validation_clean_code(self):
        result = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        jsonschema.validate(instance=parsed, schema=SARIF_SCHEMA)

    def test_sarif_schema_validation_multi_file_multi_rule(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = os.path.join(tmpdir, "src1.c")
            f2 = os.path.join(tmpdir, "src2.c")
            with open(f1, "w") as out:
                out.write("void f(void) {\n    goto exit_label;\nexit_label:\n    return;\n}\n")
            with open(f2, "w") as out:
                out.write("#include <stdio.h>\nvoid g(char *buf) {\n    gets(buf);\n}\n")

            result = self.scanner.scan_path(tmpdir)
            sarif_str = ReportGenerator.to_sarif(result)
            parsed = json.loads(sarif_str)

            # Validate against official SARIF 2.1.0 JSON Schema
            jsonschema.validate(instance=parsed, schema=SARIF_SCHEMA)

            # Assert findings exist across multiple rules and files
            results = parsed["runs"][0]["results"]
            self.assertGreaterEqual(len(results), 2)
            rule_ids = {r["ruleId"] for r in results}
            file_uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}

            self.assertIn("CGULL-018", rule_ids)
            self.assertIn("CGULL-001", rule_ids)
            self.assertTrue(any(uri.endswith("src1.c") for uri in file_uris))
            self.assertTrue(any(uri.endswith("src2.c") for uri in file_uris))

            # Verify source location details in findings
            for res in results:
                self.assertIn("locations", res)
                loc = res["locations"][0]["physicalLocation"]
                self.assertIn("artifactLocation", loc)
                self.assertIn("uri", loc["artifactLocation"])
                self.assertIn("region", loc)
                region = loc["region"]
                self.assertGreaterEqual(region["startLine"], 1)
                self.assertGreaterEqual(region["startColumn"], 1)
                self.assertIn("snippet", region)

    def test_sarif_schema_fields_present(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertIn("$schema", parsed)
        self.assertEqual(len(parsed["runs"]), 1)

    def test_sarif_severity_maps_to_correct_level(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        levels = {r["level"] for r in parsed["runs"][0]["results"]}
        # CGULL-001 (gets) is High severity -> SARIF "error"
        self.assertIn("error", levels)

    def test_sarif_rules_deduplicated_across_multiple_findings(self):
        code = "void f(char *a, char *b, char *c) {\n    gets(a);\n    gets(b);\n    gets(c);\n}"
        result = self.scanner.scan_text(code, "sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        gets_rule_entries = [r for r in parsed["runs"][0]["tool"]["driver"]["rules"] if r["id"] == "CGULL-001"]
        self.assertEqual(len(gets_rule_entries), 1)
        gets_results = [r for r in parsed["runs"][0]["results"] if r["ruleId"] == "CGULL-001"]
        self.assertEqual(len(gets_results), 3)

    def test_sarif_full_description_uses_rule_description_not_remediation(self):
        from cgull.rules.banned_functions import BannedFunctionsRule
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        rule_entry = next(r for r in rules if r["id"] == "CGULL-001")
        gets_issue = next(i for i in result.issues if i.rule_id == "CGULL-001")
        self.assertEqual(rule_entry["fullDescription"]["text"], BannedFunctionsRule.description)
        self.assertNotEqual(rule_entry["fullDescription"]["text"], gets_issue.remediation)

    def test_sarif_no_findings_produces_empty_results(self):
        result = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        self.assertEqual(parsed["runs"][0]["results"], [])

    def test_sarif_location_uses_forward_slashes(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "windows\\style\\sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        uri = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertNotIn("\\", uri)

    def test_sarif_results_include_partial_fingerprints(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        parsed = json.loads(ReportGenerator.to_sarif(result))
        fp = parsed["runs"][0]["results"][0]["partialFingerprints"]["cgullFingerprint/v1"]
        self.assertTrue(fp)
        self.assertEqual(fp, result.issues[0].fingerprint)

    def test_sarif_reports_scan_errors_and_validates_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            broken = os.path.join(tmpdir, "broken.c")
            try:
                os.symlink(os.path.join(tmpdir, "nope"), broken)
            except OSError:
                self.skipTest("Symlinks not supported")
            result = self.scanner.scan_path(tmpdir)
            sarif_str = ReportGenerator.to_sarif(result)
            parsed = json.loads(sarif_str)

            # Validate against official SARIF 2.1.0 schema
            jsonschema.validate(instance=parsed, schema=SARIF_SCHEMA)

            inv = parsed["runs"][0]["invocations"][0]
            self.assertFalse(inv["executionSuccessful"])
            self.assertEqual(inv["properties"]["filesFailed"], 1)
            self.assertEqual(len(inv["properties"]["scanErrors"]), 1)
            self.assertIn("toolExecutionNotifications", inv)
            self.assertEqual(len(inv["toolExecutionNotifications"]), 1)


class TestReportGeneratorMarkdown(unittest.TestCase):
    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_markdown_clean_scan_shows_passed_message(self):
        result = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        output = ReportGenerator.to_markdown(result)
        self.assertIn("No vulnerabilities detected", output)
        self.assertIn("✅ Passed", output)

    def test_markdown_vulnerable_scan_shows_findings(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_markdown(result)
        self.assertIn("CGULL-001", output)
        self.assertIn("Needs Immediate Remediation", output)

    def test_markdown_includes_autofix_block_when_present(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_markdown(result)
        self.assertIn("Suggested Fix", output)

    def test_markdown_reports_scan_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            broken = os.path.join(tmpdir, "broken.c")
            try:
                os.symlink(os.path.join(tmpdir, "nope"), broken)
            except OSError:
                self.skipTest("Symlinks not supported")
            result = self.scanner.scan_path(tmpdir)
            output = ReportGenerator.to_markdown(result)
            self.assertIn("## ⚠️ Scan Errors", output)
            self.assertIn("`broken.c`", output)

    def test_markdown_reports_scan_errors_escapes_special_characters(self):
        from cgull.models import ScanError
        err = ScanError(
            file_path="foo|bar`baz\n.c",
            error_type="Error|Type`Bad\r\n",
            message="Line 1|Line 2`Line 3\nLine 4",
        )
        res = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        res.scan_errors = [err]
        output = ReportGenerator.to_markdown(res)
        self.assertIn("## ⚠️ Scan Errors", output)
        self.assertIn("foo\\|bar", output)
        self.assertIn("\\`", output)
        error_table_lines = [line for line in output.splitlines() if "foo" in line]
        self.assertEqual(len(error_table_lines), 1)


class TestReportGeneratorTerminal(unittest.TestCase):
    def setUp(self):
        self.scanner = CGullScanner(engine_mode=AnalysisEngine.HYBRID)

    def test_terminal_clean_scan_shows_success(self):
        result = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        output = ReportGenerator.to_terminal_text(result)
        self.assertIn("No vulnerabilities found", output)

    def test_terminal_vulnerable_scan_shows_finding_details(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_terminal_text(result)
        self.assertIn("CGULL-001", output)
        self.assertIn("[HIGH]", output)

    def test_terminal_summary_counts_match_result(self):
        result = self.scanner.scan_text(VULNERABLE_CODE, "sample.c")
        output = ReportGenerator.to_terminal_text(result)
        self.assertIn(f"Total Findings   : {result.total_issues_count}", output)

    def test_terminal_reports_scan_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            broken = os.path.join(tmpdir, "broken.c")
            try:
                os.symlink(os.path.join(tmpdir, "nope"), broken)
            except OSError:
                self.skipTest("Symlinks not supported")
            result = self.scanner.scan_path(tmpdir)
            output = ReportGenerator.to_terminal_text(result)
            self.assertIn("SCAN ERRORS", output)
            self.assertIn("broken.c", output)

    def test_terminal_reports_scan_errors_sanitizes_ansi_and_control_chars(self):
        from cgull.models import ScanError
        err = ScanError(
            file_path="\x1b[31mhostile\x1b[0m.c\n",
            error_type="Error\x00Type",
            message="Line 1\nForged Line: [SUCCESS]",
        )
        res = self.scanner.scan_text(CLEAN_CODE, "clean.c")
        res.scan_errors = [err]
        output = ReportGenerator.to_terminal_text(res)
        self.assertIn("SCAN ERRORS", output)
        self.assertNotIn("\x1b[31m", output)
        self.assertNotIn("\x00", output)
        self.assertIn("hostile.c", output)
        self.assertIn("Line 1 Forged Line: [SUCCESS]", output)


class TestReportGeneratorReachableUnder(unittest.TestCase):
    def setUp(self):
        from cgull.rules.banned_functions import BannedFunctionsRule
        from cgull.models import ConfigProfile
        self.scanner = CGullScanner(rules=[BannedFunctionsRule()], engine_mode=AnalysisEngine.HYBRID)
        self.source_code = (
            "#include <string.h>\n"
            "#include <stdio.h>\n"
            "\n"
            "void auth_user(char *dst, const char *src) {\n"
            "    (void)src;\n"
            "#ifdef LEGACY_AUTH\n"
            "    strcpy(dst, src);\n"
            "#endif\n"
            "    gets(dst);\n"
            "}\n"
        )
        self.profiles = [
            ConfigProfile("baseline", {}),
            ConfigProfile("LEGACY_AUTH", {"LEGACY_AUTH": None}),
        ]
        self.result = self.scanner.scan_text_profiles(self.source_code, profiles=self.profiles, file_path="auth.c")

    def test_reachable_under_json_format(self):
        json_str = ReportGenerator.to_json(self.result)
        parsed = json.loads(json_str)
        strcpy_issue = next(i for i in parsed["issues"] if "strcpy" in i["message"])
        gets_issue = next(i for i in parsed["issues"] if "gets" in i["message"])
        self.assertEqual(strcpy_issue["reachable_under"], ["+LEGACY_AUTH"])
        self.assertEqual(gets_issue["reachable_under"], ["unconditional"])

    def test_reachable_under_sarif_format(self):
        sarif_str = ReportGenerator.to_sarif(self.result)
        parsed = json.loads(sarif_str)
        jsonschema.validate(instance=parsed, schema=SARIF_SCHEMA)
        results = parsed["runs"][0]["results"]
        strcpy_res = next(r for r in results if "strcpy" in r["message"]["text"])
        gets_res = next(r for r in results if "gets" in r["message"]["text"])
        self.assertEqual(strcpy_res["properties"]["reachableUnder"], ["+LEGACY_AUTH"])
        self.assertEqual(strcpy_res["properties"]["reachable_under"], ["+LEGACY_AUTH"])
        self.assertEqual(gets_res["properties"]["reachableUnder"], ["unconditional"])
        self.assertEqual(gets_res["properties"]["reachable_under"], ["unconditional"])

    def test_reachable_under_markdown_format(self):
        md_str = ReportGenerator.to_markdown(self.result)
        self.assertIn("[+LEGACY_AUTH]", md_str)
        self.assertNotIn("[unconditional]", md_str)

    def test_reachable_under_terminal_format(self):
        term_str = ReportGenerator.to_terminal_text(self.result)
        self.assertIn("[+LEGACY_AUTH]", term_str)
        self.assertNotIn("[unconditional]", term_str)

    def test_reachable_under_hostile_tag_sanitization_terminal(self):
        from cgull.models import ConfigProfile
        hostile_profile = ConfigProfile("\x1b[31mBAD\x1b[0m\nHEADING_INJECTION", {"LEGACY_AUTH": None})
        profiles = [ConfigProfile("baseline", {}), hostile_profile]
        res = self.scanner.scan_text_profiles(self.source_code, profiles=profiles, file_path="auth.c")
        term_str = ReportGenerator.to_terminal_text(res)
        self.assertNotIn("\x1b[31m", term_str)
        self.assertNotIn("\nHEADING", term_str)
        self.assertIn("BAD HEADING_INJECTION", term_str)

    def test_reachable_under_hostile_tag_escaping_markdown(self):
        from cgull.models import ConfigProfile
        hostile_profile = ConfigProfile("FOO\n### INJECTED_HEADING\n|pipe`tick", {"LEGACY_AUTH": None})
        profiles = [ConfigProfile("baseline", {}), hostile_profile]
        res = self.scanner.scan_text_profiles(self.source_code, profiles=profiles, file_path="auth.c")
        md_str = ReportGenerator.to_markdown(res)
        self.assertNotIn("\n### INJECTED_HEADING", md_str)
        self.assertIn("\\|pipe\\`tick", md_str)


if __name__ == "__main__":
    unittest.main()
