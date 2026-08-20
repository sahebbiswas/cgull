"""
Tests for cgull.models: dataclass serialization and enum behavior.
"""

import unittest

from cgull.models import Issue, ScanResult, FileScanSummary, ScanError, Severity, AnalysisEngine, FixType, ParserStatus, Confidence


class TestSeverityEnum(unittest.TestCase):
    def test_severity_values(self):
        self.assertEqual(Severity.HIGH.value, "High")
        self.assertEqual(Severity.MEDIUM.value, "Medium")
        self.assertEqual(Severity.LOW.value, "Low")

    def test_severity_is_string_enum(self):
        # Severity subclasses str, so it should compare equal to its value
        self.assertEqual(Severity.HIGH, "High")


class TestFixTypeEnum(unittest.TestCase):
    def test_fixtype_values(self):
        self.assertEqual(FixType.SAFE_FIX.value, "safe_fix")
        self.assertEqual(FixType.SUGGESTED_FIX.value, "suggested_fix")
        self.assertEqual(FixType.MANUAL_REVIEW.value, "manual_review")


class TestIssueSerialization(unittest.TestCase):
    def test_to_dict_contains_all_fields(self):
        issue = Issue(
            rule_id="CGULL-001",
            rule_name="Banned Functions",
            impact=Severity.HIGH,
            file_path="test.c",
            line_number=5,
            message="Test message",
        )
        d = issue.to_dict()
        self.assertEqual(d["rule_id"], "CGULL-001")
        self.assertEqual(d["impact"], "High")
        self.assertEqual(d["line_number"], 5)
        self.assertEqual(d["fix_type"], "manual_review")
        self.assertIsNone(d["auto_fix_replacement"])
        self.assertIsNone(d["suggested_fix_replacement"])

    def test_to_dict_with_fix_type(self):
        issue = Issue(
            rule_id="CGULL-002",
            rule_name="Format String",
            impact=Severity.HIGH,
            file_path="test.c",
            line_number=10,
            fix_type=FixType.SAFE_FIX,
            auto_fix_replacement='printf("%s", arg)',
        )
        d = issue.to_dict()
        self.assertEqual(d["fix_type"], "safe_fix")
        self.assertEqual(d["auto_fix_replacement"], 'printf("%s", arg)')
        self.assertIsNone(d["suggested_fix_replacement"])

    def test_default_column_number_is_one(self):
        issue = Issue(rule_id="X", rule_name="X", impact=Severity.LOW, file_path="a.c", line_number=1)
        self.assertEqual(issue.column_number, 1)


class TestScanResultSerialization(unittest.TestCase):
    def test_to_dict_structure(self):
        result = ScanResult(
            target_path="src/",
            scanned_files_count=2,
            total_lines_of_code=100,
            total_issues_count=1,
            high_severity_count=1,
            medium_severity_count=0,
            low_severity_count=0,
            scan_duration_seconds=0.5,
            timestamp="2026-01-01T00:00:00Z",
            issues=[Issue(rule_id="CGULL-001", rule_name="Banned", impact=Severity.HIGH, file_path="a.c", line_number=1)],
            file_summaries=[FileScanSummary(file_path="a.c", lines_of_code=100, issues_count=1, high_count=1, medium_count=0, low_count=0, scan_duration_ms=1.0)],
            analysis_status_counts={ParserStatus.FALLBACK_PARSER.value: 2},
        )
        d = result.to_dict()
        self.assertEqual(d["schema_version"], "1")
        self.assertEqual(d["meta"]["tool"], "C-GULL")
        self.assertIn("analysis", d)
        self.assertEqual(d["analysis"]["parser"], "fallback-parser")
        self.assertEqual(d["analysis"]["status"], "success")
        self.assertEqual(d["summary"]["files_discovered"], 2)
        self.assertEqual(d["summary"]["files_analyzed"], 2)
        self.assertEqual(d["summary"]["files_ignored"], 0)
        self.assertEqual(d["summary"]["files_failed"], 0)
        self.assertEqual(d["summary"]["scanned_files_count"], 2)
        self.assertEqual(len(d["issues"]), 1)
        self.assertEqual(len(d["file_summaries"]), 1)

    def test_empty_result_serializes_cleanly(self):
        result = ScanResult(
            target_path="src/",
            scanned_files_count=0,
            total_lines_of_code=0,
            total_issues_count=0,
            high_severity_count=0,
            medium_severity_count=0,
            low_severity_count=0,
            scan_duration_seconds=0.0,
            timestamp="2026-01-01T00:00:00Z",
        )
        d = result.to_dict()
        self.assertEqual(d["issues"], [])
        self.assertEqual(d["file_summaries"], [])
        self.assertEqual(d["scan_errors"], [])
        self.assertEqual(d["ignored_paths"], [])
        self.assertEqual(d["failed_paths"], [])
        self.assertIn("analysis", d)
        self.assertEqual(d["summary"]["files_discovered"], 0)

    def test_scan_error_to_dict_and_result_integration(self):
        err = ScanError(file_path="broken.c", error_type="PermissionError", message="Permission denied")
        self.assertEqual(err.to_dict(), {
            "file_path": "broken.c",
            "error_type": "PermissionError",
            "message": "Permission denied",
        })
        result = ScanResult(
            target_path="src/",
            scanned_files_count=0,
            total_lines_of_code=0,
            total_issues_count=0,
            high_severity_count=0,
            medium_severity_count=0,
            low_severity_count=0,
            scan_duration_seconds=0.1,
            timestamp="2026-01-01T00:00:00Z",
            scan_errors=[err],
            failed_paths=["broken.c"],
            files_discovered=1,
            files_analyzed=0,
            files_failed=1,
        )
        d = result.to_dict()
        self.assertEqual(d["summary"]["files_failed"], 1)
        self.assertEqual(len(d["scan_errors"]), 1)
        self.assertEqual(d["scan_errors"][0]["error_type"], "PermissionError")

    def test_positional_arguments_compatibility(self):
        issue = Issue(rule_id="CGULL-001", rule_name="Banned", impact=Severity.HIGH, file_path="a.c", line_number=1)
        fs = FileScanSummary(file_path="a.c", lines_of_code=10, issues_count=1, high_count=1, medium_count=0, low_count=0, scan_duration_ms=0.5)
        # Verify positional construction up to legacy positional fields
        res = ScanResult(
            "src/", 1, 10, 1, 1, 0, 0, 0.5, "timestamp",
            [issue], [fs], ["ignored.c"], ["failed.c"]
        )
        self.assertEqual(res.target_path, "src/")
        self.assertEqual(res.scanned_files_count, 1)
        self.assertEqual(res.issues, [issue])
        self.assertEqual(res.file_summaries, [fs])
        self.assertEqual(res.ignored_paths, ["ignored.c"])
        self.assertEqual(res.failed_paths, ["failed.c"])
        self.assertEqual(res.scan_errors, [])


class TestParserStatusAndConfidenceEnums(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(ParserStatus.PYCPARSER_SUCCESS.value, "pycparser-success")
        self.assertEqual(ParserStatus.FALLBACK_PARSER.value, "fallback-parser")
        self.assertEqual(ParserStatus.REGEX.value, "regex")
        self.assertEqual(ParserStatus.PARSE_FAILED.value, "parse-failed")
        self.assertEqual(Confidence.FULL.value, "FULL")
        self.assertEqual(Confidence.FALLBACK.value, "FALLBACK")
        self.assertEqual(Confidence.LIMITED.value, "LIMITED")

    def test_get_overall_parser_status_derivation(self):
        res1 = ScanResult("a", 1, 10, 0, 0, 0, 0, 0.1, "now", analysis_status_counts={ParserStatus.PARSE_FAILED.value: 2})
        self.assertEqual(res1.get_overall_parser_status(), "parse-failed")

        res2 = ScanResult("a", 1, 10, 0, 0, 0, 0, 0.1, "now", analysis_status_counts={ParserStatus.REGEX.value: 2})
        self.assertEqual(res2.get_overall_parser_status(), "regex")

        res3 = ScanResult("a", 1, 10, 0, 0, 0, 0, 0.1, "now", analysis_status_counts={ParserStatus.PYCPARSER_SUCCESS.value: 1, ParserStatus.REGEX.value: 1})
        self.assertEqual(res3.get_overall_parser_status(), "hybrid")


if __name__ == "__main__":
    unittest.main()
