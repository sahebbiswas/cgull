"""
Tests for cgull.models: dataclass serialization and enum behavior.
"""

import unittest

from cgull.models import Issue, ScanResult, FileScanSummary, ScanError, Severity, AnalysisEngine, FixType, ParserStatus, ParseTier, Confidence, ConfigProfile


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
            reachable_under=["+LEGACY_AUTH"],
        )
        d = issue.to_dict()
        self.assertEqual(d["rule_id"], "CGULL-001")
        self.assertEqual(d["impact"], "High")
        self.assertEqual(d["line_number"], 5)
        self.assertEqual(d["fix_type"], "manual_review")
        self.assertEqual(d["reachable_under"], ["+LEGACY_AUTH"])
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


class TestParseTierEnum(unittest.TestCase):
    def test_parsetier_values(self):
        self.assertEqual(ParseTier.PCPP_PYCPARSER.value, "pcpp+pycparser")
        self.assertEqual(ParseTier.DIRECTIVE_STRIPPED.value, "directive-stripped")
        self.assertEqual(ParseTier.REGEX_FALLBACK.value, "regex-fallback")

    def test_file_scan_summary_includes_parse_tier(self):
        fs = FileScanSummary(
            file_path="a.c",
            lines_of_code=100,
            issues_count=1,
            high_count=1,
            medium_count=0,
            low_count=0,
            scan_duration_ms=1.0,
            parse_tier=ParseTier.PCPP_PYCPARSER.value,
        )
        d = fs.to_dict()
        self.assertEqual(d["parse_tier"], "pcpp+pycparser")


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


class TestConfigProfile(unittest.TestCase):
    def test_construction_and_flags_types(self):
        cp = ConfigProfile("debug", {"DEBUG": None, "RETRY_COUNT": 5, "VERSION": "1.0"})
        self.assertEqual(cp.name, "debug")
        self.assertEqual(cp.flags, {"DEBUG": None, "RETRY_COUNT": 5, "VERSION": "1.0"})
        self.assertEqual(cp.presence_flags, {"DEBUG"})
        self.assertEqual(cp.value_flags, {"RETRY_COUNT": 5, "VERSION": "1.0"})

    def test_default_flags_is_empty_dict(self):
        cp = ConfigProfile("default")
        self.assertEqual(cp.name, "default")
        self.assertEqual(cp.flags, {})

    def test_label_and_reachable_under_rendering(self):
        cp1 = ConfigProfile("debug")
        self.assertEqual(cp1.label, "+debug")
        self.assertEqual(cp1.reachable_under, "+debug")
        self.assertEqual(str(cp1), "+debug")

        cp2 = ConfigProfile("+release")
        self.assertEqual(cp2.label, "+release")
        self.assertEqual(cp2.reachable_under, "+release")

        cp3 = ConfigProfile("")
        self.assertEqual(cp3.label, "")
        self.assertEqual(cp3.reachable_under, "")

    def test_equality_and_hashing_same_flags(self):
        cp_header = ConfigProfile("debug", {"ENABLE_LOGGING": None, "MAX_WORKERS": 4})
        cp_json = ConfigProfile("debug", {"MAX_WORKERS": 4, "ENABLE_LOGGING": None})
        self.assertEqual(cp_header, cp_json)
        self.assertEqual(hash(cp_header), hash(cp_json))

        # Profiles with different names evaluate as unequal even if flags match
        cp_diff_name1 = ConfigProfile("header_debug", {"FOO": None})
        cp_diff_name2 = ConfigProfile("json_debug", {"FOO": None})
        self.assertNotEqual(cp_diff_name1, cp_diff_name2)

    def test_deduplication_in_set_and_dict(self):
        cp_header = ConfigProfile("debug", {"ENABLE_LOGGING": None, "MAX_WORKERS": 4})
        cp_json = ConfigProfile("debug", {"MAX_WORKERS": 4, "ENABLE_LOGGING": None})
        cp_other = ConfigProfile("prod", {"ENABLE_LOGGING": None, "MAX_WORKERS": 4})

        profile_set = {cp_header, cp_json, cp_other}
        self.assertEqual(len(profile_set), 2)  # cp_header and cp_json deduplicate into 1; cp_other is distinct

        profile_dict = {cp_header: "header_val"}
        profile_dict[cp_json] = "json_val"
        self.assertEqual(len(profile_dict), 1)
        self.assertEqual(profile_dict[cp_header], "json_val")

    def test_inequality_different_flags(self):
        cp1 = ConfigProfile("debug", {"FOO": None})
        cp2 = ConfigProfile("debug", {"FOO": None, "BAR": 1})
        self.assertNotEqual(cp1, cp2)
        self.assertFalse(cp1 == "not_a_config_profile")

    def test_serialization_and_deserialization(self):
        cp = ConfigProfile("release", {"OPTIMIZE": 3, "NDEBUG": None})
        d = cp.to_dict()
        self.assertEqual(d, {
            "name": "release",
            "flags": {"OPTIMIZE": 3, "NDEBUG": None},
            "presence_flags": ["NDEBUG"],
            "value_flags": {"OPTIMIZE": 3},
            "label": "+release",
        })

        cp_restored = ConfigProfile.from_dict(d)
        self.assertEqual(cp, cp_restored)
        self.assertEqual(cp_restored.name, "release")
        self.assertEqual(cp_restored.label, "+release")
        self.assertEqual(cp_restored.flags, {"OPTIMIZE": 3, "NDEBUG": None})

    def test_deserialization_from_presence_and_value_flags(self):
        d = {
            "name": "debug",
            "presence_flags": ["DEBUG", "LOGGING"],
            "value_flags": {"RETRY_COUNT": 3},
        }
        cp = ConfigProfile.from_dict(d)
        self.assertEqual(cp.name, "debug")
        self.assertEqual(cp.flags, {"DEBUG": None, "LOGGING": None, "RETRY_COUNT": 3})
        self.assertEqual(cp.presence_flags, {"DEBUG", "LOGGING"})
        self.assertEqual(cp.value_flags, {"RETRY_COUNT": 3})

    def test_flags_mutation_isolation(self):
        original_flags = {"FLAG1": None, "COUNT": 10}
        cp = ConfigProfile("isolated", original_flags)
        original_flags["FLAG2"] = "modified"
        self.assertNotIn("FLAG2", cp.flags)

    def test_immutability_enforced(self):
        cp = ConfigProfile("immutable", {"FLAG1": None, "COUNT": 10})
        with self.assertRaises(Exception):
            cp.name = "new_name"
        with self.assertRaises(Exception):
            cp.flags = {}

        with self.assertRaises(TypeError):
            cp.flags["FLAG2"] = "new"  # type: ignore

    def test_pickle_serialization(self):
        import pickle
        cp = ConfigProfile("picklable", {"FLAG1": None, "COUNT": 10})
        pickled = pickle.dumps(cp)
        unpickled = pickle.loads(pickled)
        self.assertEqual(cp, unpickled)
        self.assertEqual(unpickled.name, "picklable")
        self.assertEqual(unpickled.flags, {"FLAG1": None, "COUNT": 10})


if __name__ == "__main__":
    unittest.main()
