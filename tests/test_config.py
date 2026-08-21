"""
Unit tests for C-GULL project configuration file support (TOML) and inline suppressions.
"""

import os
import tempfile
import unittest
from cgull.config import CGullConfig, find_config_file, load_config, parse_severity_str
from cgull.engine import CGullScanner
from cgull.models import Severity, AnalysisEngine
from cgull.rules import get_all_rules, get_rule_by_id
from cgull.rules.banned_functions import BannedFunctionsRule
from cgull.rules.memory_management import UncheckedDynamicAllocationsRule, UseAfterFreeRule
from cgull.cli import main
from cgull.utils import SuppressionMap


class TestConfigLoading(unittest.TestCase):
    def test_find_config_file_standalone(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, ".cgull.toml")
            with open(config_path, "w", encoding="utf-8") as f:
                f.write("schema_version = 1\n")

            found = find_config_file(tmpdir)
            self.assertEqual(os.path.abspath(found), os.path.abspath(config_path))

    def test_find_config_file_pyproject(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pyproject_path = os.path.join(tmpdir, "pyproject.toml")
            with open(pyproject_path, "w", encoding="utf-8") as f:
                f.write("[tool.cgull]\nschema_version = 1\n")

            found = find_config_file(tmpdir)
            self.assertEqual(os.path.abspath(found), os.path.abspath(pyproject_path))

    def test_standalone_precedence_over_pyproject(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            standalone_path = os.path.join(tmpdir, ".cgull.toml")
            pyproject_path = os.path.join(tmpdir, "pyproject.toml")
            with open(standalone_path, "w", encoding="utf-8") as f:
                f.write("schema_version = 1\n")
            with open(pyproject_path, "w", encoding="utf-8") as f:
                f.write("[tool.cgull]\nschema_version = 1\n")

            found = find_config_file(tmpdir)
            self.assertEqual(os.path.abspath(found), os.path.abspath(standalone_path))

    def test_load_full_config(self):
        toml_content = """
schema_version = 1
unknown_future_key = "test_warning"

[rules]
skip = { "CGULL-019" = "team MISRA style exception" }

[rules.severity]
CGULL-024 = "high"
CGULL-020 = "low"

[functions.memory]
alloc   = ["xmalloc", "kmalloc"]
realloc = ["xrealloc"]
dealloc = ["xfree", "kfree"]

[functions.banned]
[functions.banned.custom_copy]
reason = "unsafe custom copy"
remediation = "use safe_copy()"

[paths]
exclude = ["third_party/", "generated/"]

[output]
default_format = "sarif"
fail_on = "high"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = os.path.join(tmpdir, ".cgull.toml")
            with open(cfg_file, "w", encoding="utf-8") as f:
                f.write(toml_content)

            config = load_config(config_path=cfg_file)

            self.assertEqual(config.schema_version, 1)
            self.assertIn("CGULL-019", config.skipped_rules)
            self.assertEqual(config.skipped_rules["CGULL-019"], "team MISRA style exception")
            self.assertEqual(config.severity_overrides["CGULL-024"], Severity.HIGH)
            self.assertEqual(config.severity_overrides["CGULL-020"], Severity.LOW)
            self.assertEqual(config.alloc_funcs, ["xmalloc", "kmalloc"])
            self.assertEqual(config.realloc_funcs, ["xrealloc"])
            self.assertEqual(config.dealloc_funcs, ["xfree", "kfree"])
            self.assertIn("custom_copy", config.banned_funcs)
            self.assertEqual(config.banned_funcs["custom_copy"]["reason"], "unsafe custom copy")
            self.assertEqual(config.exclude_paths, ["third_party/", "generated/"])
            self.assertEqual(config.default_format, "sarif")
            self.assertEqual(config.fail_on, "high")
            self.assertTrue(any("unknown_future_key" in w for w in config.warnings))

    def test_warn_on_fallback_config(self):
        toml_content = """
schema_version = 1
[output]
warn_on_fallback = true
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = os.path.join(tmpdir, ".cgull.toml")
            with open(cfg_file, "w", encoding="utf-8") as f:
                f.write(toml_content)

            config = load_config(config_path=cfg_file)
            self.assertTrue(config.warn_on_fallback)


class TestRuleCustomization(unittest.TestCase):
    def test_rule_skipping(self):
        cfg = CGullConfig(skipped_rules={"CGULL-019": "skipped"})
        all_rules = get_all_rules()
        active = cfg.apply_to_rules(all_rules)
        active_ids = {r.rule_id for r in active}
        self.assertNotIn("CGULL-019", active_ids)
        self.assertIn("CGULL-001", active_ids)

    def test_severity_overrides(self):
        cfg = CGullConfig(severity_overrides={"CGULL-020": Severity.HIGH})
        all_rules = get_all_rules()
        active = cfg.apply_to_rules(all_rules)
        r20 = next(r for r in active if r.rule_id == "CGULL-020")
        self.assertEqual(r20.impact, Severity.HIGH)

    def test_custom_allocators(self):
        rule = UncheckedDynamicAllocationsRule(extra_alloc_funcs=["xmalloc"])
        self.assertIn("xmalloc", rule.alloc_funcs)

        code = """
void test_alloc(void) {
    char *p = xmalloc(100);
    p[0] = 'A';
}
"""
        scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
        result = scanner.scan_text(code, file_path="test.c")
        self.assertEqual(result.total_issues_count, 1)
        self.assertEqual(result.issues[0].rule_id, "CGULL-003")

    def test_custom_deallocators_uaf(self):
        rule = UseAfterFreeRule(extra_dealloc_funcs=["xfree"])
        self.assertIn("xfree", rule.dealloc_funcs)

        code = """
void test_uaf(void) {
    char *p = malloc(100);
    xfree(p);
    p[0] = 'A';
}
"""
        scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
        result = scanner.scan_text(code, file_path="test.c")
        self.assertEqual(result.total_issues_count, 1)
        self.assertEqual(result.issues[0].rule_id, "CGULL-022")

    def test_custom_banned_functions(self):
        rule = BannedFunctionsRule(extra_banned_funcs={
            "custom_strcpy": {"reason": "custom insecure copy", "remediation": "use safe_copy()"}
        })
        code = """
void test_banned(void) {
    custom_strcpy(dest, src);
}
"""
        issues = rule.scan_line("test.c", 3, "    custom_strcpy(dest, src);", code, code.splitlines())
        self.assertEqual(len(issues), 1)
        self.assertIn("custom insecure copy", issues[0].message)


class TestInlineSuppressions(unittest.TestCase):
    def test_extended_suppression_syntax(self):
        lines = [
            "int foo() {} /* cgull-disable-line CGULL-019 */",
            "// cgull-disable-next-line CGULL-007",
            "arr[i] = 10;",
            "gets(buf); // cgull-disable CGULL-001"
        ]
        sup = SuppressionMap.from_source(lines)
        self.assertTrue(sup.is_suppressed(1, "CGULL-019"))
        self.assertTrue(sup.is_suppressed(3, "CGULL-007"))
        self.assertFalse(sup.is_suppressed(2, "CGULL-007"))
        self.assertTrue(sup.is_suppressed(4, "CGULL-001"))


class TestCLIConfigIntegration(unittest.TestCase):
    def test_cli_rules_with_config(self):
        toml_content = """
schema_version = 1
[rules]
skip = { "CGULL-019" = "MISRA explicit void disabled" }
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, ".cgull.toml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(toml_content)

            exit_code = main(["rules", "--config", cfg_path])
            self.assertEqual(exit_code, 0)

    def test_missing_explicit_config_fails(self):
        exit_code = main(["scan", ".", "--config", "non_existent_config.toml"])
        self.assertEqual(exit_code, 1)

    def test_invalid_fail_on_fails(self):
        toml_content = """
schema_version = 1
[output]
fail_on = "invalid_severity_level"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, ".cgull.toml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(toml_content)

            exit_code = main(["scan", ".", "--config", cfg_path])
            self.assertEqual(exit_code, 1)

    def test_invalid_banned_func_identifier_fails(self):
        toml_content = """
schema_version = 1
[functions.banned]
"invalid regex (func)" = "reason"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, ".cgull.toml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(toml_content)

            exit_code = main(["scan", ".", "--config", cfg_path])
            self.assertEqual(exit_code, 1)

    def test_string_literal_does_not_suppress(self):
        lines = [
            'char *msg = "cgull-disable-next-line CGULL-001";',
            "gets(buf);"
        ]
        sup = SuppressionMap.from_source(lines)
        self.assertFalse(sup.is_suppressed(2, "CGULL-001"))


if __name__ == "__main__":
    unittest.main()
