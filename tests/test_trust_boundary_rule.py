import unittest

from benchmarks.security_fact_support import build_security_context, build_security_models
from cgull.config import CGullConfig
from cgull.models import Confidence
from cgull.rules.trust_boundary import UnvalidatedExternalDataSinkRule
from cgull.semantic_models import parse_semantic_models


class TestUnvalidatedExternalDataSinkRule(unittest.TestCase):
    def setUp(self):
        self.models = build_security_models()

    def _scan(self, source: str, models=None):
        ctx = build_security_context(source)
        ctx.source_lines = source.splitlines()
        rule = UnvalidatedExternalDataSinkRule()
        CGullConfig(semantic_models=models or self.models).apply_to_rules([rule])
        return rule.scan_ast("test.c", ctx)

    def test_detects_straight_line_use_before_validation(self):
        issues = self._scan(
            """
int external_read(void);
void sink(int);
void caller(void) {
    int value = external_read();
    sink(value);
}
"""
        )
        self.assertEqual(len(issues), 1)
        self.assertIn("sink", issues[0].message)
        self.assertIn("bounds_checked", issues[0].message)
        self.assertIn("untrusted", issues[0].message)

    def test_checked_validator_satisfies_sink_requirement(self):
        issues = self._scan(
            """
int external_read(void);
int validate(int);
void sink(int);
void caller(void) {
    int value = external_read();
    if (!validate(value))
        return;
    sink(value);
}
"""
        )
        self.assertEqual(issues, [])

    def test_validation_after_sink_is_ineffective(self):
        issues = self._scan(
            """
int external_read(void);
int validate(int);
void sink(int);
void caller(void) {
    int value = external_read();
    sink(value);
    validate(value);
}
"""
        )
        self.assertEqual(len(issues), 1)

    def test_validation_on_only_one_branch_is_not_guaranteed(self):
        issues = self._scan(
            """
int external_read(void);
int validate(int);
void sink(int);
void caller(int gate) {
    int value = external_read();
    if (gate) {
        if (!validate(value))
            return;
    }
    sink(value);
}
"""
        )
        self.assertEqual(len(issues), 1)

    def test_validation_inside_optional_loop_is_not_guaranteed(self):
        issues = self._scan(
            """
int external_read(void);
int validate(int);
void sink(int);
void caller(int gate) {
    int value = external_read();
    while (gate) {
        if (!validate(value))
            return;
        break;
    }
    sink(value);
}
"""
        )
        self.assertEqual(len(issues), 1)

    def test_validation_in_only_one_switch_case_is_not_guaranteed(self):
        issues = self._scan(
            """
int external_read(void);
int validate(int);
void sink(int);
void caller(int mode) {
    int value = external_read();
    switch (mode) {
    case 1:
        if (!validate(value))
            return;
        break;
    default:
        break;
    }
    sink(value);
}
"""
        )
        self.assertEqual(len(issues), 1)

    def test_validation_properties_are_typed(self):
        models = parse_semantic_models(
            {
                "sources": [{"function": "external_read", "outputs": ["return"]}],
                "validators": [
                    {
                        "function": "authorize",
                        "target": "arg:0",
                        "property": "authorized",
                        "success": "return_nonzero",
                    }
                ],
                "sinks": [
                    {
                        "function": "sink",
                        "requirements": {"arg:0": ["bounds_checked"]},
                    }
                ],
            }
        )
        issues = self._scan(
            """
int external_read(void);
int authorize(int);
void sink(int);
void caller(void) {
    int value = external_read();
    if (!authorize(value))
        return;
    sink(value);
}
""",
            models=models,
        )
        self.assertEqual(len(issues), 1)
        self.assertIn("bounds_checked", issues[0].message)
        self.assertNotIn("missing [authorized]", issues[0].message)

    def test_multihop_source_wrapper_is_detected(self):
        issues = self._scan(
            """
int external_read(void);
void sink(int);
int read_one(void) { return external_read(); }
int read_two(void) { return read_one(); }
void caller(void) {
    int value = read_two();
    sink(value);
}
"""
        )
        self.assertEqual(len(issues), 1)
        self.assertIn("untrusted", issues[0].message)

    def test_unknown_provenance_is_reported_with_limited_confidence(self):
        issues = self._scan(
            """
int unknown_read(void);
void sink(int);
void caller(void) {
    int value = unknown_read();
    sink(value);
}
"""
        )
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].confidence, Confidence.LIMITED)
        self.assertIn("unknown", issues[0].message)


if __name__ == "__main__":
    unittest.main()
