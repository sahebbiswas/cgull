import unittest

from benchmarks.security_fact_support import build_security_context, build_security_models
from cgull.cfg.security_dataflow import Provenance
from cgull.cfg.security_queries import (
    SecuritySinkFinding,
    SecuritySinkViolation,
    query_unvalidated_sink_flows,
)
from cgull.semantic_models import ValidationProperty


class TestSecurityQueries(unittest.TestCase):
    def test_definite_violation_is_not_degraded_by_unknown_peer(self):
        required = frozenset({ValidationProperty.BOUNDS_CHECKED})
        finding = SecuritySinkFinding(
            function_name="caller",
            sink_name="sink",
            line_number=1,
            expression="sink(a, b)",
            violations=(
                SecuritySinkViolation(
                    0, "a", Provenance.UNTRUSTED, required, required
                ),
                SecuritySinkViolation(
                    1, "b", Provenance.UNKNOWN, required, required
                ),
            ),
        )
        self.assertFalse(finding.degraded)

    def test_all_unknown_violations_are_degraded(self):
        required = frozenset({ValidationProperty.BOUNDS_CHECKED})
        finding = SecuritySinkFinding(
            function_name="caller",
            sink_name="sink",
            line_number=1,
            expression="sink(a)",
            violations=(
                SecuritySinkViolation(
                    0, "a", Provenance.UNKNOWN, required, required
                ),
            ),
        )
        self.assertTrue(finding.degraded)

    def test_direct_source_name_is_included_when_known(self):
        source = """
int external_read(void);
void sink(int);
void caller(void) {
    int value = external_read();
    sink(value);
}
"""
        ctx = build_security_context(source)
        findings = query_unvalidated_sink_flows(ctx, build_security_models())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].violations[0].known_sources, ("external_read",))

    def test_partial_validator_is_included_as_evidence(self):
        source = """
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
        ctx = build_security_context(source)
        findings = query_unvalidated_sink_flows(ctx, build_security_models())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].violations[0].observed_validators, ("validate",))


if __name__ == "__main__":
    unittest.main()
