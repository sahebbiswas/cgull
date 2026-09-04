from cgull.engine import CGullScanner
from cgull.models import Severity
from cgull.rules.banned_functions import (
    BannedFunctionPolicy,
    BannedFunctionsRule,
)


def _scan(source: str):
    return CGullScanner(rules=[BannedFunctionsRule()]).scan_text(source, file_path="policy.c").issues


def test_default_banned_function_policy_is_table_driven():
    expected = {
        "gets": BannedFunctionPolicy.UNCONDITIONAL,
        "strcpy": BannedFunctionPolicy.UNCONDITIONAL,
        "strcat": BannedFunctionPolicy.UNCONDITIONAL,
        "sprintf": BannedFunctionPolicy.UNCONDITIONAL,
        "vsprintf": BannedFunctionPolicy.UNCONDITIONAL,
        "scanf": BannedFunctionPolicy.DATA_DEPENDENT,
        "mktemp": BannedFunctionPolicy.UNCONDITIONAL,
        "tmpnam": BannedFunctionPolicy.UNCONDITIONAL,
        "tempnam": BannedFunctionPolicy.UNCONDITIONAL,
    }
    rule = BannedFunctionsRule()
    assert set(rule.banned_funcs) == set(expected)
    for function_name, policy in expected.items():
        entry = rule.policy[function_name]
        assert entry.policy is policy
        assert entry.reason


def test_trusted_literal_does_not_suppress_or_downgrade_unconditional_strcpy_or_gets():
    issues = _scan(
        """
        void copy_trusted(void) {
            char dest[32];
            const char *trusted = "ok";
            strcpy(dest, trusted);
            gets(dest);
        }
        """
    )
    assert len(issues) == 2
    assert all(issue.impact is Severity.HIGH for issue in issues)
    assert all("policy=unconditional" in issue.message for issue in issues)


def test_bounded_direct_scanf_is_suppressed_but_unbounded_scanf_is_reported():
    issues = _scan(
        """
        void read_name(void) {
            char name[32];
            scanf("%31s", name);
            scanf("%s", name);
        }
        """
    )
    assert len(issues) == 1
    assert "policy=data-dependent" in issues[0].message
    assert "unbounded %s" in issues[0].message


def test_bounded_scanf_format_propagates_across_helper_boundary():
    issues = _scan(
        """
        static void read_with(const char *fmt, char *out) {
            scanf(fmt, out);
        }

        void caller(void) {
            char name[32];
            read_with("%31s", name);
        }
        """
    )
    assert issues == []


def test_unbounded_scanf_format_propagates_across_helper_boundary():
    issues = _scan(
        """
        static void read_with(const char *fmt, char *out) {
            scanf(fmt, out);
        }

        void caller(void) {
            char name[32];
            read_with("%s", name);
        }
        """
    )
    assert len(issues) == 1
    assert "at least one caller passes a literal with an unbounded %s" in issues[0].message


def test_unknown_scanf_format_retains_conservative_fallback_coverage():
    issues = _scan(
        """
        void read_name(const char *fmt, char *out) {
            scanf(fmt, out);
        }
        """
    )
    assert len(issues) == 1
    assert "conservative fallback retained" in issues[0].message


def test_project_configured_bans_are_unconditional_unless_explicitly_overridden():
    rule = BannedFunctionsRule(
        extra_banned_funcs={
            "project_copy": {"reason": "project policy"},
            "conditional_copy": {
                "reason": "project semantic policy",
                "policy": "data-dependent",
            },
        }
    )
    assert rule.policy["project_copy"].policy is BannedFunctionPolicy.UNCONDITIONAL
    assert rule.policy["conditional_copy"].policy is BannedFunctionPolicy.DATA_DEPENDENT


def test_scanf_prototype_is_not_reported():
    issues = _scan('int scanf(const char *format, ...);\n')
    assert issues == []
