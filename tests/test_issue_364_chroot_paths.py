"""CGULL-039 must cover every successful chroot path."""

import pytest

from cgull.ast_analyzer import CASTParser
from cgull.rules.crypto_and_safety import ImproperChrootJailRule
from cgull import CGullScanner


def scan(body):
    code = (
        "int chroot(const char *); int chdir(const char *); void work(void);\nvoid f(int flag, int other) {\n"
        + body
        + "\n}"
    )
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return ImproperChrootJailRule().scan_ast("chroot.c", ctx)


@pytest.mark.parametrize(
    "body",
    [
        'chroot("jail"); chdir("/");',
        'if (chroot("jail") == 0) { chdir("/"); work(); }',
        'if (chroot("jail") != 0) return; chdir("/");',
        'if (chroot("jail") < 0) return; chdir("/");',
        'if (chroot("jail")) return; chdir("/");',
        'if (!chroot("jail")) chdir("/");',
        'int rc = chroot("jail"); if (rc == -1) return; chdir("/");',
        'int rc; if ((rc = chroot("jail")) != 0) return; chdir("/");',
        'int rc = chroot("jail"); int copy = rc; if (copy) return; chdir("/");',
        'chroot("jail"); if (flag) chdir("/"); else chdir("/");',
        '{ chroot("jail"); } chdir("/");',
        'chroot("jail"); goto repair; return; repair: chdir("/");',
        'chroot("jail"); do { chdir("/"); } while (flag);',
        'while (flag) { chroot("jail"); chdir("/"); }',
        'if (flag && chroot("jail") == 0) chdir("/");',
        'chroot("jail") == 0 && chdir("/");',
        'chroot("jail") != 0 || chdir("/");',
        'chroot("jail"), chdir("/");',
        'if (0) chroot("jail");',
        'return; chroot("jail");',
        'sizeof(chroot("jail"));',
    ],
)
def test_safe_success_paths(body):
    assert scan(body) == []


@pytest.mark.parametrize(
    "body",
    [
        'chroot("jail");',
        'chroot("jail"); if (flag) chdir("/");',
        'chdir("/"); chroot("jail");',
        'chroot("jail"); if (flag) return; chdir("/");',
        'chroot("jail"); if (flag) goto end; chdir("/"); end: return;',
        'chroot("jail"); while (flag) { chdir("/"); }',
        'chroot("jail"); do { if (flag) break; chdir("/"); } while (other);',
        'chroot("jail"); loop: if (flag) goto loop; chdir("/");',
        'chroot("jail"); goto missing; chdir("/");',
        'if (chroot("jail") != 0) chdir("/");',
        'int rc = chroot("jail"); if (rc == 0) return; chdir("/");',
        'int rc = chroot("jail"); rc = flag; if (rc) return; chdir("/");',
        'if (chroot("jail") == 0 && flag) chdir("/");',
        'chroot("jail") == 0 || chdir("/");',
        'chroot("jail"); chdir("..");',
        'chroot("jail"); work(); chdir("/");',
        'chroot("jail"); sizeof(chdir("/"));',
        'if (flag) chroot("jail"); else chdir("/");',
        'chroot("jail"); switch (flag) { case 1: chdir("/"); break; default: return; }',
    ],
)
def test_adversarial_success_paths(body):
    assert len(scan(body)) == 1


def test_multiple_calls_are_independent():
    findings = scan('chroot("first");\nchdir("/");\nchroot("second");')
    assert [issue.line_number for issue in findings] == [5]


def test_hybrid_does_not_add_lexical_false_positive():
    scanner = CGullScanner(rules=[ImproperChrootJailRule()])
    assert (
        scanner.scan_text(
            'void f(void) { { chroot("jail"); } chdir("/"); }'
        ).total_issues_count
        == 0
    )


@pytest.mark.parametrize(
    "body",
    [
        'chroot("jail") + chdir("/");',
        'work(chroot("jail"), chdir("/"));',
        'int rc = flag; chroot("jail"); { int rc = 1; } if (rc) chdir("/");',
        'volatile int rc = chroot("jail"); if (rc) return; chdir("/");',
        'chroot("jail"); for (;;) {}',
    ],
)
def test_uncertain_order_bindings_and_nontermination(body):
    assert scan(body)


def test_ternary_repairs_all_paths():
    assert scan('chroot("jail"); flag ? chdir("/") : chdir("/");') == []


def test_ternary_bypass():
    assert scan('chroot("jail"); flag ? chdir("/") : 0;')


def test_label_does_not_evaluate_its_entire_statement():
    assert scan('chroot("jail"); repair: if (flag) chdir("/");')
    assert scan('chroot("jail"); repair: { if (flag) return; chdir("/"); }')
    assert scan('start: chroot("jail"); chdir("/");') == []


def test_failed_structured_parse_cannot_prove_lexical_repair():
    ctx = CASTParser().parse('void f(void) { chroot("jail"); chdir("/"); }')
    ctx.pycparser_ast = None
    ctx.has_pycparser = False
    assert ImproperChrootJailRule().scan_ast("fallback.c", ctx)


def test_compound_assignment_does_not_use_rhs_as_result():
    assert scan('chroot("jail"); int rc = 1; if (rc -= 1) chdir("/");')


def test_unsequenced_continuation_can_precede_repair():
    assert scan('chroot("jail"); chdir("/") + work();')


def test_unsequenced_arguments_can_continue_before_repair():
    assert scan('chroot("jail"); work(chdir("/"), work());')
