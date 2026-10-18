import pytest
from cgull.ast_analyzer import CASTParser
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine, Severity
from cgull.rules.crypto_and_safety import UncheckedPrivilegeDropRule

TEST_CODE = """
#include <unistd.h>

void safe_drops() {
    if (setuid(1000) != 0) return;
    int res = setgid(1000);
    if (res < 0) return;
    while (seteuid(1000) != 0) {}
}

void unsafe_drops() {
    setuid(1000);
    (void)setgid(1000);
    seteuid(1000), setegid(1000);
}
"""

def test_unchecked_privilege_drop():
    scanner = CGullScanner(rules=[UncheckedPrivilegeDropRule()])
    res = scanner.scan_text(TEST_CODE, file_path="test_privs.c")

    issues_by_line = {issue.line_number: issue for issue in res.issues}

    # Vulnerable lines
    # 12: setuid
    # 13: (void)setgid
    # 14: seteuid, setegid
    assert 12 in issues_by_line
    assert "Return value of privilege-dropping function" in issues_by_line[12].message

    assert 13 in issues_by_line
    assert issues_by_line[13].message.find("setgid") != -1

    assert 14 in issues_by_line
    # Depending on how the comma operator is parsed, we might get two findings for line 14 or just one.
    assert "Return value of privilege-dropping function" in issues_by_line[14].message

    # Safe lines
    # 5, 6, 8
    assert 5 not in issues_by_line
    assert 6 not in issues_by_line
    assert 8 not in issues_by_line


# --------------------------------------------------------------------------
# Shared cases: every analysis path must flag exactly the lines marked FLAG.
# (Comments are stripped before analysis, so the markers do not affect it.)
# --------------------------------------------------------------------------

COMMON_CODE = """#include <unistd.h>
int handle_status(int);
int ok;

void statements(int c) {
    setuid(1);                                  // FLAG
    handle_status(setuid(2));
    int rc = 0; setuid(3);                      // FLAG
    if (setuid(4)) return;
    if (c) setuid(5);                           // FLAG
    for (setuid(6); c; c--) {}                  // FLAG
    for (c = 0; setuid(7); c++) {}
    c = c ? setuid(8) : 0;
    setuid(9) || handle_status(1);
    seteuid(10), setegid(11);                   // FLAG
    (void)setgid(12);                           // FLAG
    while (c) setuid(13);                       // FLAG
    if (c) { c = 1; } else setuid(14);          // FLAG
    rc = setuid(15);
    while (setuid(16) != 0) {}
    handle_status(handle_status(setuid(17)));
    if (rc && setuid(18) != 0) return;
    ok && setuid(23);                           // FLAG
    !c && setgid(24);                           // FLAG
    c ? setuid(25) : 0;                         // FLAG
    c ? setuid(26) : setgid(26);                // FLAG
    rc = (setuid(27), 2);                       // FLAG
    rc = (2, setuid(28));
    if (setuid(29), c) return;                  // FLAG
    ok = ok && setuid(30);
    rc = c ? setuid(31) : setgid(31);
    rc = !setuid(32);
    ok && !setuid(33);
    switch (c) {
    case -1: setuid(19); break;                 // FLAG
    default: break;
    }
}

int returned(void) {
    return setuid(20);
}

int returned_parenthesized(void) {
    return (setuid(21));
}
"""

# A construct pycparser cannot parse forces the lexical fallback parser while
# leaving every line number above unchanged.
FORCE_FALLBACK_SUFFIX = "template <typename T> struct Box { T v; };\n"


def _marked_lines(code):
    return [n for n, line in enumerate(code.splitlines(), 1) if "// FLAG" in line]


def _flagged_lines(code, mode=AnalysisEngine.HYBRID):
    scanner = CGullScanner(rules=[UncheckedPrivilegeDropRule()], engine_mode=mode)
    res = scanner.scan_text(code, file_path="t.c")
    return sorted({issue.line_number for issue in res.issues})


@pytest.mark.parametrize(
    "mode",
    [AnalysisEngine.HYBRID, AnalysisEngine.REGEX, AnalysisEngine.AST],
    ids=["hybrid", "regex-only", "ast-only"],
)
def test_common_cases_agree_on_every_engine_path(mode):
    assert _flagged_lines(COMMON_CODE, mode) == _marked_lines(COMMON_CODE)


def test_common_cases_agree_on_lexical_fallback_parser():
    code = COMMON_CODE + FORCE_FALLBACK_SUFFIX
    ctx = CASTParser().parse(code)
    assert ctx.pycparser_ast is None, "fixture must exercise the no-AST fallback"
    assert _flagged_lines(code, AnalysisEngine.AST) == _marked_lines(COMMON_CODE)
    assert _flagged_lines(code, AnalysisEngine.HYBRID) == _marked_lines(COMMON_CODE)


def _dropped_callees(code, mode):
    scanner = CGullScanner(rules=[UncheckedPrivilegeDropRule()], engine_mode=mode)
    issues = scanner.scan_text(code, file_path="t.c").issues
    return sorted(i.message.split("'")[1] for i in issues)


@pytest.mark.parametrize(
    "mode, force_fallback",
    [
        (AnalysisEngine.AST, False),
        (AnalysisEngine.REGEX, False),
        (AnalysisEngine.AST, True),
    ],
    ids=["ast", "regex-only", "lexical-fallback"],
)
def test_only_the_dropped_operand_of_a_comma_expression_is_reported(mode, force_fallback):
    suffix = FORCE_FALLBACK_SUFFIX if force_fallback else ""
    head = "#include <unistd.h>\nint f(int c) {\n    int rc = 0;\n"
    tail = "\n    return rc;\n}\n" + suffix
    cases = {
        "    rc = (setuid(1), 2);": ["setuid()"],
        "    rc = (2, setuid(1));": [],
        "    c = (setuid(1), setgid(2));": ["setuid()"],
        "    seteuid(1), setegid(2);": ["setegid()", "seteuid()"],
        "    if (setuid(1), c) return 0;": ["setuid()"],
        "    if (c, setuid(1)) return 0;": [],
        "    rc = (setuid(1), setgid(2)) + 1;": ["setuid()"],
    }
    for stmt, expected in cases.items():
        code = head + stmt + tail
        if force_fallback:
            assert CASTParser().parse(code).pycparser_ast is None
        assert _dropped_callees(code, mode) == expected, stmt


def test_issue_metadata_is_reported_for_each_engine():
    for mode, engine_name in ((AnalysisEngine.AST, "AST"), (AnalysisEngine.REGEX, "Regex")):
        scanner = CGullScanner(rules=[UncheckedPrivilegeDropRule()], engine_mode=mode)
        res = scanner.scan_text("#include <unistd.h>\nvoid f(void) {\n    setuid(1000);\n}\n", file_path="t.c")
        assert len(res.issues) == 1
        issue = res.issues[0]
        assert issue.rule_id == "CGULL-057"
        assert issue.impact == Severity.HIGH
        assert issue.cwe_id == "CWE-273"
        assert issue.engine == engine_name
        assert issue.line_number == 3
        assert issue.column_number == 5
        assert "setuid" in issue.message


# --------------------------------------------------------------------------
# Review feedback: a call used as a function argument is not discarded
# --------------------------------------------------------------------------

ARGUMENT_CODE = """#include <unistd.h>
int handle_status(int);
int report(int, int);
void f(void) {
    handle_status(setuid(1000));
    report(1, setgid(1000));
    handle_status(report(0, seteuid(1000)));
}
"""


@pytest.mark.parametrize(
    "mode",
    [AnalysisEngine.HYBRID, AnalysisEngine.REGEX, AnalysisEngine.AST],
    ids=["hybrid", "regex-only", "ast-only"],
)
def test_call_passed_as_function_argument_is_not_reported(mode):
    assert _flagged_lines(ARGUMENT_CODE, mode) == []


def test_call_passed_as_function_argument_is_not_reported_by_lexical_fallback():
    code = ARGUMENT_CODE + FORCE_FALLBACK_SUFFIX
    assert CASTParser().parse(code).pycparser_ast is None
    assert _flagged_lines(code, AnalysisEngine.AST) == []


# --------------------------------------------------------------------------
# AST precision: which operand of a compound expression is actually dropped
# --------------------------------------------------------------------------

def _ast_issues(body):
    code = "#include <unistd.h>\nint handle_status(int);\nint ok;\nvoid f(int c) {\n" + body + "\n}\n"
    scanner = CGullScanner(rules=[UncheckedPrivilegeDropRule()], engine_mode=AnalysisEngine.AST)
    return scanner.scan_text(code, file_path="t.c").issues


def test_comma_expression_reports_only_the_dropped_operand():
    issues = _ast_issues("    c = (setuid(1), setgid(2));")
    assert len(issues) == 1
    assert "setuid" in issues[0].message  # setgid's value is what `c` receives


def test_comma_expression_statement_reports_every_operand():
    issues = _ast_issues("    seteuid(1), setegid(2);")
    assert sorted(i.message.split("'")[1] for i in issues) == ["setegid()", "seteuid()"]


def test_short_circuit_operands():
    assert _ast_issues("    setuid(1) || handle_status(1);") == []  # tested for failure
    assert _ast_issues("    setuid(1) && handle_status(1);") == []
    assert len(_ast_issues("    ok && setuid(1);")) == 1  # result thrown away


def test_ternary_statement_drops_both_branches_but_not_the_condition():
    assert len(_ast_issues("    c ? setuid(1) : setgid(1);")) == 2
    assert _ast_issues("    setuid(1) ? handle_status(1) : handle_status(2);") == []


def test_cast_to_non_void_type_still_discards():
    assert len(_ast_issues("    (int)setuid(1);")) == 1
    assert _ast_issues("    c = (int)setuid(1);") == []


def test_unary_and_arithmetic_use_counts_as_consumed():
    assert _ast_issues("    c = !setuid(1);") == []
    assert _ast_issues("    c = 1 + setuid(1);") == []


def test_non_target_calls_and_member_calls_are_ignored():
    assert _ast_issues("    handle_status(1);") == []


# --------------------------------------------------------------------------
# Regex path: statement scoping and multi-line statements
# --------------------------------------------------------------------------

def _regex_flagged(code):
    return _flagged_lines(code, AnalysisEngine.REGEX)


def test_regex_earlier_assignment_in_same_line_does_not_hide_call():
    # An earlier statement's '=' used to suppress the report in regex-only mode.
    code = "#include <unistd.h>\nvoid f(void) {\n    int rc = 0; setuid(1000);\n    int x = 1; seteuid(1000), x = 2;\n}\n"
    assert _regex_flagged(code) == [3, 4]


def test_regex_assignment_in_same_statement_still_counts_as_checked():
    code = "#include <unistd.h>\nvoid f(void) {\n    int rc = 0, ok = setuid(1000);\n    rc = setgid(1);\n}\n"
    assert _regex_flagged(code) == []


def test_regex_multiline_statements():
    code = """#include <unistd.h>
int report(int, int);
void f(int c, int rc) {
    rc =
        setuid(1);
    report(c,
        setuid(2));
    if (c &&
        setuid(3))
        return;
    if (c)
        setuid(4);
    while (rc)
        setuid(5);
    else_branch:
    setuid(6);
}
"""
    # Lines 5, 7 and 9 are consumed (assignment continued on the next line, call
    # argument, condition). 12: braceless if body, 14: braceless while body,
    # 16: statement after a label.
    assert _regex_flagged(code) == [12, 14, 16]


def test_regex_prefix_does_not_leak_across_statement_boundaries():
    code = """#include <unistd.h>
void f(int c) {
    c = 1;
    setuid(1);
    if (c) {
        c = 2;
    }
    setgid(2);
}
"""
    assert _regex_flagged(code) == [4, 8]


def test_regex_literals_and_comments_do_not_affect_the_decision():
    code = """#include <unistd.h>
void log_msg(const char *);
void f(void) {
    log_msg("a=b"); setuid(1);
    log_msg("please call setuid(0) later");
    /* x = */ setgid(2);
}
"""
    assert _regex_flagged(code) == [4, 6]


def test_regex_ignores_prototypes_members_and_macro_definitions():
    code = """#include <unistd.h>
extern int setuid(uid_t uid);
typedef int (*dropper)(void);
struct ops { int (*setuid)(int); };
#define DROP_PRIVS() setuid(0)
#define DROP_BOTH() \\
    setuid(0); \\
    setgid(0)
int f(struct ops *o) {
    o->setuid(1);
    return DROP_PRIVS();
}
"""
    assert _regex_flagged(code) == []


def test_regex_scan_line_without_masked_line_masks_literals_itself():
    rule = UncheckedPrivilegeDropRule()
    line = 'log("x = 1"); setuid(0);'
    issues = rule.scan_line("t.c", 1, line, line, [line])
    assert len(issues) == 1
    assert issues[0].column_number == line.index("setuid") + 1
    assert issues[0].code_snippet == line


def test_regex_scan_line_tolerates_missing_source_lines():
    rule = UncheckedPrivilegeDropRule()
    assert len(rule.scan_line("t.c", 5, "    setuid(0);", "", [])) == 1
    assert rule.scan_line("t.c", 5, "    rc = setuid(0);", "", []) == []


def test_regex_reports_each_unchecked_call_on_a_line_once():
    code = "#include <unistd.h>\nvoid f(void) {\n    setuid(1); setgid(2);\n}\n"
    scanner = CGullScanner(rules=[UncheckedPrivilegeDropRule()], engine_mode=AnalysisEngine.REGEX)
    issues = scanner.scan_text(code, file_path="t.c").issues
    assert sorted(i.column_number for i in issues) == [5, 16]


# --------------------------------------------------------------------------
# Lexical fallback (no pycparser AST)
# --------------------------------------------------------------------------

def test_fallback_condition_is_not_reported_even_without_assignment_target():
    # The lexical call list has no assignment target for `if (setuid(...))`;
    # the word-boundary check used to be malformed so this was reported.
    code = """#include <unistd.h>
void f(int uid) {
    if (setuid(uid)) return;
    while (setgid(uid)) {}
    setuid(uid);
}
""" + FORCE_FALLBACK_SUFFIX
    assert CASTParser().parse(code).pycparser_ast is None
    assert _flagged_lines(code, AnalysisEngine.AST) == [5]


def test_fallback_same_line_earlier_assignment_does_not_hide_call():
    code = """#include <unistd.h>
void f(void) {
    int rc = 0; setuid(1000);
}
""" + FORCE_FALLBACK_SUFFIX
    assert CASTParser().parse(code).pycparser_ast is None
    scanner = CGullScanner(rules=[UncheckedPrivilegeDropRule()], engine_mode=AnalysisEngine.AST)
    issues = scanner.scan_text(code, file_path="t.c").issues
    assert [(i.line_number, i.column_number) for i in issues] == [(3, 17)]


def test_fallback_picks_the_matching_call_when_a_callee_repeats_on_one_line():
    code = """#include <unistd.h>
int f(void) {
    int rc = setuid(1); setuid(2);
    return rc;
}
""" + FORCE_FALLBACK_SUFFIX
    assert CASTParser().parse(code).pycparser_ast is None
    scanner = CGullScanner(rules=[UncheckedPrivilegeDropRule()], engine_mode=AnalysisEngine.AST)
    issues = scanner.scan_text(code, file_path="t.c").issues
    assert [(i.line_number, i.column_number) for i in issues] == [(3, 25)]
