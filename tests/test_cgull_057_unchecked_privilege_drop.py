import pytest
from cgull.engine import CGullScanner
from cgull.models import Severity
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
