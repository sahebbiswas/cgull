from unittest.mock import patch

import pytest

from cgull import AnalysisEngine, CGullScanner
from cgull.ast_analyzer import CASTParser, CoverageDegradedError
from cgull.models import ParseTier


UNEXPANDED_OFFSETOF = """
int recover(void) {
    return offsetof(Container, member);
}
"""


def test_forced_fallback_rejects_unexpanded_offsetof():
    parser = CASTParser()
    with patch.object(parser, "_try_pcpp_preprocess", return_value=None):
        with pytest.raises(CoverageDegradedError, match="offsetof"):
            parser.parse(UNEXPANDED_OFFSETOF)


def test_forced_fallback_without_offsetof_remains_supported():
    parser = CASTParser()
    with patch.object(parser, "_try_pcpp_preprocess", return_value=None):
        ctx = parser.parse("int f(void) { return 0; }")

    assert ctx.has_pycparser
    assert ctx.parse_tier == ParseTier.DIRECTIVE_STRIPPED.value


def test_offsetof_text_in_comments_and_strings_does_not_trigger_coverage_failure():
    parser = CASTParser()
    source = r'''
int f(void) {
    /* offsetof(Container, member) is documented here. */
    const char *text = "offsetof(Container, member)";
    return text != 0;
}
'''
    with patch.object(parser, "_try_pcpp_preprocess", return_value=None):
        ctx = parser.parse(source)

    assert ctx.has_pycparser
    assert ctx.parse_tier == ParseTier.DIRECTIVE_STRIPPED.value


def test_explicit_user_defined_offsetof_function_is_not_treated_as_macro_degradation():
    parser = CASTParser()
    source = """
#undef offsetof
int offsetof(int left, int right) { return left + right; }
int f(void) { return offsetof(1, 2); }
"""
    ctx = parser.parse(source)

    # The important contract is that an explicitly declared/defined function
    # named offsetof is not rejected as degraded macro coverage.  The parser may
    # legitimately choose a lower fallback tier for this unusual construct.
    assert {fn.name for fn in ctx.functions} >= {"offsetof", "f"}


def test_scan_text_surfaces_structured_coverage_diagnostic():
    scanner = CGullScanner(rules=[], engine_mode=AnalysisEngine.AST)
    with patch.object(scanner.ast_parser, "_try_pcpp_preprocess", return_value=None):
        result = scanner.scan_text(UNEXPANDED_OFFSETOF, file_path="offsetof.c", quiet=True)

    assert result.files_failed == 1
    assert len(result.scan_errors) == 1
    diagnostic = result.scan_errors[0]
    assert diagnostic.file_path == "offsetof.c"
    assert diagnostic.error_type == "CoverageDegradedError"
    assert "preprocessing/layout precision degraded" in diagnostic.message
    assert "offsetof" in diagnostic.message


def test_pcpp_path_does_not_leave_builtin_offsetof_unexpanded():
    pytest.importorskip("pcpp")
    pytest.importorskip("pycparser")

    parser = CASTParser()
    source = """
typedef struct Container {
    int member;
} Container;

int recover(void) {
    return (int)offsetof(Container, member);
}
"""
    ctx = parser.parse(source)

    assert ctx.parse_tier == ParseTier.PCPP_PYCPARSER.value


def test_explicitly_unexpanded_offsetof_is_deterministic_across_jobs(tmp_path):
    # Undefining the built-in expansion forces an actual offsetof FuncCall to
    # survive even when pcpp is installed, exercising the same central guard in
    # both the in-process and worker-process paths.
    source = """
#undef offsetof
int recover(void) {
    return offsetof(Container, member);
}
"""
    for name in ("a.c", "b.c"):
        (tmp_path / name).write_text(source, encoding="utf-8")

    sequential = CGullScanner(rules=[], engine_mode=AnalysisEngine.AST).scan_path(
        str(tmp_path), jobs=1, quiet=True
    )
    parallel = CGullScanner(rules=[], engine_mode=AnalysisEngine.AST).scan_path(
        str(tmp_path), jobs=2, quiet=True
    )

    def diagnostics(result):
        return sorted((e.file_path, e.error_type, e.message) for e in result.scan_errors)

    assert sequential.files_failed == parallel.files_failed == 2
    assert diagnostics(sequential) == diagnostics(parallel)
    assert all(error_type == "CoverageDegradedError" for _, error_type, _ in diagnostics(sequential))
