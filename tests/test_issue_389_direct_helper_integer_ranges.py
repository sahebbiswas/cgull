"""Regression coverage for same-TU direct-helper integer ranges (#389)."""

from cgull.ast_analyzer import CASTParser
from cgull.cfg import IntegerRange, integer_range_summary_index
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


_PREAMBLE = """
typedef unsigned long size_t;
void *malloc(size_t size);
short read_short(void);
"""


def _parse(functions: str):
    ctx = CASTParser().parse(_PREAMBLE + functions)
    assert ctx.has_pycparser
    return ctx


def _scan(functions: str):
    ctx = _parse(functions)
    return IntegerNarrowingCastRule().scan_ast("issue_389.c", ctx)


def _cwes(functions: str):
    return [issue.cwe_id for issue in _scan(functions)]


def _scanner_cwes(scanner: CGullScanner, functions: str):
    result = scanner.scan_text(_PREAMBLE + functions, "issue_389_scanner.c")
    return [issue.cwe_id for issue in result.issues if issue.rule_id == "CGULL-049"]


def test_constant_argument_proves_private_helper_nonnegative():
    assert _cwes("""
static void sink(short n) { malloc(n); }
void safe(void) { sink(99); }
""") == []


def test_guarded_argument_proves_private_helper_nonnegative():
    assert _cwes("""
static void sink(short n) { malloc(n); }
void entry(short n) {
    if (n >= 0) {
        sink(n);
    }
}
""") == []


def test_mixed_safe_and_unsafe_callers_preserve_finding():
    assert _cwes("""
static void sink(short n) { malloc(n); }
void safe(void) { sink(99); }
void unsafe(short n) { sink(n); }
""") == ["CWE-194"]


def test_externally_callable_helper_cannot_use_local_callers_as_global_proof():
    assert _cwes("""
void sink(short n) { malloc(n); }
void safe(void) { sink(99); }
""") == ["CWE-194"]


def test_escaped_static_helper_cannot_use_direct_callers_as_global_proof():
    assert _cwes("""
static void sink(short n) { malloc(n); }
void (*sink_ptr)(short) = sink;
void safe(void) { sink(99); }
""") == ["CWE-194"]


def test_parameter_mutation_invalidates_entry_summary_before_sink():
    assert _cwes("""
static void sink(short n) {
    n = read_short();
    malloc(n);
}
void safe(void) { sink(99); }
""") == ["CWE-194"]


def test_direct_return_summary_suppresses_proven_safe_conversion():
    assert _cwes("""
static short safe_size(void) { return 99; }
void safe(void) { malloc(safe_size()); }
""") == []


def test_return_summary_flows_through_simple_local_assignment():
    assert _cwes("""
static short safe_size(void) { return 99; }
void safe(void) {
    short n = safe_size();
    malloc(n);
}
""") == []


def test_unsafe_return_summary_preserves_finding():
    assert _cwes("""
static short identity(short n) { return n; }
void unsafe(short n) { malloc(identity(n)); }
""") == ["CWE-194"]


def test_return_assignment_mutation_does_not_leave_stale_fact():
    assert _cwes("""
static short safe_size(void) { return 99; }
void unsafe(void) {
    short n = safe_size();
    n = read_short();
    malloc(n);
}
""") == ["CWE-194"]


def test_recursive_helpers_fall_back_conservatively():
    assert _cwes("""
static short countdown(short n) {
    if (n <= 0) return n;
    return countdown(n - 1);
}
void safe(void) { malloc(countdown(99)); }
""") == ["CWE-194"]


def test_fixed_point_propagates_through_helper_chain():
    ctx = _parse("""
static short identity(short n) { return n; }
static void sink(short n) { malloc(n); }
void safe(void) { sink(identity(99)); }
""")
    summaries = integer_range_summary_index(ctx)
    assert summaries.converged
    assert summaries.parameter_ranges["identity"]["n"] == IntegerRange(99, 99)
    assert summaries.return_ranges["identity"] == IntegerRange(99, 99)
    assert summaries.parameter_ranges["sink"]["n"] == IntegerRange(99, 99)
    assert IntegerNarrowingCastRule().scan_ast("issue_389.c", ctx) == []


def test_summary_cache_is_scoped_to_ast_context():
    safe_ctx = _parse("""
static void sink(short n) { malloc(n); }
void safe(void) { sink(99); }
""")
    unsafe_ctx = _parse("""
static void sink(short n) { malloc(n); }
void unsafe(short n) { sink(n); }
""")

    safe_summary = integer_range_summary_index(safe_ctx)
    unsafe_summary = integer_range_summary_index(unsafe_ctx)
    assert safe_summary.parameter_ranges["sink"]["n"] == IntegerRange(99, 99)
    assert unsafe_summary.parameter_ranges["sink"]["n"].lower < 0
    assert safe_summary is integer_range_summary_index(safe_ctx)
    assert unsafe_summary is integer_range_summary_index(unsafe_ctx)


def test_scanner_reuses_no_range_summary_across_scan_contexts():
    scanner = CGullScanner(engine_mode=AnalysisEngine.AST)
    safe = _scanner_cwes(scanner, """
static void sink(short n) { malloc(n); }
void safe(void) { sink(99); }
""")
    unsafe = _scanner_cwes(scanner, """
static void sink(short n) { malloc(n); }
void unsafe(short n) { sink(n); }
""")
    assert safe == []
    assert unsafe == ["CWE-194"]


def test_pinned_juliet_flow_41_external_sink_stays_conservative():
    # Juliet 1.3 flow 41 declares goodG2BSink with external linkage. The
    # positive local call therefore cannot prove the sink parameter globally.
    assert _cwes("""
void CWE194_Unexpected_Sign_Extension__connect_socket_malloc_41_goodG2BSink(short data) {
    if (data < 100) malloc(data);
}
static void goodG2B(void) {
    short data = 0;
    data = 100 - 1;
    CWE194_Unexpected_Sign_Extension__connect_socket_malloc_41_goodG2BSink(data);
}
void CWE194_Unexpected_Sign_Extension__connect_socket_malloc_41_good(void) { goodG2B(); }
""") == ["CWE-194"]


def test_pinned_juliet_flow_42_static_return_source_is_proven_safe():
    # Juliet 1.3 flow 42 returns the good source from a static same-TU helper.
    assert _cwes("""
static short goodG2BSource(short data) {
    data = 100 - 1;
    return data;
}
static void goodG2B(void) {
    short data = 0;
    data = goodG2BSource(data);
    if (data < 100) malloc(data);
}
void CWE194_Unexpected_Sign_Extension__connect_socket_malloc_42_good(void) { goodG2B(); }
""") == []


def test_pinned_juliet_flow_42_unsafe_return_source_retains_cwe_194():
    assert _cwes("""
static short badSource(short data) {
    data = read_short();
    return data;
}
void CWE194_Unexpected_Sign_Extension__connect_socket_malloc_42_bad(void) {
    short data = 0;
    data = badSource(data);
    if (data < 100) malloc(data);
}
""") == ["CWE-194"]
