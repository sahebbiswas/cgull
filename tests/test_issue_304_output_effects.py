from cgull.ast_analyzer import CASTParser
from cgull.cfg.summaries import analyze_function_summaries
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules import get_rule_by_id


def _parse(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return ctx


def _scan(rule_id: str, code: str):
    rule = get_rule_by_id(rule_id)
    scanner = CGullScanner(rules=[rule], engine_mode=AnalysisEngine.HYBRID)
    return [issue for issue in scanner.scan_text(code, f"{rule_id}.c").issues if issue.rule_id == rule_id]


def test_output_parameter_summaries_distinguish_must_from_may_and_propagate_wrappers():
    summaries = analyze_function_summaries(_parse("""
        void initialize(int *out) { *out = 7; }
        void maybe_initialize(int *out, int cond) {
            if (cond) *out = 7;
        }
        void wrapper(int *out) { initialize(out); }
    """))

    assert summaries["initialize"].must_initialize_params == {0}
    assert summaries["initialize"].may_initialize_params == {0}
    assert summaries["maybe_initialize"].must_initialize_params == set()
    assert summaries["maybe_initialize"].may_initialize_params == {0}
    assert summaries["wrapper"].must_initialize_params == {0}
    assert summaries["wrapper"].may_initialize_params == {0}


def test_partial_aggregate_output_writes_are_may_only():
    summaries = analyze_function_summaries(_parse("""
        struct S { int written; int other; };
        void init_field(struct S *out) { out->written = 7; }
        void init_element(int *out) { out[0] = 7; }
    """))

    assert summaries["init_field"].must_initialize_params == set()
    assert summaries["init_field"].may_initialize_params == {0}
    assert summaries["init_element"].must_initialize_params == set()
    assert summaries["init_element"].may_initialize_params == {0}


def test_cgull_023_definite_helper_initialization_is_safe_but_conditional_is_not():
    safe = _scan("CGULL-023", """
        void initialize(int *out) { *out = 7; }
        int f(void) {
            int value;
            initialize(&value);
            return value;
        }
    """)
    unsafe = _scan("CGULL-023", """
        void initialize(int *out, int cond) { if (cond) *out = 7; }
        int f(int cond) {
            int value;
            initialize(&value, cond);
            return value;
        }
    """)

    assert safe == []
    assert len(unsafe) == 1


def test_cgull_021_definite_pointer_output_is_safe_but_conditional_is_not():
    safe = _scan("CGULL-021", """
        static char storage;
        void initialize(char **out) { *out = &storage; }
        char *f(void) {
            char *value;
            initialize(&value);
            return value;
        }
    """)
    unsafe = _scan("CGULL-021", """
        static char storage;
        void initialize(char **out, int cond) { if (cond) *out = &storage; }
        char *f(int cond) {
            char *value;
            initialize(&value, cond);
            return value;
        }
    """)

    assert safe == []
    assert len(unsafe) == 1


def test_cgull_003_wrapper_return_nullness_keeps_checked_and_unchecked_paths_distinct():
    prelude = """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void *make(void) { return malloc(8); }
    """
    safe = _scan("CGULL-003", prelude + """
        int f(void) {
            char *value = make();
            if (!value) return -1;
            return *value;
        }
    """)
    unsafe = _scan("CGULL-003", prelude + """
        int f(void) {
            char *value = make();
            return *value;
        }
    """)

    assert safe == []
    assert len(unsafe) == 1


def test_cgull_004_caller_nullness_query_keeps_guarded_and_unguarded_derefs_distinct():
    safe = _scan("CGULL-004", """
        int f(int *value) {
            if (!value) return -1;
            return *value;
        }
    """)
    unsafe = _scan("CGULL-004", """
        int f(int *value) { return *value; }
    """)

    assert safe == []
    assert len(unsafe) == 1
