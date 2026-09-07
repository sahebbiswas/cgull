from benchmarks.security_fact_support import build_security_context
from cgull.analysis_session import AnalysisSession
from cgull.cfg.pointer_ranges import (
    OffsetInterval,
    PointerProvenance,
    PointerRangeFact,
    analyze_translation_unit_pointer_ranges,
    join_pointer_facts,
)


def test_alias_preserves_origin_offset_and_accessible_range():
    ctx = build_security_context(
        r'''
        void caller(void) {
            char a[32];
            char *p = a;
            char *q = p;
        }
        '''
    )
    result = analyze_translation_unit_pointer_ranges(ctx)
    q = result.query("caller", "q")

    assert q.origin == "a"
    assert q.offset == OffsetInterval.exact(0)
    assert q.lower_bound == 0
    assert q.upper_bound == 32
    assert q.provenance is PointerProvenance.LOCAL_OBJECT


def test_positive_constant_offset_reduces_forward_capacity():
    ctx = build_security_context(
        r'''
        void caller(void) {
            char a[32];
            char *p = a;
            char *q = p + 4;
        }
        '''
    )
    q = analyze_translation_unit_pointer_ranges(ctx).query("caller", "q")

    assert q.origin == "a"
    assert q.offset == OffsetInterval.exact(4)
    assert q.lower_bound == 4
    assert q.upper_bound == 28


def test_backward_offset_does_not_invent_preceding_capacity():
    ctx = build_security_context(
        r'''
        void caller(void) {
            char a[32];
            char *p = a;
            char *q = p - 4;
        }
        '''
    )
    q = analyze_translation_unit_pointer_ranges(ctx).query("caller", "q")

    assert q.origin == "a"
    assert q.offset == OffsetInterval.exact(-4)
    assert q.lower_bound is None
    assert q.upper_bound is None
    assert "OUTSIDE_PROVEN_RANGE" in q.degradations


def test_identity_cast_preserves_fact():
    ctx = build_security_context(
        r'''
        void caller(void) {
            char a[16];
            char *p = (char *)a;
        }
        '''
    )
    p = analyze_translation_unit_pointer_ranges(ctx).query("caller", "p")
    assert p.origin == "a"
    assert p.upper_bound == 16


def test_reassignment_invalidates_stale_proof():
    ctx = build_security_context(
        r'''
        char *opaque(void);
        void caller(void) {
            char a[16];
            char *p = a;
            p = opaque();
        }
        '''
    )
    p = analyze_translation_unit_pointer_ranges(ctx).query("caller", "p")
    assert p.origin is None
    assert not p.has_accessible_range


def test_conflicting_branch_origins_join_to_unknown():
    ctx = build_security_context(
        r'''
        void caller(int flag) {
            char a[8];
            char b[8];
            char *p = a;
            if (flag) p = a; else p = b;
            (void)p;
        }
        '''
    )
    p = analyze_translation_unit_pointer_ranges(ctx).query("caller", "p")
    assert p.origin is None
    assert not p.has_accessible_range


def test_loop_converges_conservatively():
    ctx = build_security_context(
        r'''
        void caller(int n) {
            char a[8];
            char *p = a;
            while (n--) {
                p += 1;
            }
            (void)p;
        }
        '''
    )
    p = analyze_translation_unit_pointer_ranges(ctx).query("caller", "p")
    assert p.origin == "a"
    assert p.offset.lower == 0
    assert p.offset.upper is not None
    assert p.upper_bound is not None


def test_unknown_offset_keeps_origin_but_drops_safety_proof():
    ctx = build_security_context(
        r'''
        void caller(int n) {
            char a[32];
            char *p = a;
            char *q = p + n;
        }
        '''
    )
    q = analyze_translation_unit_pointer_ranges(ctx).query("caller", "q")
    assert q.origin == "a"
    assert q.offset.is_unknown
    assert not q.has_accessible_range
    assert "UNSUPPORTED_ARITHMETIC" in q.degradations


def test_size_analysis_seeds_formal_pointer_extent():
    ctx = build_security_context(
        r'''
        void consume(char *p) { (void)p; }
        void caller(void) {
            char a[24];
            consume(a);
        }
        '''
    )
    session = AnalysisSession(ctx)
    fact = session.queries.pointer_range("consume", "p")

    assert fact.origin == "p"
    assert fact.upper_bound == 24


def test_session_query_is_cached_and_rule_neutral():
    ctx = build_security_context(
        r'''
        void caller(void) {
            char a[4];
            char *p = a;
        }
        '''
    )
    session = AnalysisSession(ctx)
    first = session.pointer_range_analysis
    second = session.pointer_range_analysis

    assert first is second
    assert session.queries.pointer_range("caller", "p").upper_bound == 4


def test_join_intersects_accessible_capacity():
    left = PointerRangeFact.object("a", 16).shifted(4)
    right = PointerRangeFact.object("a", 16).shifted(8)
    joined = join_pointer_facts(left, right)

    assert joined.origin == "a"
    assert joined.offset == OffsetInterval(4, 8)
    assert joined.lower_bound == 4
    assert joined.upper_bound == 8
