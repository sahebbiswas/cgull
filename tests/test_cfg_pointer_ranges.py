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
    assert q.element_width == 1
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
    assert p.element_width == 1


def test_non_char_pointer_alias_preserves_element_stride():
    ctx = build_security_context(
        r'''
        void caller(void) {
            int a[8];
            int *p = a;
            int *q = p + 4;
        }
        '''
    )
    q = analyze_translation_unit_pointer_ranges(ctx).query("caller", "q")

    assert q.origin == "a"
    assert q.element_width == 4
    assert q.offset == OffsetInterval.exact(16)
    assert q.lower_bound == 16
    assert q.upper_bound == 16


def test_compound_pointer_arithmetic_uses_element_stride():
    ctx = build_security_context(
        r'''
        void caller(void) {
            int a[8];
            int *p = a;
            p += 2;
        }
        '''
    )
    p = analyze_translation_unit_pointer_ranges(ctx).query("caller", "p")

    assert p.element_width == 4
    assert p.offset == OffsetInterval.exact(8)
    assert p.lower_bound == 8
    assert p.upper_bound == 24


def test_integer_literal_suffixes_preserve_constant_pointer_offsets():
    ctx = build_security_context(
        r'''
        void caller(void) {
            int a[16];
            int *p = a;
            int *q = p + 2UL;
            q += 1LL;
        }
        '''
    )
    q = analyze_translation_unit_pointer_ranges(ctx).query("caller", "q")

    assert q.element_width == 4
    assert q.offset == OffsetInterval.exact(12)
    assert q.lower_bound == 12
    assert q.upper_bound == 52
    assert "UNSUPPORTED_ARITHMETIC" not in q.degradations


def test_commutative_constant_plus_pointer_preserves_range():
    ctx = build_security_context(
        r'''
        void caller(void) {
            int a[8];
            int *p = a;
            int *q = 2 + p;
        }
        '''
    )
    q = analyze_translation_unit_pointer_ranges(ctx).query("caller", "q")

    assert q.origin == "a"
    assert q.element_width == 4
    assert q.offset == OffsetInterval.exact(8)
    assert q.lower_bound == 8
    assert q.upper_bound == 24


def test_pointer_increment_updates_stride():
    ctx = build_security_context(
        r'''
        void caller(void) {
            int a[8];
            int *p = a;
            p++;
        }
        '''
    )
    p = analyze_translation_unit_pointer_ranges(ctx).query("caller", "p")

    assert p.offset == OffsetInterval.exact(4)
    assert p.lower_bound == 4
    assert p.upper_bound == 28


def test_for_pointer_increment_widens_non_converged_range():
    ctx = build_security_context(
        r'''
        void caller(int n) {
            int a[32];
            int *p = a;
            for (int i = 0; i < n; ++i) {
                (void)p;
                p++;
            }
        }
        '''
    )
    p = analyze_translation_unit_pointer_ranges(ctx).query("caller", "p")

    assert p.origin == "a"
    assert p.offset.is_unknown
    assert not p.has_accessible_range
    assert "LOOP_NOT_CONVERGED" in p.degradations


def test_multidimensional_array_tracks_total_extent_and_row_stride():
    ctx = build_security_context(
        r'''
        void caller(void) {
            int a[3][5];
            int (*p)[5] = a;
            int (*q)[5] = p + 1;
        }
        '''
    )
    result = analyze_translation_unit_pointer_ranges(ctx)
    p = result.query("caller", "p")
    q = result.query("caller", "q")

    assert p.upper_bound == 60
    assert p.element_width == 20
    assert q.offset == OffsetInterval.exact(20)
    assert q.lower_bound == 20
    assert q.upper_bound == 40


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


def test_non_converged_loop_widens_advancing_pointer_to_unknown():
    ctx = build_security_context(
        r'''
        void caller(int n) {
            char a[32];
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
    assert p.offset.is_unknown
    assert not p.has_accessible_range
    assert "LOOP_NOT_CONVERGED" in p.degradations


def test_loop_widening_keeps_unmodified_pointer_precise():
    ctx = build_security_context(
        r'''
        void caller(int n) {
            char a[32];
            char b[8];
            char *p = a;
            char *stable = b;
            while (n--) {
                p += 1;
            }
            (void)p;
            (void)stable;
        }
        '''
    )
    result = analyze_translation_unit_pointer_ranges(ctx)
    stable = result.query("caller", "stable")

    assert stable.origin == "b"
    assert stable.offset == OffsetInterval.exact(0)
    assert stable.upper_bound == 8
    assert "LOOP_NOT_CONVERGED" not in stable.degradations


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


def test_size_analysis_seeds_formal_pointer_extent_and_stride():
    ctx = build_security_context(
        r'''
        void consume(int *p) { (void)p; }
        void caller(void) {
            int a[6];
            consume(a);
        }
        '''
    )
    session = AnalysisSession(ctx)
    fact = session.queries.pointer_range("consume", "p")

    assert fact.origin == "p"
    assert fact.upper_bound == 24
    assert fact.element_width == 4


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


def test_join_intersects_accessible_capacity_and_preserves_stride():
    left = PointerRangeFact.object("a", 32, element_width=4).shifted(4)
    right = PointerRangeFact.object("a", 32, element_width=4).shifted(8)
    joined = join_pointer_facts(left, right)

    assert joined.origin == "a"
    assert joined.offset == OffsetInterval(4, 8)
    assert joined.lower_bound == 4
    assert joined.upper_bound == 24
    assert joined.element_width == 4
