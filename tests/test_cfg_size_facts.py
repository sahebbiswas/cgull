from benchmarks.security_fact_support import build_security_context
from cgull.cfg.size_facts import (
    SizeFact,
    SizeSafety,
    analyze_translation_unit_size_dataflow,
    join_size_facts,
)


def _safety(result, callee):
    return [call.classify(buffer_arg=0, size_arg=1) for call in result.calls_to(callee)]


def test_known_array_capacity_survives_two_wrapper_calls():
    ctx = build_security_context(
        r'''
        void sink(char *, unsigned);
        void level2(char *dst, unsigned n) { sink(dst, n); }
        void level1(char *dst, unsigned n) { level2(dst, n); }
        void caller(void) {
            char buf[32];
            level1(buf, 16);
        }
        '''
    )
    result = analyze_translation_unit_size_dataflow(ctx)

    assert result.parameter_extents["level1"][0] == SizeFact.exact(32)
    assert result.parameter_extents["level2"][0] == SizeFact.exact(32)
    assert _safety(result, "sink") == [SizeSafety.SAFE]


def test_safe_and_unsafe_constant_sizes_are_distinguished():
    safe = build_security_context(
        r'''
        void sink(char *, unsigned);
        void caller(void) { char buf[16]; sink(buf, 16); }
        '''
    )
    unsafe = build_security_context(
        r'''
        void sink(char *, unsigned);
        void caller(void) { char buf[16]; sink(buf, 17); }
        '''
    )

    assert _safety(analyze_translation_unit_size_dataflow(safe), "sink") == [SizeSafety.SAFE]
    assert _safety(analyze_translation_unit_size_dataflow(unsafe), "sink") == [SizeSafety.UNSAFE]


def test_single_element_non_char_array_uses_element_width():
    ctx = build_security_context(
        r'''
        void sink(int *, unsigned);
        void caller(void) {
            int buf[1];
            sink(buf, 4);
        }
        '''
    )
    result = analyze_translation_unit_size_dataflow(ctx)

    call = result.calls_to("sink")[0]
    assert call.extents[0] == SizeFact.exact(4)
    assert call.classify(buffer_arg=0, size_arg=1) is SizeSafety.SAFE


def test_guard_refines_only_guarded_path():
    ctx = build_security_context(
        r'''
        void sink(char *, unsigned);
        void wrapper(char *dst, unsigned n) {
            if (n <= 32) {
                sink(dst, n);
            }
            sink(dst, n);
        }
        void caller(unsigned n) {
            char buf[32];
            wrapper(buf, n);
        }
        '''
    )
    result = analyze_translation_unit_size_dataflow(ctx)

    assert _safety(result, "sink") == [SizeSafety.SAFE, SizeSafety.UNKNOWN]


def test_unknown_arithmetic_never_proves_safety():
    ctx = build_security_context(
        r'''
        void sink(char *, unsigned);
        void caller(void) {
            char buf[32];
            unsigned n = 16;
            sink(buf, n + 1);
        }
        '''
    )
    result = analyze_translation_unit_size_dataflow(ctx)

    call = result.calls_to("sink")[0]
    assert call.sizes[1].is_unknown
    assert "UNSUPPORTED_ARITHMETIC" in call.sizes[1].degradations
    assert call.classify(buffer_arg=0, size_arg=1) is SizeSafety.UNKNOWN


def test_named_struct_member_extent_is_field_sensitive():
    ctx = build_security_context(
        r'''
        struct packet { char header[8]; char payload[24]; };
        void sink(char *, unsigned);
        void caller(void) {
            struct packet p;
            sink(p.payload, 24);
        }
        '''
    )
    result = analyze_translation_unit_size_dataflow(ctx)

    assert result.calls_to("sink")[0].extents[0] == SizeFact.exact(24)
    assert _safety(result, "sink") == [SizeSafety.SAFE]


def test_for_init_and_update_calls_are_recorded():
    ctx = build_security_context(
        r'''
        void sink(char *, unsigned);
        int ready(void);
        void caller(void) {
            char buf[8];
            for (sink(buf, 8); ready(); sink(buf, 9)) {
                break;
            }
        }
        '''
    )
    result = analyze_translation_unit_size_dataflow(ctx)

    assert _safety(result, "sink") == [SizeSafety.SAFE, SizeSafety.UNSAFE]


def test_for_initializer_declaration_updates_size_state():
    ctx = build_security_context(
        r'''
        void sink(char *, unsigned);
        void caller(void) {
            char buf[8];
            for (unsigned n = 8; n; n = 0) {
                sink(buf, n);
                break;
            }
        }
        '''
    )
    result = analyze_translation_unit_size_dataflow(ctx)

    assert _safety(result, "sink") == [SizeSafety.SAFE]


def test_conflicting_callers_join_to_conservative_bounds():
    ctx = build_security_context(
        r'''
        void consume(char *dst) { (void)dst; }
        void small(void) { char a[16]; consume(a); }
        void large(void) { char b[32]; consume(b); }
        '''
    )
    result = analyze_translation_unit_size_dataflow(ctx)

    fact = result.parameter_extents["consume"][0]
    assert fact.lower == 16
    assert fact.upper == 32
    assert not fact.is_exact


def test_recursive_propagation_converges_without_losing_extent():
    ctx = build_security_context(
        r'''
        void sink(char *, unsigned);
        void b(char *);
        void a(char *p) { b(p); }
        void b(char *p) {
            if (p) a(p);
            sink(p, 16);
        }
        void caller(void) {
            char buf[16];
            a(buf);
        }
        '''
    )
    result = analyze_translation_unit_size_dataflow(ctx)

    assert result.parameter_extents["a"][0] == SizeFact.exact(16)
    assert result.parameter_extents["b"][0] == SizeFact.exact(16)
    assert _safety(result, "sink") == [SizeSafety.SAFE]
    assert not result.diagnostics


def test_join_preserves_parameter_relation_only_when_callers_agree():
    assert join_size_facts(SizeFact.parameter(0), SizeFact.parameter(0)).parameter_index == 0
    assert join_size_facts(SizeFact.parameter(0), SizeFact.parameter(1)).is_unknown
