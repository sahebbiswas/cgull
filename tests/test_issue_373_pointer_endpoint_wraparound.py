"""Endpoint arithmetic must be safe before it participates in a range proof."""
import pytest
from cgull.ast_analyzer import CASTParser
from cgull.analysis_session import analysis_session_for
from cgull.rules.types_and_arrays import PointerEndpointWraparoundRule


def analyze(body, params='char *p, char *base, char *end, unsigned long len, int flag'):
    ctx = CASTParser().parse('typedef unsigned long UINTN;\nint f(' + params + ') {\n' + body + '\n}')
    assert ctx.has_pycparser
    issues = PointerEndpointWraparoundRule().scan_ast('test.c', ctx)
    return issues, analysis_session_for(ctx).pointer_range_analysis.function('f')


@pytest.mark.parametrize('condition', [
    'p + len <= end', 'end >= p + len', 'p + len > end',
    'base <= p - len', 'p - len >= base', 'p + 4 <= end',
    'p >= base + 4', 'p >= 4 + base', 'p + sizeof(int) < end',
    'len <= (unsigned long)(end - p)', '(unsigned long)(end - p) >= len',
])
def test_unsafe_comparisons(condition):
    issues, result = analyze('if (' + condition + ') return 1; return 0;')
    assert issues and all(i.rule_id == 'CGULL-052' for i in issues)
    assert not result.query('p').guarded_intervals


@pytest.mark.parametrize('body', [
    'if (p > end) return 0; return len <= (unsigned long)(end-p);',
    'return p <= end && len <= (unsigned long)(end-p);',
    'if (p > end || len > (unsigned long)(end-p)) return 0; return p+len <= end;',
    'if (p > end) return 0; if (len > (unsigned long)(end-p)) return 0; return p+len <= end;',
    'if (base > p) return 0; if (len > (unsigned long)(p-base)) return 0; return base <= p-len;',
    'char a[16]; return a+4 <= a;',
    'char a[16]; char *q=a+8; return a <= q-4;',
    'char a[16]; if (len > 16) return 0; return a+len <= a;',
    'return p+0 <= end;',
    'return len+1 <= 8;',  # ordinary integer arithmetic is another rule's job
    'char *q=p+len; return 1;',  # no range comparison
])
def test_independent_evidence_and_non_checks(body):
    assert not analyze(body)[0]


@pytest.mark.parametrize('body', [
    'return len <= (unsigned long)(end-p) && p <= end;',
    'return p <= end || len <= (unsigned long)(end-p);',
    'if(flag) { if(p>end) return 0; } return len <= (unsigned long)(end-p);',
    'if(p>end) return 0; p=base; return len <= (unsigned long)(end-p);',
    'if(p>end) return 0; if(len>(unsigned long)(end-p)) return 0; len++; return p+len <= end;',
    'char a[16]; if(len>16) return 0; len=100; return a+len <= end;',
    'char a[16]; return a+17 <= end;',
    'char a[16]; return a-1 >= base;',
    'return p+external_length() <= end;',
])
def test_missing_or_invalidated_evidence(body):
    assert analyze(body)[0]


@pytest.mark.parametrize('typ', ['uintptr_t', 'UINTN'])
def test_integer_address_temporary(typ):
    assert analyze(f'{typ} endpoint=({typ})p+len; return endpoint <= ({typ})end;')[0]
    assert analyze(f'return ({typ})p-len >= ({typ})base;')[0]
    assert not analyze(f'{typ} endpoint=({typ})p+len; endpoint=0; return endpoint <= 10;')[0]


def test_rejected_endpoint_does_not_prove_bounds_on_success_edge():
    issues, result = analyze('if(p+12 > end) return 0; return p[11];')
    assert issues
    assert result.query('p').forward_accessible_extent is None


def test_local_constant_safe_endpoint_can_refine_guard():
    issues, result = analyze('char a[16]; char *q=a; if(q+4>end) return 0; return 1;')
    assert not issues
    assert result.query('q').guarded_intervals


@pytest.mark.parametrize('typ', ['uintptr_t', 'UINTN'])
def test_integer_address_parameter_distance_guards(typ):
    params = f'{typ} p, {typ} end, unsigned long len'
    assert analyze('return p+len <= end;', params)[0]
    assert not analyze('if(p>end) return 0; if(len>end-p) return 0; return p+len<=end;', params)[0]
    assert analyze('return len<=end-p;', params)[0]


def test_bounded_integer_address_arithmetic():
    assert not analyze('UINTN p=100; return p+4<=200;', '')[0]
    assert not analyze('UINTN p=100; return p-4>=0;', '')[0]
    assert analyze('UINTN p=2; return p-4>=0;', '')[0]


def test_pointer_endpoint_alias_cannot_launder_unsafe_arithmetic():
    issues, result = analyze('char *q=p+4; if(q>end) return 0; return q[0];')
    assert issues
    assert not result.query('q').guarded_intervals


def test_safe_pointer_endpoint_alias():
    assert not analyze('char a[16]; char *q=a+4; return q<=end;')[0]


def test_alias_retains_unsafe_history_after_original_changes():
    assert analyze('UINTN q=(UINTN)p+len; len=0; return q <= (UINTN)end;')[0]


def test_alias_join_preserves_possible_unsafe_endpoint():
    assert analyze('UINTN q=0; if(flag) q=(UINTN)p+len; return q<100;')[0]


def test_nested_endpoint_arithmetic():
    assert analyze('return (p+0)+len<=end;')[0]
    assert analyze('char a[16]; return (a+8)+12<=end;')[0]


def test_signed_size_needs_nonnegative_bound():
    params = 'int len, char *end'
    assert analyze('char a[16]; if(len>16) return 0; return a+len<=end;', params)[0]
    assert not analyze('char a[16]; if(len<0 || len>16) return 0; return a+len<=end;', params)[0]



def test_bounded_symbolic_integer_address():
    assert not analyze('if(p>100 || len>4) return 0; return p+len<=end;',
                       'UINTN p, UINTN end, unsigned long len')[0]


def test_signed_narrowed_distance_does_not_prove_safe_endpoint():
    assert analyze('if(p>end) return 0; if(len>(signed char)(end-p)) return 0; return p+len<=end;')[0]


def test_unrelated_comparison_does_not_diagnose_call_argument():
    assert not analyze('return read_value(p+len)>0;')[0]


@pytest.mark.parametrize('typ', ['UINTN', 'uintptr_t'])
def test_compound_address_endpoint(typ):
    assert analyze(f'{typ} q=({typ})p; q+=len; return q<=({typ})end;')[0]


def test_compound_pointer_endpoint():
    assert analyze('char *q=p; q+=4; return q<=end;')[0]


@pytest.mark.parametrize('condition', [
    'p>=base+4', 'base+4<=p', 'p>base+3', 'base+3<p',
    'p>=4+base', 'p>=base+4u', 'p>=base+sizeof(int)',
])
def test_safe_constant_lower_endpoint_spellings(condition):
    issues, result = analyze('char storage[16]; base=storage; if(!(' + condition + ')) return 0; return 1;')
    assert not issues
    assert result.query('p').backward_accessible_extent == 4


def test_validator_capacity_is_independent_endpoint_evidence():
    from cgull.semantic_models import parse_semantic_models
    ctx = CASTParser().parse('int valid(void *, unsigned long); '
                            'int f(char *p, char *end) { if(!valid(p,16)) return 0; return p+12<=end; }')
    models = parse_semantic_models({'validators': [{
        'function': 'valid', 'target': 'arg:0', 'length': 'arg:1',
        'property': 'bounds_checked', 'success': 'return_nonzero',
    }]})
    analysis_session_for(ctx, semantic_models=models)
    assert not PointerEndpointWraparoundRule().scan_ast('test.c', ctx)



def test_unsigned_comparison_cannot_prove_signed_size_nonnegative():
    assert analyze('char a[16]; if(len<0u || len>16) return 0; return a+len<=end;',
                   'int len, char *end')[0]


def test_volatile_length_does_not_reuse_numeric_guard():
    assert analyze('char a[16]; if(len>16) return 0; return a+len<=end;',
                   'volatile unsigned long len, char *end')[0]


def test_volatile_pointer_does_not_reuse_ordering():
    assert analyze('if(p>end) return 0; return len<=(unsigned long)(end-p);',
                   'char *volatile p, char *end, unsigned long len')[0]



def test_commuted_pointer_alias_keeps_endpoint_hazard():
    issues, result = analyze('char *q=4+p; if(q>end) return 0; return q[0];')
    assert issues
    assert not result.query('q').guarded_intervals
