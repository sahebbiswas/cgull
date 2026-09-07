"""Enclosing-range proofs must hold on every path reaching the access."""
import pytest

from cgull.ast_analyzer import CASTParser
from cgull.analysis_session import analysis_session_for
from cgull.rules.types_and_arrays import ValidatedPointerRangeRule
from cgull.semantic_models import parse_semantic_models


def analyze(body, params='char *p, char *base, char *end, int flag', validate=True):
    ctx = CASTParser().parse('int valid(void *, unsigned long);\nvoid f(' + params + ') {\n' +
                            ('if (!valid(p, 8)) return;\n' if validate else '') + body + '\n}')
    assert ctx.has_pycparser
    models = parse_semantic_models({'validators': [{
        'function': 'valid', 'target': 'arg:0', 'length': 'arg:1',
        'property': 'bounds_checked', 'success': 'return_nonzero',
    }]})
    session = analysis_session_for(ctx, semantic_models=models)
    return ValidatedPointerRangeRule().scan_ast('test.c', ctx), session.pointer_range_analysis.function('f')


@pytest.mark.parametrize('condition', [
    'p >= base + 4', 'base + 4 <= p', 'p - base >= 4', '4 <= p - base',
    'p > base + 3', 'base + 3 < p', 'p - base > 3', '3 < p - base',
    'p >= 4 + base', 'p >= base + 4u', 'p >= base + sizeof(int)',
])
def test_lower_spellings_and_early_return(condition):
    issues, result = analyze('if (!(' + condition + ')) return; int x=*(int *)(p-4);')
    assert not issues
    assert result.query('p').backward_accessible_extent == 4
    assert analyze('if (' + condition + ') { int x=*(int *)(p-4); }')[0] == []


@pytest.mark.parametrize('condition', [
    'p + 12 <= end', 'end >= p + 12', 'end - p >= 12', '12 <= end - p',
    'p + 11 < end', 'end > p + 11', 'end - p > 11', '11 < end - p',
])
def test_upper_spellings(condition):
    issues, result = analyze('if (!(' + condition + ')) return; int x=*(int *)(p+8);')
    assert not issues
    assert result.query('p').forward_accessible_extent == 12
    assert analyze('if (!(' + condition + ')) return; int x=p[-1];')[0]
    assert analyze('if (!(' + condition + ')) return; int x=p[12];')[0]


@pytest.mark.parametrize('body,bad', [
    ('if(p < base+4 || p+12 > end) return; int x=p[-4]+p[11];', False),
    ('if(p >= base+4 && p+12 <= end) { int x=p[-4]+p[11]; }', False),
    ('if(p >= base+4 || p+12 <= end) { int x=p[-4]; }', True),
    ('if(p < base+4) return; int x=p[8];', True),
    ('if(flag) { if(p < base+4) return; } int x=p[-4];', True),
    ('if(flag) { if(p < base+4) return; } else { if(p-base < 4) return; } int x=p[-4];', False),
    ('if(p >= base+4) { if(flag) { int x=p[-4]; } }', False),
    ('if(p >= base+4) {} int x=p[-4];', True),
    ('if(p < base+4) { int x=p[-4]; }', True),
    ('if(p < base+4) return; char *q=p-4; int x=*(int *)q;', False),
    ('char *q=p; if(p < base+4) return; int x=q[-4];', False),
    ('if(p < base+3) return; int x=p[-4];', True),
])
def test_paths_and_independent_sides(body, bad):
    assert bool(analyze(body)[0]) == bad


@pytest.mark.parametrize('mutation', ['p++', 'p+=1', 'p=base', 'base++', 'base=end', 'end--', 'n++', 'n=9'])
def test_mutation_invalidates_alias_proof(mutation):
    body = ('int n=4; char *q=p; if(p < base+n || p+12 > end) return; ' +
            mutation + '; int x=q[-4]+q[11];')
    assert analyze(body)[0]


@pytest.mark.parametrize('mutation', ['base++', 'end--', 'n++', 'p++'])
def test_loop_carried_mutation(mutation):
    assert analyze('int n=4; char *q=p; if(p < base+n || p+12 > end) return; '
                   'while(flag) { ' + mutation + '; } int x=q[-4]+q[11];')[0]


@pytest.mark.parametrize('condition', [
    'p >= base + flag', 'p >= base + flag*4', 'p-base >= 4u',
    '(unsigned long)(p-base) >= 4', 'p >= base-4',
    '(unsigned long)p >= (unsigned long)base+4',
])
def test_unsupported_does_not_prove_safety(condition):
    assert analyze('if(!(' + condition + ')) return; int x=p[-4];')[0]


def test_named_constant_and_type_conversion():
    assert not analyze('unsigned int n=4; if(p < base+n) return; int x=p[-4];')[0]
    assert not analyze('int n=4; if(p-base < n) return; int x=p[-4];')[0]
    assert analyze('unsigned int n=4; if(p-base < n) return; int x=p[-4];')[0]
    assert analyze('unsigned short n=65540; if(p < base+n) return; int x=p[-4];')[0]


@pytest.mark.parametrize('condition,backward,forward', [
    ('p >= base', 0, 0), ('p > base', 1, 0),
    ('p <= end', 0, 0), ('p < end', 0, 1),
])
def test_unadorned_bounds(condition, backward, forward):
    _, result = analyze('if(!(' + condition + ')) return;', validate=False)
    assert result.query('p').backward_accessible_extent == backward
    assert result.query('p').forward_accessible_extent == forward


def test_no_validator_needed_and_stride():
    assert not analyze('if(p < base+4) return; int x=p[-4];', validate=False)[0]
    assert analyze('if(p+8 > end) return; int x=p[-4];', validate=False)[0]
    assert not analyze('if(p < base+4) return; int x=p[-4];',
                       params='int *p, int *base, int *end, int flag')[0]
    assert analyze('if(p < base+4) return; int x=p[-4];',
                   params='int *p, char *base, char *end, int flag')[0]


def test_registry_free_shared_facts():
    ctx = CASTParser().parse('void f(char *p, char *base) { if(p < base+4) return; char *q=p-4; }')
    result = analysis_session_for(ctx).pointer_range_analysis.function('f')
    assert result.query('q').forward_accessible_extent == 4


@pytest.mark.parametrize('loop,changed', [
    ('for(;flag; base++) {}', 'base'), ('while(n--) {}', 'n'),
    ('do { end--; } while(flag);', 'end'),
])
def test_loop_header_and_do_while_queries_discard_proofs(loop, changed):
    _, result = analyze('int n=4; char *q=p; if(p < base+n || p+12 > end) return; ' + loop)
    assert all(changed not in proof.dependencies for proof in result.query('q').guarded_intervals)


@pytest.mark.parametrize('size', ['+4u', '-(-4u)', 'sizeof(int)'])
def test_unsigned_distance_wrappers_do_not_prove_lower_bound(size):
    assert analyze('if(p-base < ' + size + ') return; int x=p[-4];')[0]


def test_volatile_size_does_not_establish_constant_proof():
    assert analyze('volatile int n=4; if(p < base+n) return; int x=p[-4];')[0]


def test_merge_retains_dependencies_from_both_paths():
    prefix = 'if(flag) { if(p < base+4) return; } else { if(p < end+4) return; } '
    assert not analyze(prefix + 'int x=p[-4];')[0]
    assert analyze(prefix + 'end++; int x=p[-4];')[0]
    assert analyze(prefix + 'base++; int x=p[-4];')[0]


def test_unrelated_mutation_preserves_proof_and_revalidation_restores_it():
    assert not analyze('if(p < base+4) return; flag++; int x=p[-4];')[0]
    assert not analyze('if(p < base+4) return; base++; if(p < base+4) return; int x=p[-4];')[0]
