import pytest

from cgull.analysis_session import analysis_session_for
from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import PointerProvenanceRule, PointerRangeBoundsRule


def analyze(source):
    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    result = analysis_session_for(ctx).pointer_range_analysis
    return result, PointerProvenanceRule().scan_ast('test.c', ctx)


@pytest.mark.parametrize('operation,offset', [('', 0), ('u += 4;', 4), ('u = u + 4;', 4), ('u++;', 1)])
def test_address_roundtrip(operation, offset):
    result, issues = analyze('void f(void) { char a[16]; uintptr_t u=(uintptr_t)a; ' + operation + ' char *p=(char *)u; *p=0; }')
    fact = result.query('f', 'p')
    assert fact.origin == 'a'
    assert fact.offset.exact_value == offset
    assert fact.object_extent == 16
    assert not issues


@pytest.mark.parametrize('operation', ['u *= 2;', 'u ^= 4;', 'u = u & ~3UL;', 'u += n;', 'u = (unsigned int)u;'])
def test_lossy_arithmetic(operation):
    result, issues = analyze('void f(int n) { char a[16]; uintptr_t u=(uintptr_t)a; ' + operation + ' char *p=(char *)u; *p=0; }')
    fact = result.query('f', 'p')
    assert fact.offset.is_unknown
    assert fact.object_extent is None
    assert not fact.proven_intervals
    assert len(issues) == 1


def test_unused_cast_does_not_report():
    _, issues = analyze('void f(char *p) { unsigned int u=(unsigned int)p; char *q=(char *)u; }')
    assert not issues


@pytest.mark.parametrize('right,bad', [('a', False), ('b', True)])
def test_subtraction(right, bad):
    _, issues = analyze('void f(void) { int a[8], b[8]; long d=&a[6]-&' + right + '[2]; }')
    assert bool(issues) == bad
    if bad:
        assert issues[0].cwe_id == 'CWE-469'


def test_unknown_subtraction_and_integer_difference():
    result, issues = analyze('void f(int *a, int *b) { long d=a-b; uintptr_t x=(uintptr_t)a; uintptr_t y=(uintptr_t)b; long n=x-y; }')
    assert not issues
    assert result.query('f', 'd').origin is None


HEADER = 'typedef struct { int flags; char sig[4]; } HEADER;\n'


def test_container_recovery():
    result, issues = analyze(HEADER + '''
void f(void) {
 HEADER h;
 char *m=&h.sig[0];
 char *alias=m;
 HEADER *p=(HEADER *)((char *)alias - offsetof(HEADER,sig));
 int n=p->flags;
}''')
    assert not issues
    assert result.query('f', 'p').origin == 'h'
    assert result.query('f', 'p').offset.exact_value == 0


def test_external_container():
    _, issues = analyze(HEADER + 'void f(char *member) { HEADER *p=(HEADER *)(member - offsetof(HEADER,sig)); int n=p->flags; }')
    assert len(issues) == 1
    assert 'containing-object' in issues[0].message


def test_helper_access_preserves_loss():
    _, issues = analyze('''
static void use(char *p) { *p=0; }
void f(void) { char a[8]; uintptr_t u=(uintptr_t)a; u ^= 4; use((char *)u); }
''')
    assert len(issues) == 1
    assert "call to 'use'" in issues[0].message


def test_loss_in_helper_propagates():
    _, issues = analyze('''
static void use(char *p) { uintptr_t u=(uintptr_t)p; u ^= 4; *(char *)u=0; }
void f(void) { char a[8]; use(a); }
''')
    assert issues
    assert any("call to 'use'" in issue.message for issue in issues)


def test_misaligned_cast_does_not_retain_proof():
    result, issues = analyze('void f(void) { int a[8]; int *p=(int *)((char *)a+1); *p=0; }')
    assert result.query('f', 'p').object_extent is None
    assert len(issues) == 1


@pytest.mark.parametrize('actual,bad', [('h.sig', False), ('external', True)])
def test_container_through_helper(actual, bad):
    result, issues = analyze(HEADER + '''
static void use(char *member) { HEADER *p=(HEADER *)(member - offsetof(HEADER,sig)); int n=p->flags; }
void f(char *external) { HEADER h; use(''' + actual + '''); }
''')
    assert bool(issues) == bad


def test_integer_update_outside_object_loses_proof():
    result, issues = analyze('void f(void) { char a[1]; uintptr_t u=(uintptr_t)(a+1); u++; *(char *)u=0; }')
    assert result.query('f', 'u').object_extent is None
    assert len(issues) == 1


def test_cast_alias_member_decay():
    result, issues = analyze(HEADER + 'void f(void) { HEADER h; char *m=h.sig; HEADER *p=(HEADER *)(m - offsetof(HEADER,sig)); int n=p->flags; }')
    assert not issues
    assert result.query('f', 'p').offset.exact_value == 0


def test_container_arithmetic_alias():
    _, issues = analyze(HEADER + 'void f(char *member) { char *base=member - offsetof(HEADER,sig); HEADER *p=(HEADER *)base; int n=p->flags; }')
    assert len(issues) == 1


def test_unknown_layout_does_not_prove_container():
    _, issues = analyze('typedef struct { int flags:3; char sig[4]; } H; void f(char *m) { H *p=(H *)(m - offsetof(H,sig)); int n=p->flags; }')
    assert len(issues) == 1


def test_scaling_remains_independent():
    from cgull.rules.types_and_arrays import PointerSubtractionSizeRule
    ctx = CASTParser().parse('void f(void) { int a[8],b[8]; int *p=a,*q=b; memcpy(a,b,q-p); }')
    assert len(PointerProvenanceRule().scan_ast('test.c', ctx)) == 1
    assert len(PointerSubtractionSizeRule().scan_ast('test.c', ctx)) == 1


def test_branch_loss_is_not_restored_by_identity_cast():
    result, issues = analyze('void f(int flag) { char a[16]; uintptr_t u=(uintptr_t)a; if(flag) u ^= 4; char *p=(char *)u; *p=0; }')
    assert result.query('f', 'p').object_extent is None
    assert len(issues) == 1


@pytest.mark.parametrize('value', ['sizeof(p)', '*p', 'p != 0'])
def test_scalar_values_are_not_pointer_aliases(value):
    result, issues = analyze('void f(unsigned long *p) { uintptr_t u=' + value + '; char *q=(char *)u; }')
    assert result.query('f', 'q').origin is None
    assert 'PROVENANCE_LOST' not in result.query('f', 'q').degradations
    assert not issues


def test_distinct_allocations_on_one_line():
    _, issues = analyze('void f(void) { char *a=malloc(8), *b=malloc(8); long d=a-b; }')
    assert len(issues) == 1
    assert issues[0].cwe_id == 'CWE-469'


def test_subtraction_aliases_and_casts():
    _, issues = analyze('void f(void) { int a[8], b[8]; int *p=a+4, *q=b+2; long d=(char *)p-(char *)q; }')
    assert len(issues) == 1


def test_unsigned_platform_address_typedef():
    result, issues = analyze('typedef unsigned long UINTN; void f(void) { int a[8]; UINTN u=(UINTN)a; int *p=(int *)u; *p=0; }')
    assert result.query('f', 'p').origin == 'a'
    assert not issues
