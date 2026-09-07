import pytest

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import PointerRangeBoundsRule


def scan(body, prefix='', params='int n'):
    ctx = CASTParser().parse(prefix + '\nvoid f(' + params + ') {\n' + body + '\n}')
    assert ctx.has_pycparser
    return PointerRangeBoundsRule().scan_ast('bounds.c', ctx)


@pytest.mark.parametrize('expr,bad', [
    ('p - 4', True), ('p + 8', True), ('p - 3', False),
    ('p + 7', False), ('p + -4', True), ('p - -8', True),
    ('&p[-4]', True), ('&p[7]', False), ('(p + 2) - 6', True),
    ('2 + p', False), ('p + n', False), ('&p[n]', False),
])
def test_constant_derivation_boundaries(expr, bad):
    issues = scan('int a[10]; int *p = &a[3]; int *q = ' + expr + ';')
    assert bool(issues) == bad
    assert all(i.cwe_id == 'CWE-823' for i in issues)


@pytest.mark.parametrize('update,bad', [('+= 3', True), ('-= 9', True), ('+= 2', False), ('-= 8', False), ('+= n', False)])
def test_compound_updates(update, bad):
    assert bool(scan('int a[10]; int *p = a + 8; p ' + update + ';')) == bad


@pytest.mark.parametrize('access,cwe', [('*p', 'CWE-125'), ('p[0]', 'CWE-125'), ('*(p - 1)', None), ('p[-1]', None)])
def test_one_past_reads(access, cwe):
    issues = scan('int a[10]; int *p = a + 10; int v = ' + access + ';')
    assert [i.cwe_id for i in issues] == ([cwe] if cwe else [])


def test_one_past_write_and_unevaluated_expressions():
    assert [i.cwe_id for i in scan('int a[10]; int *p = a + 10; *p = 1;')] == ['CWE-787']
    assert scan('int a[10]; int *p = a + 10; int *q = &*p; int n = sizeof(*p);') == []


def test_stride_casts_typedefs_aliases():
    assert scan('int a[10]; char *p = (char *)a + 39; char *q = p + 1;') == []
    assert len(scan('int a[10]; char *p = (char *)a + 39; char *q = p + 2;')) == 1
    assert len(scan('Word a[10]; Ptr p = a + 8; Ptr q = p; q += 3;', 'typedef int Word; typedef Word *Ptr;')) == 1
    assert scan('Word a[10]; Ptr p = a + 8; p += 2;', 'typedef int Word; typedef Word *Ptr;') == []
    assert scan('char a[10]; char *p = a + 8; p = (char *)a; p += 2;') == []


def test_branches_require_definite_violation():
    assert scan('int a[10]; int *p; if(n) p=a+8; else p=a; p+=3;') == []
    assert len(scan('int a[10]; int *p; if(n) p=a+8; else p=a+9; p+=3;')) == 1
    assert scan('int a[10]; int b[10]; int *p; if(n) p=a; else p=b; p+=11;') == []


def test_same_line_order_and_source_locations():
    issues = scan('int a[10]; int *p = a; p += 10; *p = 1;')
    assert len(issues) == 1
    assert issues[0].line_number == 3
    assert issues[0].column_number > 1
    assert issues[0].rule_id == 'CGULL-050'


def test_unknown_and_loop_offsets():
    assert scan('int a[10]; int *p = a; while(n--) p++; p+=11;') == []
    assert scan('int *p; int *q = p + 50;') == []
    assert scan('int a[10]; int *p = a + n; int *q = p + 50;') == []


def test_access_width_can_cross_end_even_with_in_range_start():
    issues = scan('char a[10]; int *p = (int *)(a + 9); *p = 1;')
    assert [i.cwe_id for i in issues] == ['CWE-787']


def test_no_ast_fallback():
    from types import SimpleNamespace
    assert PointerRangeBoundsRule().scan_ast('x.c', SimpleNamespace(has_pycparser=False)) == []


@pytest.mark.parametrize('body', [
    'int a[10]; int *p=a; goto skip; p+=9; skip: p+=2;',
    'int a[10]; int *p=a; { int a[1]; p=a; } p+=2;',
    'int a[10]; int *p=a+10; reset(&p); *p=1;',
    'int a[10]; int *p=a+10; int v=*(--p);',
    'int a[10]; int *p=a; switch(n) {case 1: p=a+9;} p+=2;',
])
def test_unsupported_flow_and_alias_effects_do_not_claim_definite(body):
    assert scan(body, 'void reset(int **p);') == []


def test_caller_minimum_capacity_is_not_an_exact_object_boundary():
    ctx = CASTParser().parse('void f(int *p) { p += 11; } void g(void) {int a[10]; f(a);}')
    assert PointerRangeBoundsRule().scan_ast('x.c', ctx) == []


def test_unreachable_tail_and_memory_increment():
    assert scan('int a[10]; int *p=a; return; p+=11;') == []
    assert [i.cwe_id for i in scan('int a[10]; int *p=a+10; ++*p;')] == ['CWE-787']


def test_scalar_index_value_is_not_a_pointer_alias():
    assert scan('int a[10]; int n=a[9]; int m=n+50;') == []


def test_allocation_extent_and_destination_stride():
    assert len(scan('int *p=malloc(40); p+=11;')) == 1
    assert scan('int *p; p=malloc(40); p+=10;') == []


def test_local_typedef_and_pointer_increment():
    assert len(scan('typedef char Byte; Byte a[2]; Byte *p=a+2; p++;')) == 1


def test_definite_query_does_not_confuse_guarantees_with_extents():
    from cgull.cfg.pointer_ranges import PointerRangeFact, join_pointer_facts
    a = PointerRangeFact.object('a', 10)
    mixed = join_pointer_facts(a, a.shifted(8)).shifted(3)
    assert not mixed.definitely_outside()
    assert a.shifted(10).definitely_outside(1)
    assert not a.shifted(10).definitely_outside()
    assert a.shifted(-1).definitely_outside()
    assert not a.unknown_offset().definitely_outside()
