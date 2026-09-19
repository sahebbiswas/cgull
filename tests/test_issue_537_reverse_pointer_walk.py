import pytest

from cgull.ast_analyzer import CASTParser
from cgull.rules.types_and_arrays import ReversePointerWalkRule, PointerRangeBoundsRule


def scan(body, params='char *base, int n', rule=None):
    ctx = CASTParser().parse('int isspace(int c); unsigned long strlen(const char *s); '
                            'void use(int c); int use_value(int c); void reset(char **p);\n'
                            'void f(' + params + ') {\n' + body + '\n}')
    assert ctx.has_pycparser
    return (rule or ReversePointerWalkRule()).scan_ast('reverse.c', ctx)


def test_osrtrim():
    issues = scan('if (!base) return;\nchar *back = base + strlen(base);\n'
                  'while (isspace(*(--back))) ;\n*(back + 1) = 0;')
    assert any(i.line_number == 5 and i.cwe_id == 'CWE-125' for i in issues)
    assert all(i.rule_id == 'CGULL-056' and "logical base 'base'" in i.message for i in issues)


@pytest.mark.parametrize('access', ['use(*--p);', '--p; use(*p);', 'p--; use(*p);',
                                  'use(*p--); use(*p);', 'p -= 1; use(p[0]);'])
def test_equivalent_reverse_accesses(access):
    assert scan('char *p = base; ' + access)


@pytest.mark.parametrize('loop', [
    'while (use_value(*--p)) ;', 'while (use_value(*p--)) ;',
    'while (n) { --p; use(*p); }', 'while (n) { use(*p); p--; }',
    'do { use(*p--); } while(n);', 'do {} while (use_value(*--p));',
    'for (; use_value(*--p); ) {}', 'for (; n; p--) { use(*p); }',
    'for (; n; use(*--p)) {}',
])
def test_loop_conditions_bodies_and_steps(loop):
    assert scan('char *p = base + 2; ' + loop)


@pytest.mark.parametrize('body', [
    'while(p > base && isspace((unsigned char)*--p)) ;',
    'while(base < p && isspace(*--p)) ;',
    'while(p >= base) { use(*p--); }',
    'while(n) { if(p <= base) break; --p; use(*p); }',
    'while(n) { if(p <= base) return; use(*--p); }',
    'do { if(p > base) use(*--p); } while(n);',
    'do {} while (p > base && isspace(*--p));',
    'for(; p > base; ) { use(*--p); }',
    'while (p <= base || isspace(*--p)) ;',
    'if(p > base) { --p; use(*p); }',
])
def test_guarded_walks(body):
    assert scan('char *p = base + strlen(base); ' + body) == []


@pytest.mark.parametrize('body', [
    'char *p=base; use(*p--);',
    'char *p=base+1; use(*--p);',
    'char *p=base; sizeof(*--p);',
    'char *p=base; char *q=&*--p;',
    'char *p=base; reset(&p); use(*--p);',
    'use(*--base);',
    'char *p; use(*--p);',
    'char *p=base+1; while(n) { use(*p--); break; }',
    'char *p=base; while(n) { p=base+1; use(*--p); }',
    'char *p=base; return; use(*--p);',
])
def test_no_reverse_access_or_relationship(body):
    assert scan(body) == []


def test_postfix_first_read_is_safe_but_following_read_is_not():
    issues = scan('char *p=base;\nuse(*p--);\nuse(*p);')
    assert [i.line_number for i in issues] == [5]


def test_write_and_bad_guard_order():
    assert scan('char *p=base; *--p=0;')[0].cwe_id == 'CWE-787'
    assert scan('char *p=base; while(isspace(*--p) && p>base) {}')
    assert scan('char *p=base; while(p>=base && isspace(*--p)) {}')


def test_existing_definite_rule_unchanged_for_unknown_external_base():
    assert scan('char *p=base; use(*--p);', rule=PointerRangeBoundsRule()) == []


def test_registry():
    from cgull.rules import RULE_REGISTRY
    assert RULE_REGISTRY['CGULL-056'] is ReversePointerWalkRule


def test_guard_is_not_reapplied_after_condition_decrement():
    assert scan('char *p=base+strlen(base); while(p>base && isspace(*--p)) { use(*--p); }')


def test_local_array_loop_and_memory_update():
    assert scan('char a[4]; char *p=a+3; while(n) { use(*p--); }')
    assert scan('char *p=base; --p; ++*p;')[0].cwe_id == 'CWE-787'


@pytest.mark.parametrize('body', [
    'char *p=base; while(0) { use(*--p); }',
    'char *p=base; for(;0;) { use(*--p); }',
    'char *p=base+1; do { use(*--p); } while(0);',
    'char *p=base; if(0) use(*--p);',
    'char *p=base; 0 && *--p;',
    'char *p=base; 1 || *--p;',
])
def test_constant_dead_paths_and_single_trip(body):
    assert scan(body) == []


def test_unsupported_control_and_shadowing():
    assert scan('char *p=base; goto out; use(*--p); out:;') == []
    assert scan('char *p=base; {char *p=base; use(*--p);}') == []


def test_no_ast_fallback():
    from types import SimpleNamespace
    assert ReversePointerWalkRule().scan_ast('x.c', SimpleNamespace(has_pycparser=False)) == []


def test_osrtrim_translation_unit_scan(tmp_path):
    from cgull import CGullScanner
    from cgull.models import AnalysisEngine, ScanConfig

    source = tmp_path / 'trim.c'
    source.write_text(
        '#include <ctype.h>\n#include <string.h>\n'
        'char *trim(char *text) {\n'
        '    if (!text) return text;\n'
        '    char *back=text+strlen(text);\n'
        '    while (isspace(*--back)) ;\n'
        '    return text;\n}\n', encoding='utf-8')
    config = ScanConfig.create(rules=[ReversePointerWalkRule()],
                               engine_mode=AnalysisEngine.AST, mode='tu')
    result = CGullScanner(config=config).scan_path(str(tmp_path), jobs=1, quiet=True)
    assert result.files_failed == 0
    assert [(i.rule_id, i.line_number, i.cwe_id) for i in result.issues] == [
        ('CGULL-056', 6, 'CWE-125')]
