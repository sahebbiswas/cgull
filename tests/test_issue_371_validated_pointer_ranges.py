import pytest

from cgull.ast_analyzer import CASTParser
from cgull.analysis_session import analysis_session_for
from cgull.semantic_models import parse_semantic_models, SemanticModelConfigError
from cgull.rules.types_and_arrays import ValidatedPointerRangeRule


def context(body, prefix='', success='return_nonzero', params='char *p, char *other, int n'):
    ctx = CASTParser().parse(prefix + '\nint valid(void *, unsigned long);\nvoid f(' + params + ') {\n' + body + '\n}')
    assert ctx.has_pycparser
    registry = parse_semantic_models({'validators': [{
        'function': 'valid', 'target': 'arg:0', 'length': 'arg:1',
        'property': 'bounds_checked', 'success': success,
    }], 'sources': [{'function': 'external', 'outputs': ['return']}]})
    analysis_session_for(ctx, semantic_models=registry)
    return ctx


def scan(body, **kwargs):
    return ValidatedPointerRangeRule().scan_ast('test.c', context(body, **kwargs))


@pytest.mark.parametrize('access,bad', [
    ('*(int *)(p+4)', False), ('*(int *)(p+12)', False),
    ('*(int *)(p+14)', True), ('*p', False), ('p[15]', False),
    ('p[16]', True), ('p[-1]', True), ('*(p-4)', True),
])
def test_access_intervals(access, bad):
    assert bool(scan('if (!valid(p,16)) return; int x=' + access + ';')) == bad


@pytest.mark.parametrize('body,bad', [
    ('if(valid(p,16)) { int x=p[-1]; }', True),
    ('if(valid(p,16)) {} int x=p[-1];', False),
    ('if(n) { if(!valid(p,16)) return; } int x=p[-1];', False),
    ('valid(p,16); int x=p[-1];', False),
    ('if(!valid(p,16)) return; char *q=p-4;', False),
    ('if(!valid(p,16)) return; char *q=p-4; int x=*q;', True),
    ('char *q=p; if(!valid(p,16)) return; int x=q[-1];', True),
    ('if(!valid(p,16)) return; char *q=p; int x=q[-1];', True),
    ('if(!valid(p,16)) return; p=other; int x=p[-1];', False),
    ('if(!valid(p,16)) return; char *q=p; p=other; int x=q[-1];', True),
    ('if(valid(p,16) || valid(other,16)) { int x=p[-1]; }', False),
    ('if(valid(p,16) && valid(other,16)) { int x=p[-1]; }', True),
    ('if(!valid(p,16)) return; int x=sizeof(p[-1]);', False),
    ('if(!valid(p,16)) return; char *q=&p[-1];', False),
])
def test_paths_aliases_and_invalidation(body,bad):
    assert bool(scan(body)) == bad


@pytest.mark.parametrize('name', ['memcpy', 'memmove', 'memcmp'])
@pytest.mark.parametrize('args,bad', [('other,p+12,4',False),('other,p+14,4',True),('p-1,other,4',True),('other,p+16,0',False)])
def test_memory_api(name,args,bad):
    assert bool(scan('if(!valid(p,16)) return; '+name+'('+args+');')) == bad


def test_member_and_sizeof_motivating_case():
    prefix='typedef struct { int type; } HEADER;'
    issues=scan('if(!valid(p,sizeof(HEADER))) return; HEADER *h=(HEADER *)(p-sizeof(HEADER)); int x=h->type;',prefix=prefix)
    assert len(issues)==1
    assert 'before the validated range' in issues[0].message
    assert not scan('if(!valid(p,sizeof(HEADER))) return; HEADER *h=(HEADER *)p; int x=h->type;',prefix=prefix)


def test_unknown_width_offset_is_not_claimed_safe():
    issues=scan('if(!valid(p,16)) return; int x=((struct Missing *)p)->field;')
    assert len(issues)==1
    assert 'unknown offset or access width' in issues[0].message
    assert scan('if(!valid(p,16)) return; int x=p[n];')
    assert not scan('int x=p[n];')


@pytest.mark.parametrize('success,condition', [('return_zero','valid(p,16) != 0'), ({'return_equals':7},'valid(p,16) != 7')])
def test_success_contracts(success,condition):
    assert scan('if('+condition+') return; int x=p[-1];',success=success)


def test_non_success_comparison_does_not_prove_success():
    assert not scan('if(valid(p,16) != 2) { int x=p[-1]; }',success={'return_equals':7})
    assert not scan('if(valid(p,16) != 2) { int x=p[-1]; }')


def test_external_return_and_overwrite():
    assert scan('char *q=external(); if(!valid(q,16)) return; int x=q[-1];',prefix='char *external(void);')
    assert not scan('char *q=external(); if(!valid(q,16)) return; q=external(); int x=q[-1];',prefix='char *external(void);')


def test_separate_interval_and_enclosing_object():
    assert not scan('if(!valid(p,16)) return; if(!valid(p-4,4)) return; int x=p[-1];')
    assert not scan('char a[32]; p=a+4; if(!valid(p,16)) return; int x=p[-1];')
    assert not scan('if(!valid(p,8)) return; if(!valid(p+8,8)) return; int x=*(int *)(p+6);')


@pytest.mark.parametrize('length,prop,target', [('return','bounds_checked','arg:0'),('arg:1','authorized','arg:0'),('arg:1','bounds_checked','out:0')])
def test_invalid_interval_model(length,prop,target):
    with pytest.raises(SemanticModelConfigError):
        parse_semantic_models({'validators':[{'function':'v','target':target,'length':length,'property':prop,'success':'return_nonzero'}]})


def test_multifield_struct_layout_and_sizeof():
    prefix='typedef struct Header { char tag; int value; char tail[4]; } HEADER;'
    assert scan('if(!valid(p, sizeof(HEADER))) return; HEADER *h=(HEADER *)(p-sizeof(HEADER)); int x=h->value;',prefix=prefix)
    assert not scan('if(!valid(p, sizeof(HEADER))) return; HEADER *h=(HEADER *)p; int x=h->value;',prefix=prefix)
    assert scan('if(!valid(p, 6)) return; HEADER *h=(HEADER *)p; int x=h->value;',prefix=prefix)
    assert not scan('if(!valid(p, sizeof(struct Header))) return; struct Header *h=(struct Header *)p; int x=h->value;',prefix=prefix)


def test_modeled_access_and_parameter_typedef_stride():
    ctx=context('if(!valid(p,16)) return; access(p+14,4);')
    session=analysis_session_for(ctx)
    from cgull.call_effects import CallEffectModel, CallEffectRegistry
    from dataclasses import replace
    session.semantic_models=replace(session.semantic_models,call_effects=CallEffectRegistry(effects={'access':CallEffectModel('access',size_relationships=((0,1),))}))
    assert ValidatedPointerRangeRule().scan_ast('x.c',ctx)
    assert scan('if(!valid(p,16)) return; int x=p[4];',prefix='typedef int Word;',params='Word *p, char *other, int n')


def test_different_validations_merge_to_common_interval():
    assert scan('if(n) { if(!valid(p,16)) return; } else { if(!valid(p,8)) return; } int x=p[9];')
    assert not scan('if(n) { if(!valid(p,16)) return; } else { if(!valid(p,8)) return; } int x=p[7];')


def test_shared_session_after_object_bounds_rule():
    from cgull.rules.types_and_arrays import PointerRangeBoundsRule
    ctx=context('if(!valid(p,16)) return; int x=p[-1];')
    assert not PointerRangeBoundsRule().scan_ast('x.c',ctx)
    assert ValidatedPointerRangeRule().scan_ast('x.c',ctx)


def test_unknown_memory_width_and_no_ast():
    assert scan('if(!valid(p,16)) return; memcpy(other,p,n);')
    from types import SimpleNamespace
    assert not ValidatedPointerRangeRule().scan_ast('x.c',SimpleNamespace(has_pycparser=False))
