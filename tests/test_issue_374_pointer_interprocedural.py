"""Call-specific pointer requirements, proof transfer, and SCC regressions."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from cgull.analysis_session import analysis_session_for
from cgull.ast_analyzer import CASTParser
from cgull.cfg.pointer_ranges import PointerProvenance
from cgull.cfg.value_facts import ValueProvenance
from cgull.rules.types_and_arrays import PointerRangeBoundsRule, ValidatedPointerRangeRule
from cgull.semantic_models import parse_semantic_models


MODELS = parse_semantic_models({
    'validators': [{'function': 'valid', 'target': 'arg:0', 'length': 'arg:1',
                    'property': 'bounds_checked', 'success': 'return_nonzero'}],
    'sources': [{'function': 'external', 'outputs': ['return']}],
})
INNER = 'static void inner(char *p) { int x=*(int *)(p-4); }\n'


def analyze(source):
    ctx = CASTParser().parse('int valid(void *, unsigned long); char *external(void);\n' + source)
    assert ctx.has_pycparser
    session = analysis_session_for(ctx, semantic_models=MODELS)
    issues = PointerRangeBoundsRule().scan_ast('x.c', ctx) + ValidatedPointerRangeRule().scan_ast('x.c', ctx)
    return session.pointer_range_analysis, issues


def test_mixed_callers_keep_separate_contexts_and_provenance():
    result, issues = analyze(INNER + '''
void api(void) {
 char buffer[64]; inner(buffer+8);
 char *p=external(); if(!valid(p,16)) return;
 inner(p);
}''')
    assert len(issues) == 1
    assert issues[0].code_snippet == 'inner(p);'
    assert 'before the validated range' in issues[0].message
    accesses = [event for event in result.call_events['api'] if event.is_access]
    safe, unsafe = accesses
    assert safe.fact.origin == 'buffer'
    assert safe.fact.offset.exact_value == 4
    assert safe.fact.backward_accessible_extent == 4
    assert safe.fact.forward_accessible_extent == 60
    assert unsafe.fact.provenance == PointerProvenance.EXTERNAL
    assert unsafe.fact.value_provenance == ValueProvenance.UNTRUSTED


@pytest.mark.parametrize('actual,bad', [('buffer+8', False), ('p', True)])
def test_two_wrapper_levels_aliases_and_casts(actual, bad):
    result, issues = analyze(INNER + '''
static void middle(char *q) { char *alias=q; inner((char *)(void *)alias); }
static void outer(char *r) { middle(r); }
void api(char *p) { char buffer[64]; if(!valid(p,16)) return; outer(''' + actual + '''); }
''')
    assert bool(issues) == bad
    assert any(req.offset.exact_value == -4 and req.width == 4
               for req in result.requirements['outer'].requirements)


def test_wrapper_offset_composition():
    _, issues = analyze(INNER + '''
static void middle(char *p) { inner(p+8); }
void api(void) { char buffer[16]; middle(buffer); }
''')
    assert not issues


@pytest.mark.parametrize('body,bad', [
    ('if(!valid(p,16)) return; inner(p);', True),
    ('if(flag) { if(!valid(p,16)) return; inner(p); }', True),
    ('if(flag) { if(!valid(p,16)) return; } inner(p);', False),
    ('if(!valid(p,16)) return; if(p-base<4) return; inner(p);', False),
    ('if(!valid(p,16)) return; if(p-base<3) return; inner(p);', True),
    ('if(!valid(p,16)) return; if(p>=base+4) inner(p);', True),
    ('if(!valid(p,16)) return; if(p-base<4) return; p=other; inner(p);', False),
])
def test_branch_facts_and_endpoint_safety(body, bad):
    _, issues = analyze(INNER + 'void api(char *p,char *base,char *other,int flag) {' + body + '}')
    assert bool(issues) == bad


@pytest.mark.parametrize('offset,bad', [(8, False), (0, True)])
def test_callee_validation_is_evaluated_against_caller_object(offset, bad):
    _, issues = analyze('''
static void inner(char *p) { if(!valid(p,16)) return; int x=p[-4]; }
void api(void) { char buffer[64]; inner(buffer+''' + str(offset) + '''); }
''')
    assert bool(issues) == bad
    if bad:
        assert all(issue.rule_id == 'CGULL-050' for issue in issues)


@pytest.mark.parametrize('recursive', [
    'static void inner(char *p) { int x=p[-4]; inner(p); }',
    'static void second(char *); static void inner(char *p) { int x=p[-4]; second(p); } '
    'static void second(char *p) { inner(p); }',
])
def test_recursive_scc_stabilizes(recursive):
    result, issues = analyze(recursive + '\nvoid api(char *p) { if(!valid(p,16)) return; inner(p); }')
    assert len(issues) == 1
    assert not result.diagnostics
    assert max(result.iterations_by_scc.values()) > 1


def test_recursive_shift_degrades_with_visible_diagnostic():
    result, issues = analyze('''
static void inner(char *p) { int x=p[-4]; inner(p-1); }
void api(char *p) { if(!valid(p,16)) return; inner(p); }
''')
    assert result.requirements['inner'].unknown
    assert result.diagnostics[0].code == 'CONVERGENCE_LIMIT'
    assert issues
    assert 'cannot be proven' in issues[0].message


def test_unknown_calls_and_shadowed_function_pointer_do_not_bind():
    result, issues = analyze(INNER + '''
void api(char *p, void (*inner)(char *)) {
 if(!valid(p,16)) return; inner(p); unknown(p);
}
''')
    assert not issues
    assert not result.call_events['api']


def test_block_function_declaration_still_resolves_direct_call():
    _, issues = analyze(INNER + '''
void api(char *p) {
 void inner(char *);
 if(!valid(p,16)) return; inner(p);
}
''')
    assert len(issues) == 1


def test_address_taken_function_keeps_unknown_entry():
    _, issues = analyze('''
static void inner(char *p) { if(!valid(p,16)) return; int x=p[-4]; }
void api(void) { char buffer[64]; inner(buffer+8); register_callback(inner); }
''')
    assert len(issues) == 1
    assert issues[0].rule_id == 'CGULL-051'


def test_forward_access_and_size_extent_remain_consistent():
    result, issues = analyze('''
static void inner(char *p) { int x=p[8]; }
void api(void) { char buffer[8]; inner(buffer); }
''')
    assert len(issues) == 1
    assert issues[0].rule_id == 'CGULL-050'
    # Existing #302 entry capacities are lower guarantees, not exact objects.
    assert result.query('inner', 'p').object_extent is None
    assert result.call_events['api'][0].fact.object_extent == 8


def test_opaque_actual_retains_callee_validation():
    _, issues = analyze('''
char *opaque(void);
static void inner(char *p) { if(!valid(p,16)) return; int x=p[-4]; }
void api(void) { inner(opaque()); }
''')
    assert len(issues) == 1
    assert "Required by call to 'inner'" in issues[0].message


def test_results_deterministic_across_hash_seeds():
    script = '''
import json
from test_issue_374_pointer_interprocedural import analyze, INNER
r, issues = analyze(INNER + 'static void middle(char *p) {inner(p);} void api(char *p) {if(!valid(p,16)) return; middle(p);}')
print(json.dumps([(i.rule_id,i.line_number,i.column_number,i.message) for i in issues]))
'''
    outputs = []
    for seed in ('1', '321'):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        env['PYTHONPATH'] = os.pathsep.join((str(Path(__file__).parent), str(Path(__file__).resolve().parents[1]), env.get('PYTHONPATH', '')))
        outputs.append(subprocess.check_output([sys.executable, '-c', script], env=env, text=True))
    assert json.loads(outputs[0])
    assert outputs[0] == outputs[1]
