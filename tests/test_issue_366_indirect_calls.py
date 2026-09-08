from pycparser import c_parser

from benchmarks.security_fact_support import build_security_context, build_security_models
from cgull.cfg.call_graph import CallGraphFunction, build_call_graph
from cgull.cfg.construction import build_cfg, find_function_def
from cgull.cfg.security_dataflow import analyze_function_security_dataflow
from cgull.cfg.value_facts import FormatLiteralness, ValueProvenance
from cgull.cfg.value_interprocedural import analyze_translation_unit_value_dataflow
from cgull.semantic_models import ValidationProperty


def _functions(source):
    ast = c_parser.CParser().parse(source)
    return [
        CallGraphFunction(ext.decl.name, build_cfg(ext))
        for ext in ast.ext
        if type(ext).__name__ == "FuncDef"
    ]


def _indirect_calls(graph, caller):
    return [
        call
        for node in graph.function(caller).cfg.nodes.values()
        for call in node.calls
        if call.is_indirect
    ]


def test_direct_local_initializer_resolves_indirect_call():
    graph = build_call_graph(_functions("""
        int helper(int x) { return x; }
        int caller(int x) { int (*cb)(int) = helper; return cb(x); }
    """))
    call = _indirect_calls(graph, "caller")[0]
    assert call.resolved_callees == ("helper",)
    assert call.direct_callee == "helper"
    assert call.is_indirect
    assert graph.callees("caller") == ("helper",)


def test_reassignment_is_flow_sensitive():
    graph = build_call_graph(_functions("""
        int first(int x) { return x; }
        int second(int x) { return x + 1; }
        int caller(int x) {
            int (*cb)(int) = first;
            int a = cb(x);
            cb = second;
            return a + cb(x);
        }
    """))
    calls = _indirect_calls(graph, "caller")
    assert len(calls) == 2
    first_call = next(call for call in calls if call.result_target == "a")
    second_call = next(call for call in calls if call is not first_call)
    assert first_call.resolved_callees == ("first",)
    assert first_call.direct_callee == "first"
    assert second_call.resolved_callees == ("second",)
    assert second_call.direct_callee == "second"


def test_same_target_branch_join_resolves_single_target():
    graph = build_call_graph(_functions("""
        int helper(int x) { return x; }
        int caller(int x, int flag) {
            int (*cb)(int) = helper;
            if (flag) cb = helper; else cb = helper;
            return cb(x);
        }
    """))
    call = _indirect_calls(graph, "caller")[0]
    assert call.resolved_callees == ("helper",)
    assert call.direct_callee == "helper"


def test_different_branch_targets_form_deterministic_set():
    graph = build_call_graph(_functions("""
        int a(int x) { return x; }
        int b(int x) { return x; }
        int caller(int x, int flag) {
            int (*cb)(int) = a;
            if (flag) cb = a; else cb = b;
            return cb(x);
        }
    """))
    call = _indirect_calls(graph, "caller")[0]
    assert call.resolved_callees == ("a", "b")
    assert call.direct_callee is None
    assert graph.callees("caller") == ("a", "b")


def test_unknown_function_pointer_parameter_stays_unresolved():
    graph = build_call_graph(_functions("""
        int caller(int (*cb)(int), int x) { return cb(x); }
    """))
    call = _indirect_calls(graph, "caller")[0]
    assert call.resolved_callees == ()
    assert call.direct_callee is None
    assert len(graph.unresolved_edges) == 1


def test_entry_loop_back_edge_keeps_function_pointer_parameter_unknown():
    graph = build_call_graph(_functions("""
        int helper(int x) { return x; }
        int caller(int (*cb)(int), int x) {
            while (x--) cb = helper;
            return cb(x);
        }
    """))
    call = _indirect_calls(graph, "caller")[0]
    assert call.resolved_callees == ()
    assert len(graph.unresolved_edges) == 1


def test_address_of_function_initializer_resolves():
    graph = build_call_graph(_functions("""
        int helper(int x) { return x; }
        int caller(int x) { int (*cb)(int) = &helper; return cb(x); }
    """))
    assert _indirect_calls(graph, "caller")[0].resolved_callees == ("helper",)


def test_explicit_pointer_dereference_call_resolves():
    graph = build_call_graph(_functions("""
        int helper(int x) { return x; }
        int caller(int x) { int (*cb)(int) = helper; return (*cb)(x); }
    """))
    call = _indirect_calls(graph, "caller")[0]
    assert call.resolved_callees == ("helper",)
    assert call.direct_callee == "helper"
    assert call.is_indirect


def test_value_actuals_propagate_through_resolved_indirect_call():
    ctx = build_security_context(r'''
        void consume(char *value) { (void)value; }
        void caller(void) {
            void (*cb)(char *) = consume;
            cb("fixed");
        }
    ''')
    result = analyze_translation_unit_value_dataflow(ctx)
    incoming = result.parameter_facts["consume"][0]
    assert incoming.provenance is ValueProvenance.TRUSTED
    assert incoming.format_literalness is FormatLiteralness.LITERAL


def test_validator_summary_applies_through_resolved_indirect_call():
    ctx = build_security_context(r'''
        int validate(char *value);
        void sink(char *value);
        int checked(char *value) { return validate(value); }
        void caller(char *value) {
            int (*cb)(char *) = checked;
            if (cb(value)) sink(value);
        }
    ''')
    models = build_security_models()
    result = analyze_function_security_dataflow(ctx, "caller", models)
    cfg = build_cfg(find_function_def(ctx.pycparser_ast, "caller"))
    sink = next(
        node
        for node in cfg.nodes.values()
        if any(call.direct_callee == "sink" for call in node.calls)
    )
    assert ValidationProperty.BOUNDS_CHECKED in result.query_validation_properties(
        "value", sink.node_id
    )
