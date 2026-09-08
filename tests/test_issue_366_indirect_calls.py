from pycparser import c_parser

from cgull.cfg.call_graph import CallGraphFunction, build_call_graph
from cgull.cfg.construction import build_cfg


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
    assert call.direct_callee is None
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
    calls = {call.result_target: call for call in _indirect_calls(graph, "caller")}
    assert calls["a"].resolved_callees == ("first",)
    assert calls["return"].resolved_callees == ("second",)


def test_same_target_branch_join_resolves_single_target():
    graph = build_call_graph(_functions("""
        int helper(int x) { return x; }
        int caller(int x, int flag) {
            int (*cb)(int) = helper;
            if (flag) cb = helper; else cb = helper;
            return cb(x);
        }
    """))
    assert _indirect_calls(graph, "caller")[0].resolved_callees == ("helper",)


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
    assert call.direct_callee is None
