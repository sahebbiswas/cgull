from cgull.ast_analyzer import (
    CASTParser,
    build_direct_call_signature_index,
    resolve_direct_call_signature,
)
from cgull.cfg import find_function_def
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def _issues(source: str):
    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue359.c", ctx)


def _call_signature(source: str):
    from pycparser import c_ast

    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    funcdef = find_function_def(ctx.pycparser_ast, "caller")
    calls = []

    class V(c_ast.NodeVisitor):
        def visit_FuncCall(self, node):
            calls.append(node)
            self.generic_visit(node)

    V().visit(funcdef)
    assert len(calls) == 1
    return resolve_direct_call_signature(ctx, funcdef, calls[0])


def test_prototype_only_matches_equivalent_definition_for_all_conversion_families():
    cases = [
        ("signed char", "int", "CWE-194"),
        ("int", "unsigned int", "CWE-195"),
        ("unsigned int", "int", "CWE-196"),
        ("unsigned int", "unsigned char", "CWE-197"),
    ]
    for source_type, destination_type, cwe in cases:
        prototype = f"void sink({destination_type} value);\nint caller({source_type} x) {{ sink(x); return 0; }}\n"
        definition = f"void sink({destination_type} value) {{ (void)value; }}\nint caller({source_type} x) {{ sink(x); return 0; }}\n"
        prototype_issues = _issues(prototype)
        definition_issues = _issues(definition)
        assert [issue.cwe_id for issue in prototype_issues] == [cwe]
        assert [issue.cwe_id for issue in definition_issues] == [cwe]


def test_safe_prototype_counterparts_are_clean():
    source = """
void a(unsigned int value);
void b(int value);
int caller(unsigned int u, int s) {
    a(u);
    b(s);
    return 0;
}
"""
    assert _issues(source) == []


def test_named_unnamed_typedef_qualified_and_multiple_parameters_are_supported():
    source = """
typedef unsigned char byte_t;
void sink(byte_t, const unsigned char named, unsigned int safe);
int caller(unsigned int a, unsigned int b, unsigned int c) {
    sink(a, b, c);
    return 0;
}
"""
    issues = _issues(source)
    assert len(issues) == 2
    assert "parameter #1" in issues[0].message
    assert "parameter 'named'" in issues[1].message


def test_block_scope_declaration_is_visible_and_inner_declaration_shadows_file_scope():
    visible = """
int caller(unsigned int x) {
    void sink(unsigned char value);
    sink(x);
    return 0;
}
"""
    assert len(_issues(visible)) == 1

    shadowed = """
void sink(unsigned char value);
int caller(unsigned int x) {
    {
        void sink(unsigned int value);
        sink(x);
    }
    return 0;
}
"""
    assert _issues(shadowed) == []


def test_conflicting_visible_declarations_degrade_to_unresolved():
    source = """
void sink(unsigned char value);
void sink(unsigned int value);
int caller(unsigned int x) { sink(x); return 0; }
"""
    signature = _call_signature(source)
    assert signature is not None
    assert not signature.resolved
    assert signature.provenance == "conflicting-declarations"
    assert _issues(source) == []


def test_compatible_prototype_and_definition_reconcile_deterministically():
    source = """
void sink(unsigned char value);
void sink(unsigned char value) { (void)value; }
int caller(unsigned int x) { sink(x); return 0; }
"""
    signature = _call_signature(source)
    assert signature is not None and signature.resolved
    assert signature.has_prototype
    assert len(signature.parameters) == 1
    assert len(_issues(source)) == 1


def test_variadic_fixed_parameters_are_checked_but_trailing_arguments_are_not_bound():
    source = """
void sink(unsigned char first, ...);
int caller(unsigned int a, unsigned int b) { sink(a, b); return 0; }
"""
    issues = _issues(source)
    assert len(issues) == 1
    assert "parameter 'first'" in issues[0].message


def test_unspecified_parameter_declaration_does_not_invent_destination_types():
    source = """
void sink();
int caller(unsigned int x) { sink(x); return 0; }
"""
    signature = _call_signature(source)
    assert signature is not None and signature.resolved
    assert not signature.has_prototype
    assert _issues(source) == []


def test_pointer_and_array_parameters_are_not_treated_as_scalar_integer_destinations():
    source = """
void pointer_sink(unsigned char *value);
void array_sink(unsigned char value[]);
int caller(unsigned char *p) {
    pointer_sink(p);
    array_sink(p);
    return 0;
}
"""
    assert _issues(source) == []


def test_reusable_index_resolves_many_calls_without_rewalking_function():
    from pycparser import c_ast

    source = """
void sink(unsigned char value);
int caller(unsigned int x) {
    sink(x);
    sink(x);
    sink(x);
    return 0;
}
"""
    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    funcdef = find_function_def(ctx.pycparser_ast, "caller")
    calls = []

    class V(c_ast.NodeVisitor):
        def visit_FuncCall(self, node):
            calls.append(node)

    V().visit(funcdef)
    index = build_direct_call_signature_index(ctx, funcdef)
    signatures = [index.resolve(call) for call in calls]
    assert len(signatures) == 3
    assert all(signature is not None and signature.parameters[0].type_name == "unsigned char" for signature in signatures)
