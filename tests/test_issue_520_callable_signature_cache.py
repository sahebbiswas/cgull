import cgull.ast_analyzer.callable_signatures as callable_signatures
from cgull.ast_analyzer import CASTParser, build_direct_call_signature_index
from cgull.cfg import find_function_def
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def _first_call(funcdef):
    from pycparser import c_ast

    calls = []

    class Visitor(c_ast.NodeVisitor):
        def visit_FuncCall(self, node):
            calls.append(node)

    Visitor().visit(funcdef)
    assert calls
    return calls[0]


def test_top_level_callable_signatures_are_formatted_once_per_translation_unit(monkeypatch):
    from pycparser import c_ast

    source = """
void sink(unsigned char value);
int first(unsigned int x) { sink(x); return 0; }
int second(unsigned int x) { sink(x); return 0; }
int third(unsigned int x) { sink(x); return 0; }
"""
    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser

    top_level_declarations = []
    for ext in ctx.pycparser_ast.ext:
        if isinstance(ext, c_ast.FuncDef):
            top_level_declarations.append(ext.decl)
        elif isinstance(ext, c_ast.Decl) and isinstance(ext.type, c_ast.FuncDecl):
            top_level_declarations.append(ext)
    top_level_ids = {id(decl) for decl in top_level_declarations}

    formatted = []
    original = callable_signatures._signature_from_decl

    def counting_signature(ast_ctx, decl, provenance):
        if id(decl) in top_level_ids:
            formatted.append(id(decl))
        return original(ast_ctx, decl, provenance)

    monkeypatch.setattr(callable_signatures, "_signature_from_decl", counting_signature)

    issues = IntegerNarrowingCastRule().scan_ast("issue520.c", ctx)

    assert len(issues) == 3
    assert set(formatted) == top_level_ids
    assert len(formatted) == len(top_level_ids)


def test_later_top_level_definition_is_not_visible_to_earlier_caller():
    source = """
int caller(unsigned int x) { sink(x); return 0; }
void sink(unsigned char value) { (void)value; }
"""
    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    caller = find_function_def(ctx.pycparser_ast, "caller")
    signature = build_direct_call_signature_index(ctx, caller).resolve(_first_call(caller))

    assert signature is None


def test_translation_unit_signature_state_does_not_leak_between_contexts():
    narrow = CASTParser().parse(
        "void sink(unsigned char value); int caller(unsigned int x) { sink(x); return 0; }"
    )
    wide = CASTParser().parse(
        "void sink(unsigned int value); int caller(unsigned int x) { sink(x); return 0; }"
    )
    assert narrow.has_pycparser and wide.has_pycparser

    narrow_caller = find_function_def(narrow.pycparser_ast, "caller")
    wide_caller = find_function_def(wide.pycparser_ast, "caller")
    narrow_signature = build_direct_call_signature_index(narrow, narrow_caller).resolve(
        _first_call(narrow_caller)
    )
    wide_signature = build_direct_call_signature_index(wide, wide_caller).resolve(
        _first_call(wide_caller)
    )

    assert narrow_signature is not None
    assert wide_signature is not None
    assert narrow_signature.parameters[0].type_name == "unsigned char"
    assert wide_signature.parameters[0].type_name == "unsigned int"
