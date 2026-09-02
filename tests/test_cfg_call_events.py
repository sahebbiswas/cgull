from pycparser import c_parser

from cgull.ast_analyzer import CASTParser
from cgull.cfg import build_cfg, find_function_def
from cgull.includes import IncludeResolver, TUIncludeExpander


def _build(code: str, function: str = "f"):
    ast = c_parser.CParser().parse(code)
    return build_cfg(find_function_def(ast, function))


def _calls(cfg):
    return [call for node in cfg.nodes.values() for call in node.calls]


def test_call_shapes_preserve_arguments_and_result_bindings():
    cfg = _build(
        """
        int make(int, int);
        void consume(int, int);

        int f(int a, int b) {
            consume(a, b);
            int declared = make(a, b);
            declared = make(b, a);
            return make(declared, b);
        }
        """
    )

    calls = _calls(cfg)
    consume = next(call for call in calls if call.direct_callee == "consume")
    make_calls = {
        call.actual_arguments: call
        for call in calls
        if call.direct_callee == "make"
    }

    assert consume.actual_arguments == ("a", "b")
    assert consume.result_target is None
    assert make_calls[("a", "b")].result_target == "declared"
    assert make_calls[("b", "a")].result_target == "declared"
    assert make_calls[("declared", "b")].result_target == "return"
    assert all(not call.is_unresolved for call in calls)

    declaration_event = next(node for node in cfg.nodes.values() if "declared = make(a, b)" in node.expr_str)
    assert declaration_event.direct_callee == "make"
    assert declaration_event.actual_arguments == ("a", "b")
    assert declaration_event.result_target == "declared"


def test_nested_calls_are_explicit_without_binding_inner_result_to_outer_target():
    cfg = _build(
        """
        int first(int);
        int second(int);
        int combine(int, int);

        int f(int a, int b) {
            int result = combine(first(a), second(b));
            return result;
        }
        """
    )

    calls = {call.direct_callee: call for call in _calls(cfg)}
    assert calls["combine"].actual_arguments == ("first(a)", "second(b)")
    assert calls["combine"].result_target == "result"
    assert calls["first"].actual_arguments == ("a",)
    assert calls["second"].actual_arguments == ("b",)
    assert calls["first"].result_target is None
    assert calls["second"].result_target is None


def test_indirect_function_pointer_call_is_retained_as_unresolved():
    cfg = _build(
        """
        int f(int value, int (*callback)(int)) {
            return callback(value);
        }
        """
    )

    calls = _calls(cfg)
    assert len(calls) == 1
    call = calls[0]
    assert call.direct_callee is None
    assert call.callee_expression == "callback"
    assert call.actual_arguments == ("value",)
    assert call.result_target == "return"
    assert call.is_indirect is True
    assert call.is_unresolved is True


def test_header_call_source_location_uses_original_line_map(tmp_path):
    header = tmp_path / "helper.h"
    header.write_text(
        "#ifndef HELPER_H\n"
        "#define HELPER_H\n"
        "int header_helper(int value) {\n"
        "    return sink(value, 7);\n"
        "}\n"
        "#endif\n"
    )
    source = tmp_path / "main.c"
    source.write_text('#include "helper.h"\nint sink(int, int);\n')

    resolver = IncludeResolver(include_roots=[str(tmp_path)], base_dir=str(tmp_path))
    tu = TUIncludeExpander(resolver=resolver).expand(source.read_text(), str(source))
    ast_ctx = CASTParser().parse(tu.expanded_text, line_map=tu.line_map)
    cfg = build_cfg(
        find_function_def(ast_ctx.pycparser_ast, "header_helper"),
        line_map=tu.line_map,
    )

    call = _calls(cfg)[0]
    assert call.direct_callee == "sink"
    assert call.source_location.file_path == str(header.resolve())
    assert call.source_location.line_number == 4
    containing_event = next(node for node in cfg.nodes.values() if node.calls)
    assert containing_event.source_location.file_path == str(header.resolve())
    assert containing_event.source_location.line_number == 4
