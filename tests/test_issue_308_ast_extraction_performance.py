"""Regression coverage for issue #308 extraction optimizations."""

from cgull.ast_analyzer import CASTParser
from cgull.ast_analyzer.performance import CASTParser as OptimizedCASTParser
from cgull.ast_analyzer.visitor import CASTParser as LegacyCASTParser
from cgull.utils import strip_comments_keep_lines


def _source(function_count: int = 64) -> str:
    parts = ["int global_before = 1;\n"]
    for i in range(function_count):
        parts.append(
            f"int fn_{i}(int value) {{\n"
            f"    int local_{i} = value + {i};\n"
            f"    return local_{i};\n"
            "}\n"
        )
    parts.append("unsigned long global_after = 2;\n")
    return "".join(parts)


def _function_shape(functions):
    return [
        (
            fn.name,
            fn.return_type,
            [(p.name, p.type_name, p.is_pointer, p.is_array) for p in fn.parameters],
            fn.start_line,
            fn.end_line,
            fn.body_start_line,
            fn.start_line_exp,
            fn.end_line_exp,
            fn.body,
        )
        for fn in functions
    ]


def _global_shape(global_vars):
    return {
        name: (
            var.type_name,
            var.is_pointer,
            var.is_signed,
            var.is_volatile,
            var.is_array,
            var.array_size_expr,
            var.has_initializer,
            var.declaration_line,
        )
        for name, var in global_vars.items()
    }


def test_public_parser_uses_optimized_extractor():
    assert CASTParser is OptimizedCASTParser


def test_optimized_fallback_extraction_matches_legacy_output():
    source = _source()
    clean_lines, clean_code = strip_comments_keep_lines(source)

    legacy = LegacyCASTParser()
    optimized = OptimizedCASTParser()

    legacy_functions = legacy._extract_functions(clean_lines, clean_code, set())
    optimized_functions = optimized._extract_functions(clean_lines, clean_code, set())

    assert _function_shape(optimized_functions) == _function_shape(legacy_functions)

    legacy_globals = legacy._extract_global_vars(clean_lines, legacy_functions, set())
    optimized_globals = optimized._extract_global_vars(clean_lines, optimized_functions, set())
    assert _global_shape(optimized_globals) == _global_shape(legacy_globals)


def test_optimized_extraction_preserves_line_map_coordinates():
    source = "\n\n" + _source(3)
    clean_lines, clean_code = strip_comments_keep_lines(source)
    line_map = {line: ("original.c", line + 100) for line in range(1, len(clean_lines) + 1)}

    legacy = LegacyCASTParser()
    optimized = OptimizedCASTParser()

    legacy_functions = legacy._extract_functions(clean_lines, clean_code, set(), line_map=line_map)
    optimized_functions = optimized._extract_functions(clean_lines, clean_code, set(), line_map=line_map)

    assert _function_shape(optimized_functions) == _function_shape(legacy_functions)
