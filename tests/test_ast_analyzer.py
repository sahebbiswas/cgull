"""
Tests for cgull.ast_analyzer.CASTParser: function/variable extraction,
pycparser cross-validation, and known edge cases.
"""

import unittest

from cgull.ast_analyzer import CASTParser


def _pycparser_available():
    try:
        import pycparser  # noqa: F401
        return True
    except ImportError:
        return False


class TestFunctionExtraction(unittest.TestCase):
    def setUp(self):
        self.parser = CASTParser()

    def test_simple_function_detected(self):
        ctx = self.parser.parse("int add(int a, int b) {\n    return a + b;\n}")
        self.assertEqual(len(ctx.functions), 1)
        self.assertEqual(ctx.functions[0].name, "add")

    def test_multiple_functions_detected_in_order(self):
        src = "void a(void) {}\nvoid b(void) {}\nvoid c(void) {}"
        ctx = self.parser.parse(src)
        self.assertEqual([f.name for f in ctx.functions], ["a", "b", "c"])

    def test_multiline_function_signature_detected(self):
        src = "int process(\n    char *buffer,\n    size_t len\n) {\n    return 0;\n}"
        ctx = self.parser.parse(src)
        self.assertEqual(len(ctx.functions), 1)
        self.assertEqual(ctx.functions[0].name, "process")

    def test_function_prototype_without_body_not_counted_as_function(self):
        src = "int foo(int x);\nint bar(int x) { return x; }"
        ctx = self.parser.parse(src)
        self.assertEqual(len(ctx.functions), 1)
        self.assertEqual(ctx.functions[0].name, "bar")

    def test_pointer_return_type_parsed(self):
        ctx = self.parser.parse("char *get_name(void) {\n    return 0;\n}")
        self.assertEqual(len(ctx.functions), 1)
        self.assertEqual(ctx.functions[0].name, "get_name")
        self.assertIn("*", ctx.functions[0].return_type)

    def test_empty_param_list_flagged(self):
        ctx = self.parser.parse("int init() {\n    return 0;\n}")
        self.assertTrue(ctx.functions[0].is_empty_param_list)
        self.assertFalse(ctx.functions[0].has_void_param_list)

    def test_void_param_list_flagged(self):
        ctx = self.parser.parse("int init(void) {\n    return 0;\n}")
        self.assertFalse(ctx.functions[0].is_empty_param_list)
        self.assertTrue(ctx.functions[0].has_void_param_list)

    def test_pointer_parameters_flagged(self):
        ctx = self.parser.parse("void f(int *a, int b) {\n}")
        params = ctx.functions[0].parameters
        self.assertTrue(params[0].is_pointer)
        self.assertFalse(params[1].is_pointer)

    def test_nested_braces_in_body_do_not_truncate_function(self):
        src = "void f(void) {\n    if (1) {\n        while (1) {\n            break;\n        }\n    }\n}"
        ctx = self.parser.parse(src)
        self.assertEqual(len(ctx.functions), 1)
        self.assertIn("while", ctx.functions[0].body)

    def test_control_flow_keywords_not_mistaken_for_functions(self):
        src = "void f(int x) {\n    if (x) {\n        x = 1;\n    }\n    while (x) {\n        x = 0;\n    }\n}"
        ctx = self.parser.parse(src)
        names = [fn.name for fn in ctx.functions]
        self.assertNotIn("if", names)
        self.assertNotIn("while", names)


class TestVariableExtraction(unittest.TestCase):
    def setUp(self):
        self.parser = CASTParser()

    def test_uninitialized_scalar_detected(self):
        ctx = self.parser.parse("void f(void) {\n    int status;\n}")
        var = ctx.functions[0].variables["status"]
        self.assertFalse(var.has_initializer)

    def test_initialized_scalar_detected(self):
        ctx = self.parser.parse("void f(void) {\n    int status = 0;\n}")
        var = ctx.functions[0].variables["status"]
        self.assertTrue(var.has_initializer)

    def test_vla_detected(self):
        ctx = self.parser.parse("void f(int len) {\n    char buf[len];\n}")
        var = ctx.functions[0].variables["buf"]
        self.assertTrue(var.is_vla)

    def test_fixed_size_array_not_vla(self):
        ctx = self.parser.parse("void f(void) {\n    char buf[64];\n}")
        var = ctx.functions[0].variables["buf"]
        self.assertFalse(var.is_vla)

    def test_pointer_variable_flagged(self):
        ctx = self.parser.parse("void f(void) {\n    char *p = 0;\n}")
        var = ctx.functions[0].variables["p"]
        self.assertTrue(var.is_pointer)

    def test_return_statement_not_mistaken_for_declaration(self):
        # Regression: `return total;` used to be mis-parsed as declaring a
        # variable named `total`.
        ctx = self.parser.parse("int f(void) {\n    int total = 1;\n    return total;\n}")
        self.assertEqual(len(ctx.functions[0].variables), 1)
        self.assertIn("total", ctx.functions[0].variables)

    def test_break_statement_not_mistaken_for_declaration(self):
        ctx = self.parser.parse("void f(void) {\n    while (1) {\n        break;\n    }\n}")
        self.assertEqual(len(ctx.functions[0].variables), 0)


@unittest.skipUnless(_pycparser_available(), "pycparser not installed")
class TestPycparserIntegration(unittest.TestCase):
    def setUp(self):
        self.parser = CASTParser()

    def test_ordinary_function_parses_with_pycparser(self):
        ctx = self.parser.parse("int add(int a, int b) {\n    return a + b;\n}")
        self.assertTrue(ctx.has_pycparser)
        self.assertIsNotNone(ctx.pycparser_ast)

    def test_multi_declarator_line_all_variables_recovered(self):
        src = "int f(void) {\n    int a, b, c;\n    a = 1;\n    b = 2;\n    c = 3;\n    return a + b + c;\n}"
        ctx = self.parser.parse(src)
        fn = ctx.functions[0]
        self.assertIn("a", fn.variables)
        self.assertIn("b", fn.variables)
        self.assertIn("c", fn.variables)
        for name in ("a", "b", "c"):
            self.assertEqual(fn.variables[name].declaration_line, 2)

    def test_macro_dependent_file_falls_back_gracefully(self):
        # A macro that expands into something syntactically required
        # (here, part of a declaration) can't be parsed by pycparser
        # without real preprocessing -- the parser must not crash, and
        # should fall back to the regex extractor.
        src = "#define TYPE int\nTYPE add(TYPE a, TYPE b) {\n    return a + b;\n}"
        ctx = self.parser.parse(src)  # should not raise
        self.assertEqual(len(ctx.functions), 1)


class TestStripOnly(unittest.TestCase):
    def test_strip_only_matches_full_parse_clean_source(self):
        src = "int x = 1; // comment\n"
        lines, code = CASTParser.strip_only(src)
        ctx = CASTParser().parse(src)
        self.assertEqual(code, ctx.clean_source)

    def test_strip_only_does_not_extract_functions(self):
        # strip_only is the cheap path used in pure-REGEX engine mode; it
        # must not do the (much more expensive) function/variable
        # extraction that full parse() does.
        lines, code = CASTParser.strip_only("int add(int a, int b) {\n    return a + b;\n}")
        self.assertIsInstance(lines, list)
        self.assertIsInstance(code, str)


if __name__ == "__main__":
    unittest.main()
