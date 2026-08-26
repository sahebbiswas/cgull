"""
Tests for cgull.ast_analyzer.CASTParser: function/variable extraction,
pycparser cross-validation, and known edge cases.
"""

import unittest
from unittest.mock import patch

from cgull.ast_analyzer import CASTParser


def _pycparser_available():
    try:
        import pycparser  # noqa: F401
        return True
    except ImportError:
        return False


def _pcpp_available():
    try:
        import pcpp  # noqa: F401
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

    def test_block_scoped_shadowing_variables_tracked_independently(self):
        src = """
        void f(void) {
            int i = 0;
            {
                int i = 10;
                i++;
            }
        }
        """
        ctx = self.parser.parse(src)
        fn = ctx.functions[0]
        # Should have 2 CVariables in total across scopes
        all_vars = list(fn.variables.values())
        self.assertEqual(len(all_vars), 2)
        outer_i = next(v for v in all_vars if v.enclosing_block_id == 1)
        inner_i = next(v for v in all_vars if v.enclosing_block_id == 2)
        self.assertEqual(outer_i.read_lines, [])
        self.assertGreater(len(inner_i.read_lines), 0)

    def test_scoped_var_dict_string_lookup_returns_innermost(self):
        src = """
        void f(void) {
            int x = 1;
            {
                int x = 2;
            }
        }
        """
        ctx = self.parser.parse(src)
        fn = ctx.functions[0]
        # String lookup fn.variables["x"] should return the innermost declaration (x = 2)
        v_str = fn.variables["x"]
        self.assertEqual(v_str.enclosing_block_id, 2)
        self.assertEqual(v_str.declaration_line, 5)


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

    def test_ast_parser_handles_variadic_functions(self):
        from cgull.ast_analyzer import ASTAnalyzer
        c_code = """
        void debug_print(const char *fmt, ...);

        int main(void) {
            debug_print("Status: %s", "OK");
            return 0;
        }
        """
        analyzer = ASTAnalyzer()
        ast_ctx = analyzer.parse(c_code)
        self.assertTrue(ast_ctx.has_pycparser)

    def test_ast_parser_handles_variadic_function_definition(self):
        c_code = """
        void debug_print(const char *fmt, ...) {
            // body
        }

        int main(void) {
            debug_print("Status: %s", "OK");
            return 0;
        }
        """
        analyzer = CASTParser()
        ast_ctx = analyzer.parse(c_code)
        self.assertTrue(ast_ctx.has_pycparser)
        fn_names = [f.name for f in ast_ctx.functions]
        self.assertIn("debug_print", fn_names)
        self.assertIn("main", fn_names)


class TestRegexTier3Fallback(unittest.TestCase):
    """
    Forces the regex fallback tier to run by patching _try_pycparser to fail.
    This guarantees the massive regex parsing blocks in ast_analyzer.py
    remain heavily tested even on environments where pycparser/pcpp are installed.
    """
    def setUp(self):
        from unittest.mock import patch
        self.parser = CASTParser()
        self.patcher = patch.object(self.parser, "_try_pycparser", return_value=(None, False))
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_regex_extracts_simple_function(self):
        ctx = self.parser.parse("int add(int a, int b) {\n    return a + b;\n}")
        self.assertFalse(ctx.has_pycparser)
        self.assertEqual(len(ctx.functions), 1)
        self.assertEqual(ctx.functions[0].name, "add")

    def test_regex_extracts_variables(self):
        ctx = self.parser.parse("void f(int len) {\n    char buf[len];\n}")
        self.assertFalse(ctx.has_pycparser)
        var = ctx.functions[0].variables["buf"]
        self.assertTrue(var.is_vla)

    def test_regex_fallback_handles_fn_ptr_gracefully(self):
        src = "void register_handler(void (*handler)(int)) {}"
        ctx = self.parser.parse(src)
        self.assertFalse(ctx.has_pycparser)

    def test_regex_fallback_handles_multiline_decls_gracefully(self):
        src = "void f(void) {\n    int\n    a,\n    b;\n}"
        ctx = self.parser.parse(src)
        self.assertFalse(ctx.has_pycparser)
        self.assertEqual(len(ctx.functions), 1)

    def test_regex_fallback_handles_typedefs_and_extensions(self):
        src = "typedef int custom_t;\nvoid __attribute__((noreturn)) fatal(void) {}"
        ctx = self.parser.parse(src)
        self.assertFalse(ctx.has_pycparser)


@unittest.skipUnless(_pycparser_available(), "pycparser not installed")
class TestComplexASTConstructs(unittest.TestCase):
    def setUp(self):
        self.parser = CASTParser()

    def test_function_handler_prototype_with_fn_ptr_param(self):
        src = "void register_handler(void (*handler)(int));"
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)

    def test_function_handler_def_with_fn_ptr_param(self):
        src = "void register_handler(void (*handler)(int)) {}"
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        self.assertEqual(len(ctx.functions), 1)
        fn = ctx.functions[0]
        self.assertEqual(fn.name, "register_handler")
        self.assertEqual(len(fn.parameters), 1)
        self.assertEqual(fn.parameters[0].name, "handler")
        self.assertTrue(fn.parameters[0].is_pointer)

    def test_compiler_extensions_attribute_and_declspec(self):
        src = """
        void __attribute__((noreturn)) fatal_error(const char *msg) {}
        int __declspec(dllexport) add_export(int a, int b) { return a + b; }
        """
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        names = [f.name for f in ctx.functions]
        self.assertIn("fatal_error", names)
        self.assertIn("add_export", names)

    def test_typedef_struct_and_arrays(self):
        src = """
        typedef struct {
            int x;
            int y;
        } Point;

        void draw_matrix(void) {
            Point grid[10][20];
            Point *p = &grid[0][0];
        }
        """
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        fn = ctx.functions[0]
        self.assertIn("grid", fn.variables)
        self.assertIn("p", fn.variables)
        self.assertTrue(fn.variables["p"].is_pointer)

    def test_function_pointers_in_parameters_and_variables(self):
        src = """
        int execute_callback(int (*callback)(int, char *), char *data) {
            int (*local_fp)(int) = 0;
            return callback(10, data);
        }
        """
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        fn = ctx.functions[0]
        self.assertEqual(fn.name, "execute_callback")
        self.assertTrue(fn.parameters[0].is_pointer)
        self.assertIn("local_fp", fn.variables)
        local_fp = fn.variables["local_fp"]
        self.assertTrue(local_fp.is_pointer)

    def test_complex_declarations_and_qualifiers(self):
        src = """
        void process_hw(void) {
            const volatile uint32_t *reg;
            int *p, q, **pp;
        }
        """
        ctx = self.parser.parse(src)
        fn = ctx.functions[0]
        reg_var = fn.variables["reg"]
        self.assertTrue(reg_var.is_volatile)
        self.assertTrue(reg_var.is_pointer)

        p_var = fn.variables["p"]
        q_var = fn.variables["q"]
        pp_var = fn.variables["pp"]
        self.assertTrue(p_var.is_pointer)
        self.assertFalse(q_var.is_pointer)
        self.assertTrue(pp_var.is_pointer)

    def test_standard_unsigned_typedefs_signedness(self):
        from cgull.ast_analyzer import is_unsigned_type
        self.assertTrue(is_unsigned_type("size_t"))
        self.assertTrue(is_unsigned_type("uint8_t"))
        self.assertTrue(is_unsigned_type("uint32_t"))
        self.assertTrue(is_unsigned_type("uintptr_t"))
        self.assertTrue(is_unsigned_type("unsigned int"))
        self.assertFalse(is_unsigned_type("int"))
        self.assertFalse(is_unsigned_type("ssize_t"))
        self.assertFalse(is_unsigned_type("int32_t"))
        self.assertFalse(is_unsigned_type("wint_t"))

        src = """
        typedef unsigned long my_custom_size_t;
        void memset_test(uint8_t *ptr, size_t sz, my_custom_size_t c_sz) {
            size_t idx = 0;
            my_custom_size_t c_idx = 0;
        }
        """
        ctx = self.parser.parse(src)
        fn = ctx.functions[0]
        self.assertFalse(fn.variables["idx"].is_signed)
        self.assertFalse(fn.variables["c_idx"].is_signed)

    def test_multi_declarator_and_fn_ptr_typedef_extraction(self):
        from unittest.mock import patch
        src = """
        typedef unsigned int u32, *pu32;
        typedef uint8_t (*func_ptr_t)(int a, int b);
        """
        # Test in regex fallback mode specifically
        with patch.object(self.parser, "_try_pycparser", return_value=(None, False)):
            ctx = self.parser.parse(src)
            self.assertIn("u32", ctx.unsigned_typedefs)
            self.assertIn("pu32", ctx.unsigned_typedefs)
            self.assertIn("func_ptr_t", ctx.unsigned_typedefs)

    def test_multiline_function_headers_and_declarations(self):
        src = """
        int
        multi_line_fn(
            int x,
            char *msg
        ) {
            int
                a = 1,
                b = 2;
            return x + a + b;
        }
        """
        ctx = self.parser.parse(src)
        fn = ctx.functions[0]
        self.assertEqual(fn.name, "multi_line_fn")
        self.assertEqual(len(fn.parameters), 2)
        self.assertIn("a", fn.variables)
        self.assertIn("b", fn.variables)

    def test_nested_expressions_and_cfg_nodes(self):
        src = """
        int compute(int **pp, int a, int b) {
            int result = *(*(pp + 1)) + (a * (b + 3));
            return result;
        }
        """
        ctx = self.parser.parse(src)
        fn = ctx.functions[0]
        self.assertGreater(len(fn.cfg_nodes), 0)
        result_var = fn.variables["result"]
        self.assertTrue(result_var.has_initializer)


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

@unittest.skipUnless(
    _pycparser_available() and _pcpp_available(),
    "pycparser and pcpp both required"
)
class TestPcppPreprocessing(unittest.TestCase):
    """Tests for the pcpp-based preprocessing tier in the AST pipeline."""

    def setUp(self):
        self.parser = CASTParser()

    def test_define_macro_expands_for_pycparser(self):
        """#define SIZE 128 → char buf[SIZE] should parse as fixed array, not VLA."""
        src = "#define SIZE 128\nvoid f(void) {\n    char buf[SIZE];\n}"
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        fn = ctx.functions[0]
        self.assertIn("buf", fn.variables)
        self.assertFalse(fn.variables["buf"].is_vla)
        self.assertEqual(fn.variables["buf"].array_size_expr, "128")

    def test_define_type_alias_expands_for_pycparser(self):
        """#define TYPE int → TYPE add(TYPE a, TYPE b) should use pycparser."""
        src = "#define TYPE int\nTYPE add(TYPE a, TYPE b) {\n    return a + b;\n}"
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        self.assertEqual(len(ctx.functions), 1)
        self.assertEqual(ctx.functions[0].name, "add")

    def test_ifdef_includes_defined_block(self):
        """#ifdef FEATURE with #define FEATURE should include the block."""
        src = (
            "#define FEATURE\n"
            "#ifdef FEATURE\n"
            "void feature_fn(void) { }\n"
            "#endif\n"
        )
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        names = [f.name for f in ctx.functions]
        self.assertIn("feature_fn", names)

    def test_ifdef_excludes_undefined_block(self):
        """#ifdef MISSING (without #define) should exclude the block."""
        src = (
            "#ifdef MISSING\n"
            "void missing_fn(void) { }\n"
            "#endif\n"
            "void present_fn(void) { }\n"
        )
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        names = [f.name for f in ctx.functions]
        self.assertNotIn("missing_fn", names)
        self.assertIn("present_fn", names)

    def test_line_numbers_preserved_after_preprocessing(self):
        """Line numbers in the AST model should map back to original source."""
        src = (
            "#define SIZE 64\n"       # line 1
            "\n"                       # line 2
            "void process(void) {\n"   # line 3
            "    char buf[SIZE];\n"     # line 4
            "}\n"                      # line 5
        )
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        fn = ctx.functions[0]
        self.assertEqual(fn.name, "process")
        # Function should start at line 3 (after #define and blank line)
        self.assertEqual(fn.start_line, 3)

    def test_function_like_macro_expands(self):
        """Function-like macros (e.g. MAX(a,b)) should expand."""
        src = (
            "#define MAX(a,b) ((a) > (b) ? (a) : (b))\n"
            "int f(void) {\n"
            "    int x = MAX(10, 20);\n"
            "    return x;\n"
            "}\n"
        )
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        fn = ctx.functions[0]
        self.assertIn("x", fn.variables)
        self.assertTrue(fn.variables["x"].has_initializer)

    def test_include_not_found_does_not_crash(self):
        """#include for unavailable headers should not crash preprocessing."""
        src = (
            "#include <nonexistent_header.h>\n"
            "void f(void) { }\n"
        )
        ctx = self.parser.parse(src)
        # Should still parse (pcpp passes through the #include, which then
        # gets stripped before pycparser sees it)
        self.assertEqual(len(ctx.functions), 1)
        self.assertEqual(ctx.functions[0].name, "f")

    def test_multiline_macro_call_does_not_cause_line_drift(self):
        """Multi-line function-like macro calls must not shift reported line numbers of subsequent code."""
        src = (
            "#define LOG(fmt, ...) printf(fmt, __VA_ARGS__)\n"  # line 1
            "\n"                                                # line 2
            "void test(void) {\n"                               # line 3
            "    int x = 1;\n"                                  # line 4
            "    LOG(\n"                                        # line 5
            "        \"%d %d %d\",\n"                             # line 6
            "        1,\n"                                      # line 7
            "        2,\n"                                      # line 8
            "        3\n"                                       # line 9
            "    );\n"                                          # line 10
            "    int *p = malloc(10);\n"                        # line 11
            "}\n"                                               # line 12
        )
        ctx = self.parser.parse(src)
        self.assertTrue(ctx.has_pycparser)
        self.assertEqual(ctx.parse_tier, "pcpp+pycparser")
        fn = ctx.functions[0]
        self.assertEqual(fn.name, "test")
        self.assertEqual(fn.start_line, 3)
        self.assertEqual(fn.end_line, 12)
        self.assertIn("p", fn.variables)
        self.assertEqual(fn.variables["p"].declaration_line, 11)
        malloc_calls = [call for call in fn.calls if call[0] == "malloc"]
        self.assertEqual(len(malloc_calls), 1)
        self.assertEqual(malloc_calls[0][1], 11)


class TestPreprocessorConditionalResolution(unittest.TestCase):
    """Direct tests for eval_preprocessor_expr and resolve_preprocessor_conditionals."""

    def test_eval_preprocessor_expr(self):
        from cgull.ast_analyzer import eval_preprocessor_expr
        self.assertFalse(eval_preprocessor_expr("defined(FOO)"))
        self.assertTrue(eval_preprocessor_expr("!defined(FOO)"))
        self.assertTrue(eval_preprocessor_expr("defined(FOO)", {"FOO"}))
        self.assertFalse(eval_preprocessor_expr("!defined(FOO)", {"FOO"}))
        self.assertTrue(eval_preprocessor_expr("1"))
        self.assertFalse(eval_preprocessor_expr("0"))
        self.assertTrue(eval_preprocessor_expr("!defined(A) && !defined(B)"))
        self.assertFalse(eval_preprocessor_expr("defined(A) || defined(B)"))
        self.assertFalse(eval_preprocessor_expr("UNDEFINED_SYM > 2"))

    def test_resolve_ifdef_else_strips_untaken_branch(self):
        from cgull.ast_analyzer import resolve_preprocessor_conditionals
        src = (
            "#ifdef _WIN32\n"
            "int foo(void) { return 1; }\n"
            "#else\n"
            "int foo(void) { return 2; }\n"
            "#endif"
        )
        res = resolve_preprocessor_conditionals(src)
        self.assertEqual(res.count('\n'), src.count('\n'))
        self.assertNotIn("return 1", res)
        self.assertIn("return 2", res)

    def test_resolve_ifndef_preserves_taken_branch(self):
        from cgull.ast_analyzer import resolve_preprocessor_conditionals
        src = (
            "#ifndef UNSET_MACRO\n"
            "int active_fn(void) { return 10; }\n"
            "#else\n"
            "int inactive_fn(void) { return 20; }\n"
            "#endif"
        )
        res = resolve_preprocessor_conditionals(src)
        self.assertEqual(res.count('\n'), src.count('\n'))
        self.assertIn("active_fn", res)
        self.assertNotIn("inactive_fn", res)

    def test_resolve_elif_chain(self):
        from cgull.ast_analyzer import resolve_preprocessor_conditionals
        src = (
            "#if defined(OPT_A)\n"
            "int val = 1;\n"
            "#elif defined(OPT_B)\n"
            "int val = 2;\n"
            "#elif !defined(OPT_C)\n"
            "int val = 3;\n"
            "#else\n"
            "int val = 4;\n"
            "#endif\n"
        )
        res = resolve_preprocessor_conditionals(src)
        self.assertNotIn("val = 1;", res)
        self.assertNotIn("val = 2;", res)
        self.assertIn("val = 3;", res)
        self.assertNotIn("val = 4;", res)

    def test_resolve_nested_conditionals(self):
        from cgull.ast_analyzer import resolve_preprocessor_conditionals
        src = (
            "#ifndef UNSET\n"
            "  #ifdef NESTED_UNSET\n"
            "    int a = 1;\n"
            "  #else\n"
            "    int b = 2;\n"
            "  #endif\n"
            "#else\n"
            "  int c = 3;\n"
            "#endif\n"
        )
        res = resolve_preprocessor_conditionals(src)
        self.assertNotIn("int a = 1;", res)
        self.assertIn("int b = 2;", res)
        self.assertNotIn("int c = 3;", res)

    def test_resolve_multiline_directives(self):
        from cgull.ast_analyzer import resolve_preprocessor_conditionals
        src = (
            "#if defined(FOO) \\\n"
            "    || defined(BAR)\n"
            "int x = 1;\n"
            "#else\n"
            "int x = 2;\n"
            "#endif"
        )
        res = resolve_preprocessor_conditionals(src)
        self.assertEqual(res.count('\n'), src.count('\n'))
        self.assertNotIn("int x = 1;", res)
        self.assertIn("int x = 2;", res)

    def test_resolve_in_file_define_and_undef(self):
        from cgull.ast_analyzer import resolve_preprocessor_conditionals
        src = (
            "#define IN_FILE_DEF\n"
            "#ifdef IN_FILE_DEF\n"
            "int x = 100;\n"
            "#endif\n"
            "#undef IN_FILE_DEF\n"
            "#ifdef IN_FILE_DEF\n"
            "int y = 200;\n"
            "#endif\n"
        )
        res = resolve_preprocessor_conditionals(src)
        self.assertIn("int x = 100;", res)
        self.assertNotIn("int y = 200;", res)

    def test_operator_precedence(self):
        from cgull.ast_analyzer import eval_preprocessor_expr
        # !defined(X) == 0 -> (!0) == 0 -> 1 == 0 -> 0 (False)
        self.assertFalse(eval_preprocessor_expr("!defined(X) == 0"))
        # A & B == 0 (with A=2, B=0) -> 2 & (0 == 0) -> 2 & 1 -> 0 (False)
        self.assertFalse(eval_preprocessor_expr("A & B == 0", {"A": 2, "B": 0}))
        # (A & B) == 0 (with A=2, B=0) -> (2 & 0) == 0 -> 0 == 0 -> 1 (True)
        self.assertTrue(eval_preprocessor_expr("(A & B) == 0", {"A": 2, "B": 0}))

    def test_macro_value_evaluation(self):
        from cgull.ast_analyzer import resolve_preprocessor_conditionals
        src1 = (
            "#define FOO 0\n"
            "#if FOO\n"
            "int x = 1;\n"
            "#else\n"
            "int x = 2;\n"
            "#endif\n"
        )
        res1 = resolve_preprocessor_conditionals(src1)
        self.assertNotIn("int x = 1;", res1)
        self.assertIn("int x = 2;", res1)

        src2 = (
            "#define FOO 3\n"
            "#if FOO > 2\n"
            "int x = 1;\n"
            "#else\n"
            "int x = 2;\n"
            "#endif\n"
        )
        res2 = resolve_preprocessor_conditionals(src2)
        self.assertIn("int x = 1;", res2)
        self.assertNotIn("int x = 2;", res2)

    def test_integer_suffixes(self):
        from cgull.ast_analyzer import eval_preprocessor_expr
        self.assertTrue(eval_preprocessor_expr("__STDC_VERSION__ >= 201112L", {"__STDC_VERSION__": 201112}))
        self.assertTrue(eval_preprocessor_expr("1U"))
        self.assertFalse(eval_preprocessor_expr("0UL"))
        self.assertTrue(eval_preprocessor_expr("0x10U == 16"))

    def test_dos_protection_large_shift(self):
        from cgull.ast_analyzer import eval_preprocessor_expr
        # Should execute instantly without DoS / OOM
        res = eval_preprocessor_expr("1 << 100000000")
        self.assertIsInstance(res, bool)


@unittest.skipUnless(_pycparser_available(), "pycparser not installed")
class TestPcppFallback(unittest.TestCase):
    """Tests that the directive-stripping tier works when pcpp is absent."""

    def test_parse_works_without_pcpp(self):
        """Even if _try_pcpp_preprocess returns None, pycparser tier 2 works."""
        from unittest.mock import patch
        parser = CASTParser()
        with patch.object(CASTParser, "_try_pcpp_preprocess", return_value=None):
            src = "int add(int a, int b) {\n    return a + b;\n}"
            ctx = parser.parse(src)
            self.assertTrue(ctx.has_pycparser)
            self.assertEqual(ctx.functions[0].name, "add")

    def test_tier2_duplicate_symbol_ifdef_else_parses_successfully(self):
        """
        Regression test: duplicate function definitions in #ifdef/#else branches
        must resolve in Tier 2 so pycparser parses the taken branch without errors.
        """
        from unittest.mock import patch
        src = (
            "#ifdef _WIN32\n"
            "int target_func(char *dest, const char *src) {\n"
            "    return 1;\n"
            "}\n"
            "#else\n"
            "int target_func(char *dest, const char *src) {\n"
            "    strcpy(dest, src);\n"
            "    return 0;\n"
            "}\n"
            "#endif\n"
        )
        parser = CASTParser()
        with patch.object(CASTParser, "_try_pcpp_preprocess", return_value=None):
            ctx = parser.parse(src)
            self.assertTrue(ctx.has_pycparser)
            self.assertEqual(ctx.parse_tier, "directive-stripped")
            self.assertEqual(len(ctx.functions), 1)
            fn = ctx.functions[0]
            self.assertEqual(fn.name, "target_func")
            self.assertEqual(len(fn.calls), 1)
            self.assertEqual(fn.calls[0][0], "strcpy")


class TestParseTiers(unittest.TestCase):
    def test_regex_fallback_parse_tier(self):
        from unittest.mock import patch
        parser = CASTParser()
        with patch.object(parser, "_try_pycparser", return_value=(None, False, "regex-fallback")):
            ctx = parser.parse("int main(void) { return 0; }")
            self.assertEqual(ctx.parse_tier, "regex-fallback")

    @unittest.skipUnless(_pycparser_available(), "pycparser required")
    def test_directive_stripped_parse_tier(self):
        from unittest.mock import patch
        parser = CASTParser()
        with patch.object(parser, "_try_pcpp_preprocess", return_value=None):
            ctx = parser.parse("int main(void) { return 0; }")
            self.assertEqual(ctx.parse_tier, "directive-stripped")

    @unittest.skipUnless(_pycparser_available() and _pcpp_available(), "pycparser and pcpp required")
    def test_pcpp_pycparser_parse_tier(self):
        parser = CASTParser()
        ctx = parser.parse("int main(void) { return 0; }")
        self.assertEqual(ctx.parse_tier, "pcpp+pycparser")

    @unittest.skipUnless(_pcpp_available(), "pcpp required")
    def test_pcpp_defined_syms_injection_types(self):
        parser = CASTParser()

        # Presence macro, value macro, and false/undef macro
        defined_syms_dict = {
            "FEATURE_PRESENCE": None,
            "FEATURE_VALUE": 42,
            "FEATURE_UNDEF": False,
        }
        res_dict = parser._try_pcpp_preprocess(
            "#ifdef FEATURE_PRESENCE\nint presence_enabled;\n#endif\n"
            "#if FEATURE_PRESENCE\nint presence_if_enabled;\n#endif\n"
            "#if FEATURE_VALUE == 42\nint value_matched;\n#endif\n"
            "#ifdef FEATURE_UNDEF\nint undef_should_not_appear;\n#endif\n",
            defined_syms=defined_syms_dict,
        )
        self.assertIsNotNone(res_dict)
        self.assertIn("int presence_enabled;", res_dict)
        self.assertIn("int presence_if_enabled;", res_dict)
        self.assertIn("int value_matched;", res_dict)
        self.assertNotIn("int undef_should_not_appear;", res_dict)

        # Sequence of presence flags with #if evaluation
        defined_syms_seq = ["FLAG_A", "FLAG_B"]
        res_seq = parser._try_pcpp_preprocess(
            "#if FLAG_A && FLAG_B\nint seq_flags_active;\n#endif\n",
            defined_syms=defined_syms_seq,
        )
        self.assertIsNotNone(res_seq)
        self.assertIn("int seq_flags_active;", res_seq)

    def test_cvariable_and_cparameter_is_array_and_typedefs(self):
        code = """
        typedef int IntArray[10];

        IntArray global_typedef_arr;
        int global_scalar = 10;
        int global_arr[5];

        int sum_table(IntArray param_typedef_arr, int param_arr[], int param_scalar) {
            int total = 0;
            int local_arr[10];
            IntArray local_typedef_arr;
            for (int i = 0; i < 4; i++) {
                total += 1;
            }
            return total + local_arr[0] + global_arr[0] + global_scalar + local_typedef_arr[0] + global_typedef_arr[0] + param_typedef_arr[0] + param_arr[0] + param_scalar;
        }
        """
        # Test AST mode
        parser = CASTParser()
        ctx_ast = parser.parse(code)
        self.assertTrue(ctx_ast.has_pycparser)
        fn_ast = ctx_ast.functions[0]
        self.assertFalse(fn_ast.variables["total"].is_array)
        self.assertTrue(fn_ast.variables["local_arr"].is_array)
        self.assertTrue(fn_ast.variables["local_typedef_arr"].is_array)
        self.assertFalse(ctx_ast.global_variables["global_scalar"].is_array)
        self.assertTrue(ctx_ast.global_variables["global_arr"].is_array)
        self.assertTrue(ctx_ast.global_variables["global_typedef_arr"].is_array)

        params = {p.name: p for p in fn_ast.parameters}
        self.assertTrue(params["param_typedef_arr"].is_array)
        self.assertTrue(params["param_arr"].is_array)
        self.assertFalse(params["param_scalar"].is_array)

        # Test Regex fallback mode
        with patch.object(parser, "_try_pycparser", return_value=(None, False, "regex-fallback")):
            ctx_regex = parser.parse(code)
            fn_regex = ctx_regex.functions[0]
            self.assertFalse(fn_regex.variables["total"].is_array)
            self.assertTrue(fn_regex.variables["local_arr"].is_array)
            self.assertTrue(fn_regex.variables["local_typedef_arr"].is_array)
            self.assertFalse(ctx_regex.global_variables["global_scalar"].is_array)
            self.assertTrue(ctx_regex.global_variables["global_arr"].is_array)
            self.assertTrue(ctx_regex.global_variables["global_typedef_arr"].is_array)


if __name__ == "__main__":
    unittest.main()
