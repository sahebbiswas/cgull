"""
Tests for cgull.utils: comment/string stripping, string-literal masking,
and inline suppression-comment parsing.
"""

import unittest

import io
from cgull.utils import (
    strip_comments_keep_lines,
    mask_string_and_char_literals,
    is_in_string_or_char_literal,
    SuppressionMap,
    ProgressIndicator,
)


class TestStripCommentsKeepLines(unittest.TestCase):
    def test_line_comment_blanked(self):
        src = "int x = 1; // set x\n"
        lines, code = strip_comments_keep_lines(src)
        self.assertNotIn("set x", code)
        self.assertIn("int x = 1;", code)

    def test_block_comment_blanked(self):
        src = "int x /* inline note */ = 1;\n"
        _, code = strip_comments_keep_lines(src)
        self.assertNotIn("inline note", code)
        self.assertIn("int x", code)
        self.assertIn("= 1;", code)

    def test_multiline_block_comment_preserves_line_count(self):
        src = "a();\n/* start\nmiddle\nend */\nb();\n"
        lines, code = strip_comments_keep_lines(src)
        self.assertEqual(len(src.splitlines()), len(lines))
        self.assertNotIn("middle", code)

    def test_string_contents_preserved(self):
        src = 'char *s = "// not a comment";\n'
        _, code = strip_comments_keep_lines(src)
        self.assertIn("// not a comment", code)

    def test_line_numbers_preserved_after_stripping(self):
        src = "a();\n// comment\nb();\n"
        lines, _ = strip_comments_keep_lines(src)
        self.assertEqual(lines[0], "a();")
        self.assertEqual(lines[2], "b();")

    def test_escaped_quote_inside_string_does_not_end_string(self):
        src = 'char *s = "a \\"quoted\\" b // still string";\n'
        _, code = strip_comments_keep_lines(src)
        # The // inside the string must NOT be treated as a comment start.
        self.assertIn("still string", code)

    def test_column_positions_preserved(self):
        src = "int x = 1; // comment\n"
        lines, _ = strip_comments_keep_lines(src)
        # "int x = 1;" should still start at column 0 (unchanged offset)
        self.assertTrue(lines[0].startswith("int x = 1;"))
        self.assertEqual(len(lines[0]), len(src.rstrip("\n")))


class TestMaskStringAndCharLiterals(unittest.TestCase):
    def test_string_contents_replaced_quotes_preserved(self):
        masked = mask_string_and_char_literals('char *s = "gets()";')
        self.assertNotIn("gets", masked)
        self.assertTrue(masked.count('"') == 2)

    def test_length_preserved(self):
        line = 'char *s = "hello world";'
        masked = mask_string_and_char_literals(line)
        self.assertEqual(len(masked), len(line))

    def test_code_outside_strings_untouched(self):
        line = 'strcpy(dest, "text");'
        masked = mask_string_and_char_literals(line)
        self.assertTrue(masked.startswith("strcpy(dest, "))

    def test_char_literal_masked(self):
        masked = mask_string_and_char_literals("char c = 'x';")
        self.assertIn("'x'", masked)  # single-char literal: x is itself the placeholder-length content -> stays visually similar
        self.assertTrue(masked.startswith("char c = '"))

    def test_no_string_present_unchanged(self):
        line = "int total = a + b;"
        self.assertEqual(mask_string_and_char_literals(line), line)


class TestIsInStringOrCharLiteral(unittest.TestCase):
    def test_position_inside_string_detected(self):
        line = 'char *s = "gets()";'
        idx = line.index("gets")
        self.assertTrue(is_in_string_or_char_literal(line, idx))

    def test_position_outside_string_not_detected(self):
        line = 'gets(buf); // not "in a string"'
        idx = line.index("gets")
        self.assertFalse(is_in_string_or_char_literal(line, idx))

    def test_position_after_closed_string_not_detected(self):
        line = '"first" second'
        idx = line.index("second")
        self.assertFalse(is_in_string_or_char_literal(line, idx))


class TestSuppressionMap(unittest.TestCase):
    def test_no_directives_nothing_suppressed(self):
        sup = SuppressionMap.from_source(["int x = 1;", "int y = 2;"])
        self.assertFalse(sup.is_suppressed(1, "CGULL-001"))

    def test_bare_ignore_suppresses_all_rules_on_line(self):
        sup = SuppressionMap.from_source(["strcpy(a, b); // cgull-ignore"])
        self.assertTrue(sup.is_suppressed(1, "CGULL-001"))
        self.assertTrue(sup.is_suppressed(1, "CGULL-099"))

    def test_specific_rule_ignore_only_suppresses_that_rule(self):
        sup = SuppressionMap.from_source(["strcpy(a, b); // cgull-ignore: CGULL-001"])
        self.assertTrue(sup.is_suppressed(1, "CGULL-001"))
        self.assertFalse(sup.is_suppressed(1, "CGULL-002"))

    def test_multiple_rule_ids_comma_separated(self):
        sup = SuppressionMap.from_source(["x(); // cgull-ignore: CGULL-001,CGULL-003"])
        self.assertTrue(sup.is_suppressed(1, "CGULL-001"))
        self.assertTrue(sup.is_suppressed(1, "CGULL-003"))
        self.assertFalse(sup.is_suppressed(1, "CGULL-002"))

    def test_next_line_directive_suppresses_following_line_only(self):
        sup = SuppressionMap.from_source([
            "// cgull-ignore-next-line: CGULL-001",
            "strcpy(a, b);",
            "strcpy(c, d);",
        ])
        self.assertTrue(sup.is_suppressed(2, "CGULL-001"))
        self.assertFalse(sup.is_suppressed(3, "CGULL-001"))
        self.assertFalse(sup.is_suppressed(1, "CGULL-001"))

    def test_rule_id_matching_is_case_insensitive(self):
        sup = SuppressionMap.from_source(["x(); // cgull-ignore: cgull-001"])
        self.assertTrue(sup.is_suppressed(1, "CGULL-001"))


class TestProgressIndicator(unittest.TestCase):
    def test_progress_indicator_updates_and_finishes(self):
        stream = io.StringIO()
        progress = ProgressIndicator(stream=stream, bar_width=10)
        progress.update(1, 2, "test.c")
        out = stream.getvalue()
        self.assertIn("\rScanning [█████░░░░░] 50% (1/2 files) test.c", out)

        progress.finish()
        final_out = stream.getvalue()
        self.assertTrue(final_out.endswith("\r"))

    def test_progress_indicator_quiet_mode(self):
        stream = io.StringIO()
        progress = ProgressIndicator(stream=stream, quiet=True)
        progress.update(1, 2, "test.c")
        progress.finish()
        self.assertEqual(stream.getvalue(), "")

    def test_progress_indicator_zero_total(self):
        stream = io.StringIO()
        progress = ProgressIndicator(stream=stream)
        progress.update(0, 0, "")
        self.assertIn("100% (0/0 files)", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
