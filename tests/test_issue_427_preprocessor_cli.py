"""Regression coverage for issue #427's preprocessor CLI."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest

from cgull.cli import build_parser, main


class TestPreprocessorCLI(unittest.TestCase):
    def _run(self, argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_parser_exposes_preprocessor_command(self):
        args = build_parser().parse_args(["preprocessor", "source.c", "--json"])
        self.assertEqual(args.command, "preprocessor")
        self.assertEqual(args.target, "source.c")
        self.assertTrue(args.json)

    def test_default_filters_unchanged_and_reports_interesting_entries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "sample.c")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(
                    "#if A\n"
                    "int first;\n"
                    "#elif A\n"
                    "int dead;\n"
                    "#endif\n"
                    "#if B || (B && C)\n"
                    "int simple;\n"
                    "#endif\n"
                    "#if CLEAN\n"
                    "int unchanged;\n"
                    "#endif\n"
                )

            code, out, err = self._run(["preprocessor", path])

        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[DEAD] #elif A", out)
        self.assertIn("[SIMPLIFIED] #if B || (B && C)", out)
        self.assertIn("simplified: B", out)
        self.assertNotIn("#if CLEAN", out)
        self.assertNotIn("[UNCHANGED]", out)

    def test_verbose_includes_unchanged_structural_entries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "sample.hpp")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("#if FEATURE\nint enabled;\n#else\nint disabled;\n#endif\n")

            code, out, err = self._run(["preprocessor", path, "--verbose"])

        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertIn("[UNCHANGED] #if FEATURE", out)
        self.assertIn("[UNCHANGED] #else", out)
        self.assertIn("reachability: reachable", out)

    def test_json_schema_is_structured_filtered_and_color_free(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "sample.c")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write(
                    "#if A\n"
                    "int first;\n"
                    "#elif A\n"
                    "int dead;\n"
                    "#endif\n"
                )

            code, out, err = self._run(["preprocessor", path, "--json"])

        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertNotIn("\x1b[", out)
        payload = json.loads(out)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(len(payload["files"]), 1)
        entries = payload["files"][0]["entries"]
        self.assertEqual([entry["status"] for entry in entries], ["dead"])
        entry = entries[0]
        self.assertEqual(entry["reachability"], "unreachable")
        self.assertEqual(entry["original_condition"], "A")
        self.assertIn("context_condition", entry)
        self.assertIn("effective_condition", entry)
        self.assertEqual(payload["summary"]["entries"], 2)
        self.assertEqual(payload["summary"]["unchanged"], 1)

    def test_json_verbose_includes_unchanged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "sample.c")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("#if A\nint x;\n#endif\n")

            code, out, _ = self._run(
                ["preprocessor", path, "--json", "--verbose"]
            )

        self.assertEqual(code, 0)
        entries = json.loads(out)["files"][0]["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "unchanged")

    def test_directory_results_are_deterministically_ordered(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            for name in ("z.cpp", "a.c"):
                with open(os.path.join(temp_dir, name), "w", encoding="utf-8") as stream:
                    stream.write("#if A\nint x;\n#endif\n")
            with open(os.path.join(temp_dir, "ignored.txt"), "w", encoding="utf-8") as stream:
                stream.write("#if A\n#endif\n")

            code, out, err = self._run(
                ["preprocessor", temp_dir, "--json", "--verbose"]
            )

        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        payload = json.loads(out)
        self.assertEqual([item["path"] for item in payload["files"]], ["a.c", "z.cpp"])

    def test_malformed_directive_returns_nonzero_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "broken.c")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("#if\nint x;\n#endif\n")

            code, out, err = self._run(["preprocessor", path])

        self.assertEqual(code, 2)
        self.assertEqual(err, "")
        self.assertIn("[ERROR missing_condition]", out)
        self.assertNotIn("Traceback", out)

    def test_invalid_utf8_returns_nonzero_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "invalid.c")
            with open(path, "wb") as stream:
                stream.write(b"#if A\n\xff\n#endif\n")

            code, out, err = self._run(["preprocessor", path])

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("invalid UTF-8", err)
        self.assertNotIn("Traceback", err)


if __name__ == "__main__":
    unittest.main()
