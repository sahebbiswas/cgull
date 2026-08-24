import tempfile
import unittest
from pathlib import Path
import json

from cgull import parse_compile_commands, find_compile_commands, parse_config_seeds, ConfigProfile
from cgull.cli import build_parser, handle_scan


class TestCompileCommandsIngestion(unittest.TestCase):
    def test_measurable_outcome_fixture_compile_commands(self):
        """
        Measurable outcome test:
        Fixture compile_commands.json with entries for 3 files using 2 distinct -D combinations
        produces exactly 2 ConfigProfiles with correctly parsed macro values, including a
        value-bearing flag (-DRETRY_COUNT=5) parsed into the schema's value-macro form.
        """
        cc_data = [
            {
                "directory": "/build",
                "command": "gcc -c -DDEBUG -DRETRY_COUNT=5 file1.c",
                "file": "file1.c"
            },
            {
                "directory": "/build",
                "command": "gcc -c -DDEBUG -DRETRY_COUNT=5 file2.c",
                "file": "file2.c"
            },
            {
                "directory": "/build",
                "arguments": ["gcc", "-c", "-DRELEASE", "-DMAX_BUF=1024", "file3.c"],
                "file": "file3.c"
            }
        ]

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", prefix="compile_commands_", delete=False) as tf:
            json.dump(cc_data, tf)
            temp_path = tf.name

        try:
            profiles = parse_compile_commands(temp_path)

            self.assertEqual(len(profiles), 2)

            p1 = profiles[0]
            self.assertIn("DEBUG", p1.flags)
            self.assertIsNone(p1.flags["DEBUG"])
            self.assertIn("RETRY_COUNT", p1.flags)
            self.assertEqual(p1.flags["RETRY_COUNT"], 5)
            self.assertIsInstance(p1.flags["RETRY_COUNT"], int)
            self.assertIn("DEBUG", p1.name)
            self.assertIn("RETRY_COUNT=5", p1.name)
            self.assertNotIn("file1", p1.name)
            self.assertNotIn("file2", p1.name)

            p2 = profiles[1]
            self.assertIn("RELEASE", p2.flags)
            self.assertIsNone(p2.flags["RELEASE"])
            self.assertIn("MAX_BUF", p2.flags)
            self.assertEqual(p2.flags["MAX_BUF"], 1024)
            self.assertIsInstance(p2.flags["MAX_BUF"], int)
            self.assertIn("MAX_BUF=1024", p2.name)
            self.assertNotIn("file3", p2.name)

        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_command_string_and_undef_parsing(self):
        """
        Tests parsing -D, -U, and quoted value flags from a command line string.
        """
        cc_data = [
            {
                "directory": "/build",
                "command": 'clang -DENABLE_SSL -DFOO=bar -UOLD_FLAG -DVERSION="1.0" -DHEX_VAL=0x10 main.c',
                "file": "main.c"
            }
        ]

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tf:
            json.dump(cc_data, tf)
            temp_path = tf.name

        try:
            profiles = parse_compile_commands(temp_path)
            self.assertEqual(len(profiles), 1)

            flags = profiles[0].flags
            self.assertIsNone(flags["ENABLE_SSL"])
            self.assertEqual(flags["FOO"], "bar")
            self.assertIs(flags["OLD_FLAG"], False)
            self.assertEqual(flags["VERSION"], "1.0")
            self.assertEqual(flags["HEX_VAL"], 16)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_separated_space_flags(self):
        """
        Tests parsing arguments array with space-separated -D and -U options.
        """
        cc_data = [
            {
                "directory": "/build",
                "arguments": ["gcc", "-D", "DEBUG", "-D", "RETRY_COUNT=10", "-U", "DEPRECATED", "main.c"],
                "file": "main.c"
            }
        ]

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tf:
            json.dump(cc_data, tf)
            temp_path = tf.name

        try:
            profiles = parse_compile_commands(temp_path)
            self.assertEqual(len(profiles), 1)

            flags = profiles[0].flags
            self.assertIsNone(flags["DEBUG"])
            self.assertEqual(flags["RETRY_COUNT"], 10)
            self.assertIs(flags["DEPRECATED"], False)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_auto_detection_walking_up_directories(self):
        """
        Tests that find_compile_commands locates compile_commands.json by searching upward
        from nested target directories.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            root_dir = Path(temp_dir)
            nested_dir = root_dir / "src" / "sub" / "module"
            nested_dir.mkdir(parents=True, exist_ok=True)

            cc_path = root_dir / "compile_commands.json"
            cc_path.write_text("[]", encoding="utf-8")

            found_path = find_compile_commands(str(nested_dir))
            self.assertIsNotNone(found_path)
            self.assertEqual(Path(found_path).resolve(), cc_path.resolve())

    def test_parse_config_seeds_dispatches_compile_commands(self):
        """
        Tests that parse_config_seeds dispatches compile_commands.json files to parse_compile_commands.
        """
        cc_data = [
            {
                "directory": "/build",
                "arguments": ["gcc", "-c", "-DTEST_MACRO=1", "test.c"],
                "file": "test.c"
            }
        ]
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", prefix="compile_commands_", delete=False) as tf:
            json.dump(cc_data, tf)
            temp_path = tf.name

        try:
            profiles = parse_config_seeds(temp_path)
            self.assertEqual(len(profiles), 1)
            self.assertEqual(profiles[0].flags["TEST_MACRO"], 1)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_invalid_compile_commands_structure(self):
        """
        Tests that top-level non-array structure raises ValueError.
        """
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tf:
            tf.write('{"key": "value"}')
            temp_path = tf.name

        try:
            with self.assertRaises(ValueError) as cm:
                parse_compile_commands(temp_path)
            self.assertIn("top-level JSON must be an array", str(cm.exception))
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_cli_compile_commands_argument(self):
        """
        Tests CLI parser and handle_scan with --compile-commands flag.
        """
        parser = build_parser()
        args = parser.parse_args(["scan", "--compile-commands", "build/compile_commands.json", "."])
        self.assertEqual(args.compile_commands, "build/compile_commands.json")

    def test_cli_compile_commands_nonexistent_file_error(self):
        """
        Tests that specifying a non-existent --compile-commands file returns status code 1.
        """
        parser = build_parser()
        args = parser.parse_args(["scan", "--compile-commands", "non_existent_compile_commands.json", "."])
        ret = handle_scan(args)
        self.assertEqual(ret, 1)


if __name__ == "__main__":
    unittest.main()
