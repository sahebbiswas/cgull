import tempfile
import unittest
from pathlib import Path
import logging

from cgull import parse_config_seed, ConfigProfile
from cgull.cli import build_parser


class TestConfigSeedIngestion(unittest.TestCase):
    def test_object_macro_with_parens(self):
        """
        Tests that object-like macros with parenthesized values (e.g. #define FOO (1 + 2))
        are parsed as value macros rather than mis-identified as function-like macros.
        """
        seed_content = """
#define PAREN_VAL (1 + 2)
"""
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".h", delete=False) as tf:
            tf.write(seed_content)
            temp_path = tf.name

        try:
            profile = parse_config_seed(temp_path)
            self.assertIn("PAREN_VAL", profile.flags)
            self.assertEqual(profile.flags["PAREN_VAL"], "(1 + 2)")
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_fixture_seed_header_parsing(self):
        """
        Measurable outcome test:
        Fixture seed header with 4 #defines (2 bare, 1 valued, 1 function-like)
        parses to a ConfigProfile with exactly the 3 supported macros and a logged
        skip for the 4th.
        """
        seed_content = """// config_debug.h - Sample configuration seed
#define FEATURE_SSL
#define FEATURE_ZLIB
#define MAX_BUFFER_SIZE 1024
#define MIN(a, b) ((a) < (b) ? (a) : (b))
"""
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".h", prefix="config_debug_", delete=False) as tf:
            tf.write(seed_content)
            temp_path = tf.name

        try:
            with self.assertLogs("cgull.ast_analyzer", level="WARNING") as cm:
                profile = parse_config_seed(temp_path)

            self.assertEqual(profile.name, Path(temp_path).stem)
            self.assertEqual(len(profile.flags), 3)
            self.assertIn("FEATURE_SSL", profile.flags)
            self.assertIsNone(profile.flags["FEATURE_SSL"])
            self.assertIn("FEATURE_ZLIB", profile.flags)
            self.assertIsNone(profile.flags["FEATURE_ZLIB"])
            self.assertEqual(profile.flags["MAX_BUFFER_SIZE"], 1024)
            self.assertNotIn("MIN", profile.flags)

            # Check that function-like macro MIN was logged as skipped
            self.assertTrue(any("MIN" in log_msg for log_msg in cm.output))
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_undef_directive_parsing(self):
        """
        Tests that #undef NAME lines in a seed header set the macro flag to False.
        """
        seed_content = """
#define ENABLE_SSL
#undef ENABLE_DEPRECATED_API
"""
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".h", delete=False) as tf:
            tf.write(seed_content)
            temp_path = tf.name

        try:
            profile = parse_config_seed(temp_path)
            self.assertIn("ENABLE_SSL", profile.flags)
            self.assertIsNone(profile.flags["ENABLE_SSL"])
            self.assertIn("ENABLE_DEPRECATED_API", profile.flags)
            self.assertIs(profile.flags["ENABLE_DEPRECATED_API"], False)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_config_name_comment_header_override(self):
        """
        Tests that '// cgull-config-name: custom_name' on the first line overrides
        the filename stem.
        """
        seed_content = """// cgull-config-name: release_hardened
#define OPTIMIZE 3
#define NDEBUG
"""
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".h", prefix="generic_name_", delete=False) as tf:
            tf.write(seed_content)
            temp_path = tf.name

        try:
            profile = parse_config_seed(temp_path)
            self.assertEqual(profile.name, "release_hardened")
            self.assertEqual(profile.flags["OPTIMIZE"], 3)
            self.assertIsNone(profile.flags["NDEBUG"])
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_name_override_parameter(self):
        """
        Tests that explicit name_override parameter takes precedence over stem and comment header.
        """
        seed_content = """// cgull-config-name: header_name
#define FOO 1
"""
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".h", delete=False) as tf:
            tf.write(seed_content)
            temp_path = tf.name

        try:
            profile = parse_config_seed(temp_path, name_override="param_override")
            self.assertEqual(profile.name, "param_override")
            self.assertEqual(profile.flags["FOO"], 1)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_cli_config_seed_argument(self):
        """
        Tests that --config-seed argument is recognized in the scan subcommand CLI parser.
        """
        parser = build_parser()
        args = parser.parse_args(["scan", "--config-seed", "seed1.h", "--config-seed", "seed2.h", "src/"])
        self.assertEqual(args.config_seed, ["seed1.h", "seed2.h"])


if __name__ == "__main__":
    unittest.main()
