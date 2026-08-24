import tempfile
import unittest
from pathlib import Path
import logging

import os

import json
import io
from unittest.mock import patch
from cgull import parse_config_seed, parse_config_seeds, parse_json_config_seed, ConfigProfile
from cgull.cli import build_parser, handle_scan


class TestConfigSeedIngestion(unittest.TestCase):
    def test_object_macro_with_parens_and_eval(self):
        """
        Tests that object-like macros with parenthesized values or constant expressions
        (e.g., #define FOO (0), #define BAR (1 + 2)) evaluate to integer values.
        """
        seed_content = """
#define FOO (0)
#define BAR (1 + 2)
#define PAREN_VAL (1 << 2)
"""
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".h", delete=False) as tf:
            tf.write(seed_content)
            temp_path = tf.name

        try:
            profile = parse_config_seed(temp_path)
            self.assertEqual(profile.flags["FOO"], 0)
            self.assertEqual(profile.flags["BAR"], 3)
            self.assertEqual(profile.flags["PAREN_VAL"], 4)
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

    def test_directory_config_seed_with_manifest_exclusion(self):
        """
        Measurable outcome test:
        Fixture directory with 3 config headers (one intentionally excluded via .cgullconfigs manifest)
        produces exactly 2 ConfigProfiles with correct names.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create 3 header files
            h1 = Path(temp_dir) / "config_alpha.h"
            h2 = Path(temp_dir) / "config_beta.h"
            h3 = Path(temp_dir) / "config_ignored.h"

            h1.write_text("#define ALPHA_MODE 1\n", encoding="utf-8")
            h2.write_text("#define BETA_MODE 2\n", encoding="utf-8")
            h3.write_text("#define IGNORED_MODE 3\n", encoding="utf-8")

            # Create .cgullconfigs manifest excluding config_ignored.h
            manifest = Path(temp_dir) / ".cgullconfigs"
            manifest.write_text("!config_ignored.h\n", encoding="utf-8")

            profiles = parse_config_seeds(temp_dir)

            self.assertEqual(len(profiles), 2)
            names = [p.name for p in profiles]
            self.assertEqual(names, ["config_alpha", "config_beta"])
            self.assertEqual(profiles[0].flags, {"ALPHA_MODE": 1})
            self.assertEqual(profiles[1].flags, {"BETA_MODE": 2})

    def test_directory_config_seed_manifest_inclusion_order(self):
        """
        Tests that .cgullconfigs manifest explicit inclusions dictate the ordering and selection of profiles.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            h1 = Path(temp_dir) / "config_a.h"
            h2 = Path(temp_dir) / "config_b.h"
            h3 = Path(temp_dir) / "non_config.h"

            h1.write_text("#define A 10\n", encoding="utf-8")
            h2.write_text("#define B 20\n", encoding="utf-8")
            h3.write_text("#define C 30\n", encoding="utf-8")

            manifest = Path(temp_dir) / ".cgullconfigs"
            manifest.write_text("config_b.h\nconfig_a.h\n", encoding="utf-8")

            profiles = parse_config_seeds(temp_dir)

            self.assertEqual(len(profiles), 2)
            self.assertEqual([p.name for p in profiles], ["config_b", "config_a"])

    def test_manifest_path_traversal_rejection(self):
        """
        Tests that .cgullconfigs manifest entries attempting path traversal or escaping the seed directory raise ValueError.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / ".cgullconfigs"
            manifest.write_text("sub/../../x.h\n", encoding="utf-8")

            with self.assertRaises(ValueError) as cm:
                parse_config_seeds(temp_dir)
            self.assertIn("path traversal", str(cm.exception))

    def test_manifest_non_header_rejection(self):
        """
        Tests that .cgullconfigs manifest entries including non-header files raise ValueError.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            txt_file = Path(temp_dir) / "notes.txt"
            txt_file.write_text("some text\n", encoding="utf-8")

            manifest = Path(temp_dir) / ".cgullconfigs"
            manifest.write_text("notes.txt\n", encoding="utf-8")

            with self.assertRaises(ValueError) as cm:
                parse_config_seeds(temp_dir)
            self.assertIn(".h or .hpp", str(cm.exception))

    def test_json_config_seed_parsing(self):
        """
        Tests that a JSON seed file containing multiple named profiles parses
        directly into a list of ConfigProfiles with structured flags.
        """
        json_data = {
            "debug": {
                "DEBUG_LOGS": True,
                "MAX_ATTEMPTS": 5,
                "FEATURE_X": True
            },
            "release": {
                "DEBUG_LOGS": False,
                "OPTIMIZATION_LEVEL": "O3",
                "FEATURE_X": True
            }
        }
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tf:
            json.dump(json_data, tf)
            temp_path = tf.name

        try:
            profiles = parse_config_seeds(temp_path)
            self.assertEqual(len(profiles), 2)
            self.assertEqual(profiles[0].name, "debug")
            self.assertEqual(profiles[0].flags["DEBUG_LOGS"], None)
            self.assertEqual(profiles[0].flags["MAX_ATTEMPTS"], 5)
            self.assertEqual(profiles[0].flags["FEATURE_X"], None)

            self.assertEqual(profiles[1].name, "release")
            self.assertEqual(profiles[1].flags["DEBUG_LOGS"], False)
            self.assertEqual(profiles[1].flags["OPTIMIZATION_LEVEL"], "O3")
            self.assertEqual(profiles[1].flags["FEATURE_X"], None)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_json_seed_cross_check_equality_with_header_seeds(self):
        """
        Measurable outcome test:
        Fixture JSON with 2 profiles produces 2 ConfigProfiles equal (per the schema issue's
        equality rules) to what the equivalent pair of hand-written header seeds produces.
        """
        header_debug_content = """// cgull-config-name: profile_debug
#define FEATURE_SSL
#define FEATURE_ZLIB
#define MAX_BUFFER_SIZE 1024
"""
        header_release_content = """// cgull-config-name: profile_release
#define FEATURE_SSL
#undef FEATURE_ZLIB
#define MAX_BUFFER_SIZE 2048
"""
        json_seed_data = {
            "profile_debug": {
                "FEATURE_SSL": True,
                "FEATURE_ZLIB": True,
                "MAX_BUFFER_SIZE": 1024
            },
            "profile_release": {
                "FEATURE_SSL": True,
                "FEATURE_ZLIB": False,
                "MAX_BUFFER_SIZE": 2048
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            h_debug = Path(temp_dir) / "profile_debug.h"
            h_release = Path(temp_dir) / "profile_release.h"
            json_seed = Path(temp_dir) / "profiles.json"

            h_debug.write_text(header_debug_content, encoding="utf-8")
            h_release.write_text(header_release_content, encoding="utf-8")
            json_seed.write_text(json.dumps(json_seed_data), encoding="utf-8")

            # Parse headers directly
            header_profile_debug = parse_config_seed(str(h_debug))
            header_profile_release = parse_config_seed(str(h_release))

            # Parse JSON seed
            json_profiles = parse_json_config_seed(str(json_seed))

            self.assertEqual(len(json_profiles), 2)
            # Cross-check equality using ConfigProfile.__eq__
            self.assertEqual(json_profiles[0], header_profile_debug)
            self.assertEqual(json_profiles[1], header_profile_release)

    def test_json_config_seed_invalid_structure(self):
        """
        Tests that invalid JSON structures (e.g. non-dict top-level or non-dict profiles) raise ValueError.
        """
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tf:
            tf.write("[1, 2, 3]")
            temp_path = tf.name

        try:
            with self.assertRaises(ValueError) as cm:
                parse_json_config_seed(temp_path)
            self.assertIn("top-level JSON must be an object", str(cm.exception))
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_json_config_seed_invalid_macro_names(self):
        """
        Tests that keys in JSON seed profiles that are not valid C preprocessor identifiers raise ValueError.
        """
        invalid_keys = ["BAD-NAME", "123", "HAS SPACE", "a.b"]
        for key in invalid_keys:
            json_data = {"profile1": {key: True}}
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tf:
                json.dump(json_data, tf)
                temp_path = tf.name

            try:
                with self.assertRaises(ValueError) as cm:
                    parse_json_config_seed(temp_path)
                self.assertIn("Invalid preprocessor identifier", str(cm.exception))
                self.assertIn(key, str(cm.exception))
            finally:
                Path(temp_path).unlink(missing_ok=True)

    def test_json_config_seed_unsupported_value_types(self):
        """
        Tests that unsupported value types in JSON seed profiles (e.g. floats, lists, dicts) raise ValueError.
        """
        unsupported_values = [12.34, [1, 2], {"nested": "obj"}]
        for val in unsupported_values:
            json_data = {"profile1": {"MACRO": val}}
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tf:
                json.dump(json_data, tf)
                temp_path = tf.name

            try:
                with self.assertRaises(ValueError) as cm:
                    parse_json_config_seed(temp_path)
                self.assertIn("Unsupported flag value type", str(cm.exception))
            finally:
                Path(temp_path).unlink(missing_ok=True)

    def test_parse_config_seed_rejects_json(self):
        """
        Tests that calling parse_config_seed() on a .json file raises ValueError instructing callers
        to use parse_json_config_seed() or parse_config_seeds().
        """
        json_data = {"profile1": {"MACRO": True}}
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as tf:
            json.dump(json_data, tf)
            temp_path = tf.name

        try:
            with self.assertRaises(ValueError) as cm:
                parse_config_seed(temp_path)
            self.assertIn("parse_config_seed() does not accept JSON seed files directly", str(cm.exception))
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_seed_source_profile_name_collision_diagnostic(self):
        """
        Fixture 1: Precedence when multiple --config-seed sources are given.
        Asserts that a profile name collision across sources causes an error naming both source files
        and exits with code 1, whereas non-colliding profiles combine additively.
        """
        json1_data = {
            "shared_profile": {"FLAG_A": True},
            "profile_one": {"FLAG_B": True}
        }
        json2_data = {
            "shared_profile": {"FLAG_C": True},
            "profile_two": {"FLAG_D": True}
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            s1_path = Path(temp_dir) / "seed1.json"
            s2_path = Path(temp_dir) / "seed2.json"
            c_file = Path(temp_dir) / "test.c"

            s1_path.write_text(json.dumps(json1_data), encoding="utf-8")
            s2_path.write_text(json.dumps(json2_data), encoding="utf-8")
            c_file.write_text("int main() { return 0; }\n", encoding="utf-8")

            parser = build_parser()
            args = parser.parse_args(["scan", "--config-seed", str(s1_path), "--config-seed", str(s2_path), str(c_file)])

            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                exit_code = handle_scan(args)

            self.assertEqual(exit_code, 1)
            err_msg = stderr_buf.getvalue()
            self.assertIn("Error: Profile name collision 'shared_profile'", err_msg)
            self.assertIn(str(s1_path), err_msg)
            self.assertIn(str(s2_path), err_msg)

    def test_seed_unused_macro_warning_diagnostic(self):
        """
        Fixture 2: Diagnostic for a seed defining a macro never tested anywhere in the scanned source file(s).
        Asserts that C-GULL emits a single warning on sys.stderr per run (not erroring out) and completes scan.
        """
        seed_content = """
#define UNTESTED_MACRO 100
#define TESTED_FLAG
"""
        c_content = """
#ifdef TESTED_FLAG
int x = 1;
#endif
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            seed_path = Path(temp_dir) / "config_seed.h"
            c_path = Path(temp_dir) / "app.c"

            seed_path.write_text(seed_content, encoding="utf-8")
            c_path.write_text(c_content, encoding="utf-8")

            parser = build_parser()
            args = parser.parse_args(["scan", "--config-seed", str(seed_path), str(c_path)])

            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                exit_code = handle_scan(args)

            self.assertEqual(exit_code, 0)
            err_msg = stderr_buf.getvalue()
            self.assertIn("Warning: Seed macro 'UNTESTED_MACRO' is defined in configuration seed but never tested in any scanned source file.", err_msg)
            self.assertEqual(err_msg.count("UNTESTED_MACRO"), 1)

    def test_seed_value_macro_mismatch_warning_diagnostic(self):
        """
        Fixture 3: Diagnostic for a value-macro seed (RETRY_COUNT=5) for a flag the discovery issue
        only ever saw used in a bare #ifdef context (presence-tested, not value-compared).
        Asserts that C-GULL warns with the specific file and line number where the mismatched usage was found.
        """
        seed_data = {
            "default": {
                "RETRY_COUNT": 5
            }
        }
        c_content = """// main.c
int start() {
#ifdef RETRY_COUNT
    return 1;
#endif
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            seed_path = Path(temp_dir) / "seed.json"
            c_path = Path(temp_dir) / "main.c"

            seed_path.write_text(json.dumps(seed_data), encoding="utf-8")
            c_path.write_text(c_content, encoding="utf-8")

            parser = build_parser()
            args = parser.parse_args(["scan", "--config-seed", str(seed_path), str(c_path)])

            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                exit_code = handle_scan(args)

            self.assertEqual(exit_code, 0)
            err_msg = stderr_buf.getvalue()
            self.assertIn("Warning: Seed value macro 'RETRY_COUNT' is configured with value '5' but was only tested as a presence flag", err_msg)
            self.assertIn(f"in {c_path}:3", err_msg)


if __name__ == "__main__":
    unittest.main()
