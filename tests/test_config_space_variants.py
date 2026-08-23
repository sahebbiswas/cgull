"""
Unit tests for config-space variant generation (baseline + one-at-a-time single-flag flips).
"""

import unittest

from cgull.ast_analyzer import (
    ConditionalFlagCollector,
    CollectedFlags,
    generate_config_profiles,
    eval_preprocessor_expr,
    resolve_preprocessor_conditionals,
)
from cgull.models import ConfigProfile
from cgull.utils import strip_comments_keep_lines


class TestConfigSpaceVariants(unittest.TestCase):

    def test_generate_from_collected_flags_instance(self):
        collected = CollectedFlags(
            presence_flags={"ENABLE_SSL", "USE_ZLIB"},
            value_flags={"MAX_BUF_SIZE"}
        )
        profiles = generate_config_profiles(collected)

        self.assertEqual(len(profiles), 3)  # 1 baseline + 2 presence flags
        self.assertEqual(profiles[0], ConfigProfile("baseline", {}))
        self.assertEqual(profiles[1], ConfigProfile("ENABLE_SSL", {"ENABLE_SSL": None}))
        self.assertEqual(profiles[2], ConfigProfile("USE_ZLIB", {"USE_ZLIB": None}))

    def test_generate_from_set_or_list_or_tuple(self):
        flags_set = {"FLAG_B", "FLAG_A"}
        profiles_from_set = generate_config_profiles(flags_set, baseline_name="default")

        self.assertEqual(len(profiles_from_set), 3)
        self.assertEqual(profiles_from_set[0].name, "default")
        self.assertEqual(profiles_from_set[0].flags, {})
        self.assertEqual(profiles_from_set[1].name, "FLAG_A")
        self.assertEqual(profiles_from_set[1].presence_flags, {"FLAG_A"})
        self.assertEqual(profiles_from_set[2].name, "FLAG_B")
        self.assertEqual(profiles_from_set[2].presence_flags, {"FLAG_B"})

    def test_collected_flags_method(self):
        collected = CollectedFlags(presence_flags={"DEBUG_MODE"})
        profiles = collected.generate_config_profiles(baseline_name="baseline")

        self.assertEqual(len(profiles), 2)
        self.assertEqual(profiles[0].name, "baseline")
        self.assertEqual(profiles[1].name, "DEBUG_MODE")
        self.assertEqual(profiles[1].flags, {"DEBUG_MODE": None})

    def test_conditional_flag_collector_generate_variant_configs(self):
        c_code = """
        #ifdef FEATURE_X
        void do_x(void);
        #endif

        #ifndef FEATURE_Y
        void do_y(void);
        #endif
        """
        _, clean = strip_comments_keep_lines(c_code)
        profiles = ConditionalFlagCollector.generate_variant_configs(clean)

        self.assertEqual(len(profiles), 3)  # 1 baseline + 2 single-flip variants
        self.assertEqual(profiles[0].name, "baseline")
        self.assertEqual(profiles[1].name, "FEATURE_X")
        self.assertEqual(profiles[1].presence_flags, {"FEATURE_X"})
        self.assertEqual(profiles[2].name, "FEATURE_Y")
        self.assertEqual(profiles[2].presence_flags, {"FEATURE_Y"})

    def test_fixture_with_known_flags_produces_deterministic_7_configs(self):
        """
        Fixture file with 6 presence-tested flags and 1 value macro.
        Deterministically produces 7 ConfigProfile objects (1 baseline + 6 single-flip variants).
        Value macro is excluded from presence flag single-flip variants.
        """
        c_fixture = """
        /* Fixture code testing 6 presence flags and 1 value macro */
        #ifdef OPTION_ALPHA
        int a = 1;
        #endif

        #ifndef OPTION_BETA
        int b = 2;
        #endif

        #if defined(OPTION_GAMMA) && defined(OPTION_DELTA)
        int cd = 3;
        #endif

        #if OPTION_EPSILON
        int e = 4;
        #endif

        #if !OPTION_ZETA
        int z = 5;
        #endif

        #if BUFFER_CAPACITY > 1024
        int buf[2048];
        #endif
        """
        _, clean = strip_comments_keep_lines(c_fixture)
        collected = ConditionalFlagCollector.collect(clean)

        # Verify collector extracted 6 presence flags and 1 value flag
        self.assertEqual(
            collected.presence_flags,
            {"OPTION_ALPHA", "OPTION_BETA", "OPTION_GAMMA", "OPTION_DELTA", "OPTION_EPSILON", "OPTION_ZETA"}
        )
        self.assertEqual(collected.value_flags, {"BUFFER_CAPACITY"})

        profiles = ConditionalFlagCollector.generate_variant_configs(clean, baseline_name="baseline")

        # 1 baseline + 6 presence flags = 7 configs
        self.assertEqual(len(profiles), 7)

        # Deterministic order test
        expected_names = [
            "baseline",
            "OPTION_ALPHA",
            "OPTION_BETA",
            "OPTION_DELTA",
            "OPTION_EPSILON",
            "OPTION_GAMMA",
            "OPTION_ZETA",
        ]
        actual_names = [p.name for p in profiles]
        self.assertEqual(actual_names, expected_names)

        # Ensure value-comparison macro BUFFER_CAPACITY is NOT in any generated profile
        for p in profiles:
            self.assertNotIn("BUFFER_CAPACITY", p.flags)
            self.assertNotIn("BUFFER_CAPACITY", p.presence_flags)

    def test_profile_properties_and_immutability(self):
        collected = CollectedFlags(presence_flags={"STRICT_CHECK"})
        profiles = generate_config_profiles(collected)

        p_base = profiles[0]
        self.assertEqual(p_base.name, "baseline")
        self.assertEqual(p_base.flags, {})
        self.assertEqual(p_base.presence_flags, set())
        self.assertEqual(p_base.value_flags, {})
        self.assertEqual(p_base.label, "+baseline")

        p_var = profiles[1]
        self.assertEqual(p_var.name, "STRICT_CHECK")
        self.assertEqual(p_var.flags, {"STRICT_CHECK": None})
        self.assertEqual(p_var.presence_flags, {"STRICT_CHECK"})
        self.assertEqual(p_var.value_flags, {})
        self.assertEqual(p_var.label, "+STRICT_CHECK")

        # Immutability check
        with self.assertRaises(TypeError):
            p_var.flags["NEW_FLAG"] = None

    def test_zero_presence_flags(self):
        collected = CollectedFlags(presence_flags=set(), value_flags={"VAL1"})
        profiles = generate_config_profiles(collected)

        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0], ConfigProfile("baseline", {}))

    def test_invalid_input_type(self):
        with self.assertRaises(TypeError):
            generate_config_profiles(12345)

    def test_eval_preprocessor_expr_with_config_profile_flags(self):
        """
        Tests that passing ConfigProfile.flags (with None for presence flags)
        into eval_preprocessor_expr does not raise TypeError and evaluates presence checks correctly.
        """
        cp = ConfigProfile(name="test_profile", flags={"ENABLE_FEATURE": None, "VAL_MACRO": "5", "BOOL_MACRO": True})

        self.assertTrue(eval_preprocessor_expr("ENABLE_FEATURE", cp.flags))
        self.assertTrue(eval_preprocessor_expr("defined(ENABLE_FEATURE)", cp.flags))
        self.assertTrue(eval_preprocessor_expr("VAL_MACRO == 5", cp.flags))
        self.assertTrue(eval_preprocessor_expr("BOOL_MACRO", cp.flags))
        self.assertFalse(eval_preprocessor_expr("UNDEFINED_FEATURE", cp.flags))

    def test_resolve_preprocessor_conditionals_with_config_profile_flags(self):
        """
        Tests that resolve_preprocessor_conditionals correctly handles ConfigProfile.flags
        for #if and #ifdef directives without raising TypeError.
        """
        code = """
        #ifdef ENABLE_FEATURE
        int active_feature = 1;
        #else
        int active_feature = 0;
        #endif

        #if ENABLE_FEATURE
        int active_if = 1;
        #endif

        #if UNDEFINED_FEATURE
        int inactive = 1;
        #endif
        """
        cp = ConfigProfile(name="active_spec", flags={"ENABLE_FEATURE": None})
        resolved = resolve_preprocessor_conditionals(code, cp.flags)

        self.assertIn("int active_feature = 1;", resolved)
        self.assertNotIn("int active_feature = 0;", resolved)
        self.assertIn("int active_if = 1;", resolved)
        self.assertNotIn("int inactive = 1;", resolved)


if __name__ == "__main__":
    unittest.main()
