"""
Unit tests for ConditionalFlagCollector and preprocessor flag discovery.
"""

import pytest
from cgull.ast_analyzer import ConditionalFlagCollector, CollectedFlags
from cgull.utils import strip_comments_keep_lines


def test_simple_presence_checks():
    code = """
    #ifdef DEBUG
    int x = 1;
    #endif

    #ifndef RELEASE
    int y = 2;
    #endif
    """
    _, clean = strip_comments_keep_lines(code)
    flags = ConditionalFlagCollector.collect(clean)
    assert flags.presence_flags == {"DEBUG", "RELEASE"}
    assert flags.value_flags == set()
    assert flags.all_flags == {"DEBUG", "RELEASE"}


def test_compound_defined_expressions():
    code = """
    #if defined(ENABLE_FOO) && defined(ENABLE_BAR)
    void foo(void) {}
    #elif defined BAZ || defined(QUX)
    void bar(void) {}
    #endif
    """
    _, clean = strip_comments_keep_lines(code)
    flags = ConditionalFlagCollector.collect(clean)
    assert flags.presence_flags == {"ENABLE_FOO", "ENABLE_BAR", "BAZ", "QUX"}
    assert flags.value_flags == set()


def test_bare_and_negated_if_toggles():
    code = """
    #if FOO
    int x = 1;
    #endif

    #if !BAR
    int y = 2;
    #endif

    #if BAZ && !QUX
    int z = 3;
    #endif
    """
    _, clean = strip_comments_keep_lines(code)
    flags = ConditionalFlagCollector.collect(clean)
    assert flags.presence_flags == {"FOO", "BAR", "BAZ", "QUX"}
    assert flags.value_flags == set()


def test_has_include_and_feature_test_macros():
    code = """
    #if __has_include("foo.h") || __has_include(<sys/bar.h>)
    int h = 1;
    #endif

    #if __has_builtin(__builtin_trap) && FEATURE_FLAG
    int f = 2;
    #endif
    """
    _, clean = strip_comments_keep_lines(code)
    flags = ConditionalFlagCollector.collect(clean)
    assert "foo" not in flags.all_flags
    assert "bar" not in flags.all_flags
    assert "sys" not in flags.all_flags
    assert flags.presence_flags == {"FEATURE_FLAG"}
    assert flags.value_flags == set()


def test_value_comparison_expressions():
    code = """
    #if VERBOSE_LEVEL > 2
    int debug_level = 3;
    #elif ARCH_BITS == 64
    long addr = 0;
    #endif
    """
    _, clean = strip_comments_keep_lines(code)
    flags = ConditionalFlagCollector.collect(clean)
    assert flags.presence_flags == set()
    assert flags.value_flags == {"VERBOSE_LEVEL", "ARCH_BITS"}


def test_mixed_presence_and_value_in_same_expression():
    code = """
    #if defined(FEATURE_ENABLED) && MIN_VERSION >= 10
    int active = 1;
    #endif
    """
    _, clean = strip_comments_keep_lines(code)
    flags = ConditionalFlagCollector.collect(clean)
    assert flags.presence_flags == {"FEATURE_ENABLED"}
    assert flags.value_flags == {"MIN_VERSION"}


def test_macro_in_both_presence_and_value_precedence():
    code = """
    #ifdef MY_MACRO
    int a = 1;
    #endif

    #if MY_MACRO > 5
    int b = 2;
    #endif
    """
    _, clean = strip_comments_keep_lines(code)
    flags = ConditionalFlagCollector.collect(clean)
    # Value comparison takes precedence over presence check
    assert flags.value_flags == {"MY_MACRO"}
    assert flags.presence_flags == set()


def test_nested_conditionals():
    code = """
    #ifdef OUTER_FLAG
      #if INNER_VAL < 10
        #ifndef DEEP_FLAG
          int x = 0;
        #endif
      #elif defined(INNER_FLAG2)
        int y = 1;
      #endif
    #endif
    """
    _, clean = strip_comments_keep_lines(code)
    flags = ConditionalFlagCollector.collect(clean)
    assert flags.presence_flags == {"OUTER_FLAG", "DEEP_FLAG", "INNER_FLAG2"}
    assert flags.value_flags == {"INNER_VAL"}


def test_flags_tested_but_never_defined():
    code = """
    // UNDEFINED_TOGGLE is never defined in this file
    #ifdef UNDEFINED_TOGGLE
    void run_legacy(void);
    #endif

    #if UNKNOWN_VALUE_FLAG != 0
    void run_alt(void);
    #endif
    """
    _, clean = strip_comments_keep_lines(code)
    flags = ConditionalFlagCollector.collect(clean)
    assert "UNDEFINED_TOGGLE" in flags.presence_flags
    assert "UNKNOWN_VALUE_FLAG" in flags.value_flags


def test_multiline_directive_continuation():
    code = """
    #if defined(FLAG1) && \\
        defined(FLAG2) && \\
        THRESHOLD_VAL > 100
    int multiline = 1;
    #endif
    """
    _, clean = strip_comments_keep_lines(code)
    flags = ConditionalFlagCollector.collect(clean)
    assert flags.presence_flags == {"FLAG1", "FLAG2"}
    assert flags.value_flags == {"THRESHOLD_VAL"}


def test_collected_flags_to_dict():
    flags = CollectedFlags(presence_flags={"B_FLAG", "A_FLAG"}, value_flags={"VAL_FLAG"})
    d = flags.to_dict()
    assert d["presence_flags"] == ["A_FLAG", "B_FLAG"]
    assert d["value_flags"] == ["VAL_FLAG"]
    assert d["all_flags"] == ["A_FLAG", "B_FLAG", "VAL_FLAG"]
