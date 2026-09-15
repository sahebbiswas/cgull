from pathlib import Path

import pytest

from benchmarks.juliet_attribution import (
    CWE563_DEAD_STORE,
    CWE563_DECLARATION_ONLY,
    CWE563_UNCLASSIFIED,
    applicable_rules_for_juliet_case,
    cwe563_semantic_family,
)
from benchmarks.run_juliet import CWE_RULE_MAP


@pytest.mark.parametrize(
    "filename",
    [
        "CWE563_Unused_Variable__unused_value_int_01.c",
        "CWE563_Unused_Variable__unused_value_struct_22a.c",
        "CWE563_Unused_Variable__unused_init_variable_char_01.c",
        "CWE563_Unused_Variable__unused_global_value_01.c",
        "CWE563_Unused_Variable__unused_static_global_value_01.c",
        "CWE563_Unused_Variable__unused_parameter_value_01.c",
        "CWE563_Unused_Variable__unused_class_member_value_01_bad.cpp",
    ],
)
def test_cwe563_dead_store_families_are_attributed_to_cgull_042(filename):
    path = Path(filename)

    assert cwe563_semantic_family(path) == CWE563_DEAD_STORE
    assert applicable_rules_for_juliet_case(
        "CWE-563", path, {"CGULL-042"}
    ) == {"CGULL-042"}


@pytest.mark.parametrize(
    "filename",
    [
        "CWE563_Unused_Variable__unused_uninit_variable_int_01.c",
        "CWE563_Unused_Variable__unused_global_variable_01.c",
        "CWE563_Unused_Variable__unused_static_global_variable_01.c",
        "CWE563_Unused_Variable__unused_parameter_variable_01.c",
        "CWE563_Unused_Variable__unused_class_member_variable_01_bad.cpp",
    ],
)
def test_cwe563_declaration_only_families_are_excluded_from_cgull_042(filename):
    path = Path(filename)

    assert cwe563_semantic_family(path) == CWE563_DECLARATION_ONLY
    assert applicable_rules_for_juliet_case(
        "CWE-563", path, {"CGULL-042"}
    ) == set()


def test_unknown_cwe563_family_fails_closed():
    path = Path("CWE563_Unused_Variable__future_template_int_01.c")

    assert cwe563_semantic_family(path) == CWE563_UNCLASSIFIED
    assert applicable_rules_for_juliet_case(
        "CWE-563", path, {"CGULL-042"}
    ) == set()


def test_non_cwe563_cases_keep_their_canonical_mapping():
    path = Path("CWE476_NULL_Pointer_Dereference__foo_01.c")
    mapped = {"CGULL-003", "CGULL-004"}

    assert applicable_rules_for_juliet_case("CWE-476", path, mapped) == mapped


def test_canonical_cwe563_mapping_contains_only_dead_store_rule():
    assert CWE_RULE_MAP["CWE-563"] == {"CGULL-042"}
