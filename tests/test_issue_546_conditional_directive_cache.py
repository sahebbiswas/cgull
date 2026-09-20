"""Scan-local caching for parse_conditional_directives (issue #546)."""
from __future__ import annotations

import cgull.preprocessor.directives as directives
from cgull.preprocessor import (
    conditional_directive_cache,
    parse_conditional_directives,
)


SOURCE_A = "#if A\nint x;\n#endif\n"
SOURCE_B = "#if B\nint y;\n#endif\n"


def _count_uncached_parses(monkeypatch):
    calls: list[str] = []
    real = directives._parse_conditional_directives_uncached

    def wrapped(source: str):
        calls.append(source)
        return real(source)

    monkeypatch.setattr(directives, "_parse_conditional_directives_uncached", wrapped)
    return calls


def test_cache_hit_on_repeated_identical_source(monkeypatch):
    calls = _count_uncached_parses(monkeypatch)
    with conditional_directive_cache():
        first = parse_conditional_directives(SOURCE_A)
        second = parse_conditional_directives(SOURCE_A)
    assert calls == [SOURCE_A]
    assert first.blocks and second.blocks
    assert first.directives == second.directives
    assert first is not second


def test_cache_miss_across_cleared_contexts(monkeypatch):
    calls = _count_uncached_parses(monkeypatch)
    with conditional_directive_cache():
        parse_conditional_directives(SOURCE_A)
    with conditional_directive_cache():
        parse_conditional_directives(SOURCE_A)
    assert calls == [SOURCE_A, SOURCE_A]


def test_different_sources_do_not_collide(monkeypatch):
    calls = _count_uncached_parses(monkeypatch)
    with conditional_directive_cache():
        tree_a = parse_conditional_directives(SOURCE_A)
        tree_b = parse_conditional_directives(SOURCE_B)
        tree_a_again = parse_conditional_directives(SOURCE_A)
    assert calls == [SOURCE_A, SOURCE_B]
    assert tree_a.directives[0].condition_text == "A"
    assert tree_b.directives[0].condition_text == "B"
    assert tree_a_again.directives[0].condition_text == "A"


def test_returned_tree_mutation_does_not_corrupt_cache(monkeypatch):
    calls = _count_uncached_parses(monkeypatch)
    with conditional_directive_cache():
        first = parse_conditional_directives(SOURCE_A)
        assert first.blocks
        first.blocks = ()
        first.directives = ()
        second = parse_conditional_directives(SOURCE_A)
    assert calls == [SOURCE_A]
    assert second.blocks
    assert second.directives
    assert second.directives[0].kind == "if"


def test_nested_cache_contexts_reuse_same_store(monkeypatch):
    calls = _count_uncached_parses(monkeypatch)
    with conditional_directive_cache() as outer:
        parse_conditional_directives(SOURCE_A)
        with conditional_directive_cache() as inner:
            assert inner is outer
            parse_conditional_directives(SOURCE_A)
    assert calls == [SOURCE_A]


def test_without_cache_context_parses_every_call(monkeypatch):
    calls = _count_uncached_parses(monkeypatch)
    parse_conditional_directives(SOURCE_A)
    parse_conditional_directives(SOURCE_A)
    assert calls == [SOURCE_A, SOURCE_A]


def test_equal_but_distinct_string_objects_share_cache(monkeypatch):
    calls = _count_uncached_parses(monkeypatch)
    left = "#if FLAG\nbody\n#endif\n"
    # Force a distinct str object with equal content (avoid literal interning).
    right = bytes(left, "utf-8").decode("utf-8")
    assert left == right and left is not right
    with conditional_directive_cache():
        parse_conditional_directives(left)
        parse_conditional_directives(right)
    assert calls == [left]


def test_malformed_diagnostics_stable_with_cache():
    source = "#endif\n#if A\n"
    with conditional_directive_cache():
        first = parse_conditional_directives(source)
        second = parse_conditional_directives(source)
    assert first.diagnostics
    assert first.diagnostics == second.diagnostics
    assert [d.code for d in first.diagnostics] == [d.code for d in second.diagnostics]
