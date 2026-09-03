from cgull.ast_analyzer import CASTParser
from cgull.cfg.fixed_point import FixedPointConfig
from cgull.cfg.model import Nullness
from cgull.cfg.summaries import (
    analyze_function_summaries,
    analyze_function_summaries_detailed,
    serialize_function_summaries,
)


def _parse(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return ctx


def test_existing_free_allocation_and_nullness_summary_semantics_are_preserved():
    ctx = _parse(
        """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        void release(void *p) { free(p); }
        void *make(void) { return malloc(8); }
        void *nil(void) { return 0; }
        """
    )

    summaries = analyze_function_summaries(ctx)

    assert summaries["release"].freed_params == {0}
    assert summaries["make"].returns_allocation is True
    assert summaries["make"].return_nullness == Nullness.MAYBE_NULL
    assert summaries["nil"].return_nullness == Nullness.NULL


def test_self_recursive_summary_converges():
    ctx = _parse(
        """
        typedef unsigned long size_t;
        void *malloc(size_t);

        void *self(int n) {
            if (n <= 0) return malloc(8);
            return self(n - 1);
        }
        """
    )

    result = analyze_function_summaries_detailed(ctx)

    assert result.summaries["self"].returns_allocation is True
    assert result.summaries["self"].is_unknown is False
    assert result.diagnostics == ()
    assert ("self",) in result.iterations_by_scc


def test_mutually_recursive_allocation_summary_converges():
    ctx = _parse(
        """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void *b(int n);

        void *a(int n) {
            if (n <= 0) return malloc(8);
            return b(n - 1);
        }
        void *b(int n) { return a(n); }
        """
    )

    result = analyze_function_summaries_detailed(ctx)

    assert result.summaries["a"].returns_allocation is True
    assert result.summaries["b"].returns_allocation is True
    assert result.summaries["a"].is_unknown is False
    assert result.summaries["b"].is_unknown is False
    assert result.diagnostics == ()
    assert ("a", "b") in result.iterations_by_scc


def test_forced_summary_limit_returns_conservative_unknown_and_diagnostic():
    ctx = _parse(
        """
        void *self(void *p) { return self(p); }
        """
    )

    result = analyze_function_summaries_detailed(
        ctx,
        fixed_point_config=FixedPointConfig(max_iterations_per_scc=1),
    )

    summary = result.summaries["self"]
    assert summary.is_unknown is True
    assert summary.freed_params == {0}
    assert summary.unsafe_deref_params == {0}
    assert summary.return_nullness == Nullness.UNKNOWN
    assert summary.returns_allocation is True
    assert [diagnostic.code for diagnostic in result.diagnostics] == ["CONVERGENCE_LIMIT"]


def test_canonical_summary_serialization_is_byte_for_byte_deterministic():
    ctx = _parse(
        """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);
        void release(void *p) { free(p); }
        void *make(void) { return malloc(8); }
        """
    )

    first = serialize_function_summaries(analyze_function_summaries(ctx))
    second = serialize_function_summaries(analyze_function_summaries(ctx))

    assert first == second
