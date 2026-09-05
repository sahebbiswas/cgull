from cgull.analysis_session import analysis_session_for
from cgull.ast_analyzer import CASTParser
from cgull.cfg.construction import build_cfg, find_function_def
from cgull.cfg.ownership import analyze_ownership_summaries
from cgull.rules.memory_management import UseAfterFreeRule


def _parse(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return ctx


def test_realloc_wrapper_is_possible_free_not_definite_free():
    ctx = _parse(
        """
        typedef unsigned long size_t;
        void *realloc(void *, size_t);

        void *resize(void *p) {
            return realloc(p, 32);
        }
        """
    )

    summary = analyze_ownership_summaries(ctx)["resize"]

    assert summary.freed_params == frozenset()
    assert summary.maybe_freed_params == frozenset({0})


def test_realloc_failure_keeps_original_pointer_live_for_uaf_query():
    ctx = _parse(
        """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void *realloc(void *, size_t);
        void free(void *);

        void good(void) {
            int *p = malloc(16);
            if (!p) return;
            int *tmp = realloc(p, 32);
            if (!tmp) {
                p[0] = 1;
                free(p);
                return;
            }
            p = tmp;
            p[0] = 2;
            free(p);
        }
        """
    )

    assert UseAfterFreeRule().scan_ast("test.c", ctx) == []


def test_session_reuses_node_ownership_effect_map_for_function():
    ctx = _parse(
        """
        void free(void *);
        void release(void *p) { free(p); }
        """
    )
    session = analysis_session_for(ctx)
    funcdef = find_function_def(ctx.pycparser_ast, "release")
    assert funcdef is not None
    cfg = build_cfg(
        funcdef,
        summaries=session.function_summaries,
        line_map=getattr(ctx, "line_map", None),
    )
    cfg.analyze_dataflow(initial_nonnull=set(), initial_initialized={"p"})

    first = session.ownership_effects("release", cfg)
    second = session.ownership_effects("release", cfg)

    assert first is second
