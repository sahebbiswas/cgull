from cgull.ast_analyzer import CASTParser
from cgull.call_effects import BUILTIN_CALL_EFFECTS, CallEffectModel
from cgull.cfg.ownership import analyze_ownership_summaries
from cgull.rules.memory_management import DoubleFreeRule, MemoryLeakRule, UseAfterFreeRule
from cgull.semantic_models import SemanticModelRegistry


def _parse(code: str):
    ctx = CASTParser().parse(code)
    assert ctx.has_pycparser
    return ctx


def test_ownership_summary_distinguishes_definite_and_possible_free_and_aliases():
    ctx = _parse(
        """
        void free(void *);

        void release(void *p) {
            void *alias = p;
            free(alias);
        }
        void maybe_release(int cond, void *p) {
            if (cond) free(p);
        }
        void *identity(void *p) { return p; }
        """
    )

    summaries = analyze_ownership_summaries(ctx)

    assert summaries["release"].freed_params == frozenset({0})
    assert summaries["release"].maybe_freed_params == frozenset()
    assert summaries["maybe_release"].freed_params == frozenset()
    assert summaries["maybe_release"].maybe_freed_params == frozenset({1})
    assert summaries["identity"].returned_alias_params == frozenset({0})


def test_free_in_callee_is_visible_to_uaf_and_double_free_rules():
    ctx = _parse(
        """
        void free(void *);
        void release(void *p) { free(p); }

        void bad_uaf(void *p) {
            release(p);
            *(int *)p = 1;
        }
        void bad_double_free(void *p) {
            release(p);
            free(p);
        }
        """
    )

    uaf = UseAfterFreeRule().scan_ast("test.c", ctx)
    double_free = DoubleFreeRule().scan_ast("test.c", ctx)

    assert any("Use-After-Free" in issue.message for issue in uaf)
    assert any("Double Free" in issue.message for issue in double_free)


def test_allocation_returned_through_wrapper_is_not_reported_when_freed():
    ctx = _parse(
        """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        void *make(void) { return malloc(16); }
        void good(void) {
            void *p = make();
            free(p);
        }
        """
    )

    issues = MemoryLeakRule().scan_ast("test.c", ctx)

    assert not issues


def test_modeled_transfer_suppresses_leak_but_unknown_escape_stays_conservative():
    code = """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void adopt(void *);
        void unknown(void *);

        void transferred(void) {
            void *p = malloc(16);
            adopt(p);
        }
        void unknown_escape(void) {
            void *p = malloc(16);
            unknown(p);
        }
    """

    transfer = CallEffectModel(function="adopt", takes_ownership=frozenset({0}))
    registry = SemanticModelRegistry(
        call_effects=BUILTIN_CALL_EFFECTS.merged({"adopt": transfer})
    )
    ctx = _parse(code)
    rule = MemoryLeakRule()
    rule._semantic_models = registry

    issues = rule.scan_ast("test.c", ctx)

    messages = [issue.message for issue in issues]
    assert not any("allocated for 'p'" in message and issue.line_number < 10 for issue, message in zip(issues, messages))
    assert any(issue.line_number >= 10 for issue in issues)


def test_modeled_transfer_and_escape_are_propagated_through_wrapper():
    ctx = _parse(
        """
        void adopt(void *);
        void retain(void *);
        void wrap_adopt(void *p) { adopt(p); }
        void wrap_retain(void *p) { retain(p); }
        """
    )
    registry = BUILTIN_CALL_EFFECTS.merged({
        "adopt": CallEffectModel(function="adopt", takes_ownership=frozenset({0})),
        "retain": CallEffectModel(function="retain", escapes=frozenset({0})),
    })

    summaries = analyze_ownership_summaries(ctx, call_effects=registry)

    assert summaries["wrap_adopt"].transferred_params == frozenset({0})
    assert summaries["wrap_adopt"].consumed_params == frozenset({0})
    assert summaries["wrap_retain"].escaped_params == frozenset({0})
    assert summaries["wrap_retain"].consumed_params == frozenset({0})
