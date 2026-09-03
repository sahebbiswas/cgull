from benchmarks.security_fact_support import build_security_context, build_security_models
from cgull.cfg import build_cfg, find_function_def
from cgull.cfg.fixed_point import FixedPointConfig
from cgull.cfg.value_facts import (
    FormatLiteralness,
    ValueProvenance,
    analyze_function_value_dataflow,
    analyze_value_summaries,
    analyze_value_summaries_detailed,
)
from cgull.cfg.value_interprocedural import analyze_translation_unit_value_dataflow


def _sink_node(ctx, function):
    cfg = build_cfg(find_function_def(ctx.pycparser_ast, function))
    node = next(
        item
        for item in cfg.nodes.values()
        if any(call.direct_callee == "sink" for call in item.calls)
    )
    return cfg, node


def test_three_level_return_wrapper_preserves_untrusted_non_literal_fact():
    ctx = build_security_context(
        r'''
        char *external_read(void);
        void sink(char *);
        char *one(void) { return external_read(); }
        char *two(void) { return one(); }
        char *three(void) { return two(); }
        void caller(void) {
            char *value = three();
            sink(value);
        }
        '''
    )
    models = build_security_models()
    summaries = analyze_value_summaries(ctx, models)
    facts = analyze_function_value_dataflow(ctx, "caller", models, summaries)
    cfg, sink = _sink_node(ctx, "caller")

    assert summaries["three"].return_provenance is ValueProvenance.UNTRUSTED
    assert summaries["three"].return_literalness is FormatLiteralness.NON_LITERAL
    assert facts.query_provenance("value", sink.node_id) is ValueProvenance.UNTRUSTED
    assert facts.query_format_literalness("value", sink.node_id) is FormatLiteralness.NON_LITERAL


def test_return_of_parameter_and_return_of_literal_are_distinguished():
    ctx = build_security_context(
        r'''
        char *identity(char *value) { return value; }
        char *literal(void) { return "fixed"; }
        '''
    )
    summaries = analyze_value_summaries(ctx)

    assert summaries["identity"].return_from_params == frozenset({0})
    assert summaries["identity"].return_provenance is None
    assert summaries["literal"].return_from_params == frozenset()
    assert summaries["literal"].return_provenance is ValueProvenance.TRUSTED
    assert summaries["literal"].return_literalness is FormatLiteralness.LITERAL


def test_multiple_safe_and_unsafe_callers_merge_formal_fact_conservatively():
    ctx = build_security_context(
        r'''
        char *external_read(void);
        void sink(char *);
        void consume(char *format) { sink(format); }
        void safe(void) { consume("fixed"); }
        void unsafe(void) { consume(external_read()); }
        '''
    )
    result = analyze_translation_unit_value_dataflow(ctx, build_security_models())

    incoming = result.parameter_facts["consume"][0]
    assert incoming.provenance is ValueProvenance.MIXED
    assert incoming.format_literalness is FormatLiteralness.UNKNOWN

    cfg, sink = _sink_node(ctx, "consume")
    facts = result.function("consume")
    assert facts.query_provenance("format", sink.node_id) is ValueProvenance.MIXED
    assert facts.query_format_literalness("format", sink.node_id) is FormatLiteralness.UNKNOWN


def test_address_of_actual_preserves_underlying_value_fact():
    ctx = build_security_context(
        r'''
        char *external_read(void);
        void consume(char **value);
        void caller(void) {
            char *buf = external_read();
            consume(&buf);
        }
        '''
    )
    result = analyze_translation_unit_value_dataflow(ctx, build_security_models())

    incoming = result.parameter_facts["consume"][0]
    assert incoming.provenance is ValueProvenance.UNTRUSTED
    assert incoming.format_literalness is FormatLiteralness.NON_LITERAL


def test_recursive_summary_converges_with_parameter_relationship():
    ctx = build_security_context(
        r'''
        char *b(char *);
        char *a(char *value) { return b(value); }
        char *b(char *value) {
            if (value) return a(value);
            return value;
        }
        '''
    )
    result = analyze_value_summaries_detailed(ctx)

    assert result.summaries["a"].return_from_params == frozenset({0})
    assert result.summaries["b"].return_from_params == frozenset({0})
    assert not result.diagnostics


def test_unresolved_return_degrades_to_unknown():
    ctx = build_security_context(
        r'''
        char *unknown(void);
        char *wrapper(void) { return unknown(); }
        '''
    )
    summary = analyze_value_summaries(ctx)["wrapper"]

    assert summary.return_provenance is ValueProvenance.UNKNOWN
    assert summary.return_literalness is FormatLiteralness.UNKNOWN
    assert "UNRESOLVED_CALL" in summary.degradations


def test_evidence_is_bounded_by_fixed_point_configuration():
    ctx = build_security_context(
        r'''
        char *many(int x) {
            if (x == 0) return "a";
            if (x == 1) return "b";
            if (x == 2) return "c";
            if (x == 3) return "d";
            return "e";
        }
        '''
    )
    result = analyze_value_summaries_detailed(
        ctx,
        fixed_point_config=FixedPointConfig(max_provenance=2),
    )
    summary = result.summaries["many"]

    assert len(summary.evidence) <= 2
    assert "EVIDENCE_LIMIT" in summary.degradations
