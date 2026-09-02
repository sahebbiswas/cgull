from types import SimpleNamespace

from pycparser import c_parser

from cgull.cfg import build_cfg, find_function_def
from cgull.cfg.security_dataflow import (
    Provenance,
    analyze_security_dataflow,
    analyze_security_summaries,
)
from cgull.semantic_models import (
    SemanticLocation,
    SemanticLocationKind,
    SemanticModelRegistry,
    SinkModel,
    SinkRequirement,
    SourceModel,
    SuccessCondition,
    SuccessConditionKind,
    ValidationProperty,
    ValidatorModel,
)


def _ctx(code):
    ast = c_parser.CParser().parse(code)
    functions = []
    for ext in ast.ext:
        if type(ext).__name__ != "FuncDef":
            continue
        params = []
        decl_args = getattr(getattr(ext.decl, "type", None), "args", None)
        for param in list(getattr(decl_args, "params", ()) or ()):
            name = getattr(param, "name", None)
            if name:
                params.append(SimpleNamespace(name=name))
        functions.append(SimpleNamespace(name=ext.decl.name, parameters=params))
    return SimpleNamespace(
        has_pycparser=True,
        pycparser_ast=ast,
        functions=functions,
        line_map=None,
    )


def _models():
    arg0 = SemanticLocation(SemanticLocationKind.ARGUMENT, 0)
    return SemanticModelRegistry(
        sources={
            "external_read": SourceModel(
                "external_read", (SemanticLocation(SemanticLocationKind.RETURN),)
            ),
            "external_out": SourceModel(
                "external_out", (SemanticLocation(SemanticLocationKind.OUTPUT_ARGUMENT, 0),)
            ),
        },
        validators={
            "validate": ValidatorModel(
                "validate",
                arg0,
                ValidationProperty.BOUNDS_CHECKED,
                SuccessCondition(SuccessConditionKind.RETURN_NONZERO),
            )
        },
        sinks={
            "sink": SinkModel(
                "sink",
                (SinkRequirement(arg0, frozenset({ValidationProperty.BOUNDS_CHECKED})),),
            )
        },
    )


def _facts(ctx, function, models):
    summaries = analyze_security_summaries(ctx, models)
    cfg = build_cfg(find_function_def(ctx.pycparser_ast, function))
    return cfg, analyze_security_dataflow(cfg, models, summaries), summaries


def _sink_node(cfg):
    return next(
        node
        for node in cfg.nodes.values()
        if any(call.direct_callee == "sink" for call in node.calls)
    )


def test_multihop_return_wrapper_preserves_external_provenance():
    ctx = _ctx(
        r"""
        int external_read(void);
        void sink(int);
        int read_one(void) { return external_read(); }
        int read_two(void) { return read_one(); }
        void caller(void) {
            int x = read_two();
            sink(x);
        }
        """
    )
    cfg, facts, summaries = _facts(ctx, "caller", _models())
    assert summaries["read_one"].external_return
    assert summaries["read_two"].external_return
    assert facts.query_provenance("x", _sink_node(cfg).node_id) is Provenance.UNTRUSTED


def test_output_parameter_wrapper_preserves_external_provenance():
    ctx = _ctx(
        r"""
        void external_out(int *);
        void sink(int);
        void read_value(int *p) { external_out(p); }
        void caller(void) {
            int x = 0;
            read_value(&x);
            sink(x);
        }
        """
    )
    cfg, facts, summaries = _facts(ctx, "caller", _models())
    assert 0 in summaries["read_value"].external_outputs
    assert facts.query_provenance("x", _sink_node(cfg).node_id) is Provenance.UNTRUSTED


def test_direct_output_parameter_dependency_is_substituted_at_call_site():
    ctx = _ctx(
        r"""
        int external_read(void);
        void sink(int);
        void copy_out(int *out, int value) { *out = value; }
        void caller(void) {
            int x = external_read();
            int y = 0;
            copy_out(&y, x);
            sink(y);
        }
        """
    )
    cfg, facts, summaries = _facts(ctx, "caller", _models())
    assert summaries["copy_out"].output_dependencies(0) == frozenset({1})
    assert facts.query_provenance("y", _sink_node(cfg).node_id) is Provenance.UNTRUSTED


def test_checked_validator_helper_establishes_validation():
    ctx = _ctx(
        r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        int check_value(int x) { return validate(x); }
        void caller(void) {
            int x = external_read();
            if (!check_value(x)) return;
            sink(x);
        }
        """
    )
    cfg, facts, summaries = _facts(ctx, "caller", _models())
    assert summaries["check_value"].validator_effects
    assert ValidationProperty.BOUNDS_CHECKED in facts.query_validation_properties(
        "x", _sink_node(cfg).node_id
    )


def test_ignored_validator_helper_return_does_not_validate():
    ctx = _ctx(
        r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        int check_value(int x) { return validate(x); }
        void caller(void) {
            int x = external_read();
            check_value(x);
            sink(x);
        }
        """
    )
    cfg, facts, _ = _facts(ctx, "caller", _models())
    assert facts.query_validation_properties("x", _sink_node(cfg).node_id) == frozenset()


def test_helper_that_discards_validator_result_cannot_manufacture_validation():
    ctx = _ctx(
        r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        int bad_check(int x) {
            validate(x);
            return 1;
        }
        void caller(void) {
            int x = external_read();
            if (!bad_check(x)) return;
            sink(x);
        }
        """
    )
    cfg, facts, summaries = _facts(ctx, "caller", _models())
    assert summaries["bad_check"].validator_effects == ()
    assert facts.query_validation_properties("x", _sink_node(cfg).node_id) == frozenset()


def test_sink_requirement_is_propagated_through_wrapper():
    ctx = _ctx(
        r"""
        void sink(int);
        void consume(int x) { sink(x); }
        void consume2(int x) { consume(x); }
        """
    )
    summaries = analyze_security_summaries(ctx, _models())
    requirement = summaries["consume2"].sink_requirements[0]
    assert requirement.parameter_index == 0
    assert requirement.properties == frozenset({ValidationProperty.BOUNDS_CHECKED})


def test_recursive_summaries_converge_and_preserve_parameter_dependency():
    ctx = _ctx(
        r"""
        int b(int);
        int a(int x) { return b(x); }
        int b(int x) {
            if (x) return a(x);
            return x;
        }
        """
    )
    summaries = analyze_security_summaries(ctx, _models())
    assert summaries["a"].return_from_params == frozenset({0})
    assert summaries["b"].return_from_params == frozenset({0})


def test_unknown_call_does_not_erase_existing_external_provenance():
    ctx = _ctx(
        r"""
        int external_read(void);
        void unknown(int);
        void sink(int);
        void caller(void) {
            int x = external_read();
            unknown(x);
            sink(x);
        }
        """
    )
    cfg, facts, _ = _facts(ctx, "caller", _models())
    assert facts.query_provenance("x", _sink_node(cfg).node_id) is Provenance.UNTRUSTED
