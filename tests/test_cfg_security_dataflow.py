from pycparser import c_parser

from cgull.cfg import build_cfg, find_function_def
from cgull.cfg.security_dataflow import (
    Provenance,
    analyze_security_dataflow,
    join_provenance,
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


def _build(code, models, function="f"):
    parser = c_parser.CParser()
    ast = parser.parse(code)
    cfg = build_cfg(find_function_def(ast, function))
    facts = analyze_security_dataflow(cfg, models)
    return cfg, facts


def _models(success=SuccessConditionKind.RETURN_NONZERO):
    arg0 = SemanticLocation(SemanticLocationKind.ARGUMENT, 0)
    return SemanticModelRegistry(
        sources={
            "external_read": SourceModel(
                "external_read", (SemanticLocation(SemanticLocationKind.RETURN),)
            )
        },
        validators={
            "validate": ValidatorModel(
                "validate",
                arg0,
                ValidationProperty.BOUNDS_CHECKED,
                SuccessCondition(success),
            )
        },
        sinks={
            "sink": SinkModel(
                "sink",
                (SinkRequirement(arg0, frozenset({ValidationProperty.BOUNDS_CHECKED})),),
            )
        },
    )


def _sink_node(cfg):
    return next(
        node for node in cfg.nodes.values()
        if any(call.direct_callee == "sink" for call in node.calls)
    )


def test_join_provenance_preserves_classified_taint_against_unknown():
    assert join_provenance(Provenance.UNTRUSTED, Provenance.UNKNOWN) is Provenance.UNTRUSTED
    assert join_provenance(Provenance.UNKNOWN, Provenance.UNTRUSTED) is Provenance.UNTRUSTED


def test_join_provenance_disagreement_between_classified_values_is_mixed():
    assert join_provenance(Provenance.TRUSTED, Provenance.UNTRUSTED) is Provenance.MIXED
    assert join_provenance(Provenance.MIXED, Provenance.TRUSTED) is Provenance.MIXED


def test_external_assignment_alias_reaches_sink():
    code = r"""
        int external_read(void);
        void sink(int);
        void f(void) {
            int x = external_read();
            int y = x;
            sink(y);
        }
    """
    cfg, facts = _build(code, _models())
    sink = _sink_node(cfg)
    assert facts.query_provenance("y", sink.node_id) is Provenance.UNTRUSTED


def test_untrusted_path_survives_merge_with_unclassified_path():
    code = r"""
        int external_read(void);
        int unknown_read(void);
        void sink(int);
        void f(int choose) {
            int x;
            if (choose) {
                x = external_read();
            } else {
                x = unknown_read();
            }
            sink(x);
        }
    """
    cfg, facts = _build(code, _models())
    assert facts.query_provenance("x", _sink_node(cfg).node_id) is Provenance.UNTRUSTED


def test_constant_is_trusted():
    code = r"""
        void sink(int);
        void f(void) {
            int x = 7;
            sink(x);
        }
    """
    cfg, facts = _build(code, _models())
    assert facts.query_provenance("x", _sink_node(cfg).node_id) is Provenance.TRUSTED


def test_fail_closed_validator_guard_establishes_must_property():
    models = _models(SuccessConditionKind.RETURN_NONZERO)
    code = r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        void f(void) {
            int x = external_read();
            if (!validate(x)) return;
            sink(x);
        }
    """
    cfg, facts = _build(code, models)
    sink = _sink_node(cfg)
    assert ValidationProperty.BOUNDS_CHECKED in facts.query_validation_properties("x", sink.node_id)


def test_success_branch_validator_establishes_property_inside_branch():
    code = r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        void f(void) {
            int x = external_read();
            if (validate(x)) {
                sink(x);
            }
        }
    """
    cfg, facts = _build(code, _models())
    assert ValidationProperty.BOUNDS_CHECKED in facts.query_validation_properties(
        "x", _sink_node(cfg).node_id
    )


def test_validation_on_one_branch_is_not_must_after_merge():
    code = r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        void f(int choose) {
            int x = external_read();
            if (choose) {
                if (!validate(x)) return;
            }
            sink(x);
        }
    """
    cfg, facts = _build(code, _models())
    assert ValidationProperty.BOUNDS_CHECKED not in facts.query_validation_properties(
        "x", _sink_node(cfg).node_id
    )


def test_validation_after_sink_does_not_retroactively_apply():
    code = r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        void f(void) {
            int x = external_read();
            sink(x);
            validate(x);
        }
    """
    cfg, facts = _build(code, _models())
    assert facts.query_validation_properties("x", _sink_node(cfg).node_id) == frozenset()


def test_overwrite_removes_validation_proof():
    code = r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        void f(void) {
            int x = external_read();
            if (!validate(x)) return;
            x = external_read();
            sink(x);
        }
    """
    cfg, facts = _build(code, _models())
    sink = _sink_node(cfg)
    assert facts.query_provenance("x", sink.node_id) is Provenance.UNTRUSTED
    assert facts.query_validation_properties("x", sink.node_id) == frozenset()


def test_alias_carries_validation_proof_for_same_value():
    code = r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        void f(void) {
            int x = external_read();
            if (!validate(x)) return;
            int y = x;
            sink(y);
        }
    """
    cfg, facts = _build(code, _models())
    assert ValidationProperty.BOUNDS_CHECKED in facts.query_validation_properties(
        "y", _sink_node(cfg).node_id
    )


def test_struct_member_and_index_insensitive_array_locations():
    code = r"""
        struct Packet { int len; };
        int external_read(void);
        void sink(int);
        void f(void) {
            struct Packet p;
            int a[2];
            p.len = external_read();
            a[0] = p.len;
            sink(a[1]);
        }
    """
    cfg, facts = _build(code, _models())
    sink = _sink_node(cfg)
    assert facts.query_provenance("p.len", sink.node_id) is Provenance.UNTRUSTED
    assert facts.query_provenance("a[99]", sink.node_id) is Provenance.UNTRUSTED


def test_short_circuit_true_edge_guarantees_validator_success():
    code = r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        void f(int ready) {
            int x = external_read();
            if (ready && validate(x)) {
                sink(x);
            }
        }
    """
    cfg, facts = _build(code, _models())
    assert ValidationProperty.BOUNDS_CHECKED in facts.query_validation_properties(
        "x", _sink_node(cfg).node_id
    )


def test_loop_validation_does_not_escape_when_loop_may_not_execute():
    code = r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        void f(int again) {
            int x = external_read();
            while (again) {
                if (!validate(x)) return;
                again = 0;
            }
            sink(x);
        }
    """
    cfg, facts = _build(code, _models())
    assert ValidationProperty.BOUNDS_CHECKED not in facts.query_validation_properties(
        "x", _sink_node(cfg).node_id
    )


def test_switch_fallthrough_preserves_external_provenance():
    code = r"""
        int external_read(void);
        void sink(int);
        void f(int k) {
            int x = external_read();
            switch (k) {
                case 0: x = x;
                case 1: break;
                default: break;
            }
            sink(x);
        }
    """
    cfg, facts = _build(code, _models())
    assert facts.query_provenance("x", _sink_node(cfg).node_id) is Provenance.UNTRUSTED


def test_goto_path_participates_in_must_join():
    code = r"""
        int external_read(void);
        int validate(int);
        void sink(int);
        void f(int skip) {
            int x = external_read();
            if (skip) goto use;
            if (!validate(x)) return;
        use:
            sink(x);
        }
    """
    cfg, facts = _build(code, _models())
    assert ValidationProperty.BOUNDS_CHECKED not in facts.query_validation_properties(
        "x", _sink_node(cfg).node_id
    )
