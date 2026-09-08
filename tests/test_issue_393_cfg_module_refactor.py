from pycparser import c_parser

from cgull.cfg import build_cfg
from cgull.cfg.ast_events import (
    _deref_vars as extracted_deref_vars,
    _deref_vars_with_lines as extracted_deref_vars_with_lines,
    _find_value_producing_call as extracted_value_call,
    _is_nullish as extracted_is_nullish,
)
from cgull.cfg.construction import (
    _deref_vars,
    _deref_vars_with_lines,
    _find_value_producing_call,
    _is_nullish,
)


def _func(source: str):
    ast = c_parser.CParser().parse(source)
    return next(ext for ext in ast.ext if type(ext).__name__ == "FuncDef")


def _shape(cfg):
    return {
        node_id: (node.kind, tuple(node.successors), node.expr_str)
        for node_id, node in cfg.nodes.items()
    }


def test_historic_private_construction_helpers_remain_compatible():
    assert _deref_vars is extracted_deref_vars
    assert _deref_vars_with_lines is extracted_deref_vars_with_lines
    assert _find_value_producing_call is extracted_value_call
    assert _is_nullish is extracted_is_nullish


def test_refactored_construction_preserves_structured_control_flow():
    cfg = build_cfg(
        _func(
            """
            void f(int *p, int n) {
                int i = 0;
            again:
                if (p != 0 && n > 0) {
                    *p = i;
                } else {
                    goto done;
                }
                while (i < n) {
                    i = i + 1;
                    if (i == 2) continue;
                    if (i == 3) break;
                }
                switch (n) {
                    case 1: i = 4; break;
                    default: i = 5;
                }
                if (i < n) goto again;
            done:
                return;
            }
            """
        )
    )

    kinds = {node.kind for node in cfg.nodes.values()}
    assert {"if_cond", "while_cond", "switch_cond", "label", "goto", "return"} <= kinds
    assert cfg.entry in cfg.nodes
    assert cfg.blocks

    labels = {
        node.expr_str: node.node_id
        for node in cfg.nodes.values()
        if node.kind == "label"
    }
    gotos = [node for node in cfg.nodes.values() if node.kind == "goto"]
    assert labels["again"] in {succ for node in gotos for succ in node.successors}
    assert labels["done"] in {succ for node in gotos for succ in node.successors}


def test_refactored_event_extraction_preserves_allocation_and_call_metadata():
    cfg = build_cfg(
        _func(
            """
            void *malloc(unsigned long);
            void free(void *);
            void sink(void *);
            void f(void) {
                void *p = malloc(8);
                sink(p);
                free(p);
            }
            """
        )
    )

    allocation = next(node for node in cfg.nodes.values() if node.kind == "allocation")
    free_event = next(node for node in cfg.nodes.values() if node.kind == "free")
    sink_event = next(node for node in cfg.nodes.values() if node.expr_str.startswith("sink("))

    assert allocation.allocated == {"p"}
    assert allocation.calls[0].direct_callee == "malloc"
    assert allocation.calls[0].result_target == "p"
    assert free_event.freed == {"p"}
    assert sink_event.calls[0].direct_callee == "sink"
    assert sink_event.calls[0].actual_arguments == ("p",)


def test_cfg_shape_is_deterministic_after_module_split():
    source = """
        void f(int *p) {
            if (p) *p = 1;
            return;
        }
    """
    assert _shape(build_cfg(_func(source))) == _shape(build_cfg(_func(source)))
