from pycparser import c_parser

from cgull.cfg import Allocation, Initialization, Nullness, build_cfg, find_function_def


_PRELUDE = """
typedef unsigned long size_t;
void *malloc(size_t);
void free(void *);
int condition(void);
void use_int(int);
"""


def _cfg_for(body: str):
    parser = c_parser.CParser()
    ast = parser.parse(_PRELUDE + body)
    cfg = build_cfg(find_function_def(ast, "f"))
    cfg.analyze_dataflow()
    return cfg


def _node(cfg, fragment: str):
    return next(node for node in cfg.nodes.values() if fragment in node.expr_str)


def test_unresolved_goto_is_explicit_and_diagnostic_is_structured():
    cfg = _cfg_for(
        """
        void f(int *p) {
            if (condition())
                goto missing;
            *p = 1;
        }
        """
    )

    goto = _node(cfg, "goto missing")
    unknown = next(
        node
        for node in cfg.nodes.values()
        if getattr(node, "is_unknown_control_flow", False)
    )

    assert goto.successors == [unknown.node_id]
    assert unknown.kind == "unknown_control_flow"
    assert getattr(unknown, "unresolved_target") == "missing"
    assert _node(cfg, "*p = 1").node_id in unknown.successors

    assert len(cfg.diagnostics) == 1
    diagnostic = cfg.diagnostics[0]
    assert diagnostic.code == "CFG_UNRESOLVED_GOTO"
    assert diagnostic.target == "missing"
    assert diagnostic.source_location == goto.source_location


def test_unresolved_goto_degrades_nullness_and_initialization():
    cfg = _cfg_for(
        """
        void f(int cond) {
            int *p = 0;
            int value;
            if (cond)
                goto missing;
            value = 7;
            *p = value;
        }
        """
    )

    sink = _node(cfg, "*p = value")
    assert cfg.query_nullness("p", sink.node_id) == Nullness.MAYBE_NULL
    assert (
        cfg.query_initialization("value", sink.node_id)
        == Initialization.MAYBE_INITIALIZED
    )


def test_unresolved_goto_degrades_lifetime_for_uaf_and_double_free_sinks():
    cfg = _cfg_for(
        """
        void f(char *p, int cond) {
            free(p);
            if (cond)
                goto missing;
            p[0] = 'x';
            free(p);
        }
        """
    )

    use = _node(cfg, "p[0] = 'x'")
    source_last_free = min(
        (node for node in cfg.nodes.values() if node.kind == "free"),
        key=lambda node: node.node_id,
    )

    assert cfg.query_allocation("p", use.node_id) == Allocation.MAYBE_FREED
    assert cfg.query_allocation("p", source_last_free.node_id) == Allocation.MAYBE_FREED


def test_unresolved_goto_output_is_deterministic():
    source = """
        void f(int *p) {
            if (condition())
                goto absent;
            *p = 3;
        }
    """
    first = _cfg_for(source)
    second = _cfg_for(source)

    def snapshot(cfg):
        return (
            sorted(
                (
                    node.node_id,
                    node.kind,
                    node.expr_str,
                    tuple(node.successors),
                    getattr(node, "unresolved_target", None),
                )
                for node in cfg.nodes.values()
            ),
            [
                (
                    diag.code,
                    diag.message,
                    diag.target,
                    diag.source_location.line_number,
                    diag.source_location.column_number,
                )
                for diag in cfg.diagnostics
            ],
        )

    assert snapshot(first) == snapshot(second)
