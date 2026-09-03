from cgull.cfg.call_graph import CallGraphFunction, build_call_graph
from cgull.cfg.dataflow import StructuredCFG
from cgull.cfg.fixed_point import FiniteLattice, FixedPointConfig, SCCFixedPointEngine
from cgull.cfg.model import CFGCall, CFGEvent


class _IntLattice(FiniteLattice[int]):
    max_height = 5

    def bottom(self, symbol):
        return 0

    def join(self, left, right):
        return max(left, right)

    def unknown(self, symbol, current):
        return 999


def _call(name):
    return CFGCall(direct_callee=name, callee_expression=name)


def _function(name, *callees):
    cfg = StructuredCFG()
    cfg.nodes[1] = CFGEvent(
        node_id=1,
        kind="statement",
        line_number=1,
        calls=tuple(_call(callee) for callee in callees),
    )
    return CallGraphFunction(name=name, cfg=cfg)


def test_self_recursive_scc_converges_to_fixed_point():
    graph = build_call_graph([_function("self", "self")])
    engine = SCCFixedPointEngine(graph, _IntLattice(), FixedPointConfig(max_iterations_per_scc=8))

    result = engine.run(lambda name, facts, config: min(3, facts[name] + 1))

    assert result.facts == {"self": 3}
    assert result.diagnostics == ()
    assert result.iterations_by_scc[("self",)] == 4


def test_mutual_recursion_uses_snapshot_updates_and_converges_deterministically():
    functions = [_function("b", "a"), _function("a", "b")]

    def solve(items):
        graph = build_call_graph(items)
        engine = SCCFixedPointEngine(graph, _IntLattice(), FixedPointConfig(max_iterations_per_scc=8))
        return engine.run(
            lambda name, facts, config: min(
                3,
                max([facts[callee] for callee in graph.callees(name)] or [0]) + 1,
            )
        )

    first = solve(functions)
    second = solve(reversed(functions))
    assert first.facts == {"a": 3, "b": 3}
    assert first.facts == second.facts
    assert first.iterations_by_scc == second.iterations_by_scc
    assert first.diagnostics == ()


def test_forced_iteration_limit_degrades_component_and_emits_diagnostic():
    graph = build_call_graph([_function("self", "self")])
    engine = SCCFixedPointEngine(graph, _IntLattice(), FixedPointConfig(max_iterations_per_scc=1))

    result = engine.run(lambda name, facts, config: facts[name] + 1)

    assert result.facts["self"] == 999
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "CONVERGENCE_LIMIT"
    assert result.diagnostics[0].functions == ("self",)
