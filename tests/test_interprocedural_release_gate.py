from benchmarks.run_interprocedural_release_gate import (
    _acceptance_rule_checks,
    _evaluate_budgets,
)
from cgull.cfg.fixed_point import FiniteLattice, FixedPointConfig, SCCFixedPointEngine


class _Function:
    def __init__(self, name):
        self.name = name


class _Graph:
    functions = (_Function("a"), _Function("b"))
    bottom_up_sccs = (("a", "b"),)

    @staticmethod
    def callees(name):
        return {"b"} if name == "a" else {"a"}


class _GrowingLattice(FiniteLattice[int]):
    max_height = 8

    def bottom(self, symbol):
        return 0

    def join(self, left, right):
        return max(left, right)

    def unknown(self, symbol, current):
        return 99


def test_fixed_point_limit_is_visible_and_conservative():
    engine = SCCFixedPointEngine(
        _Graph(),
        _GrowingLattice(),
        FixedPointConfig(max_iterations_per_scc=1, max_provenance=8),
    )
    result = engine.run(lambda name, facts, config: facts[name] + 1)

    assert result.facts == {"a": 99, "b": 99}
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "CONVERGENCE_LIMIT"
    assert result.iterations_by_scc[("a", "b")] == 1


def test_release_budget_failures_are_machine_readable():
    performance = {
        "slow": {
            "scan_failed": False,
            "wall_seconds": 2.0,
            "peak_memory_bytes": 100,
        },
        "failed": {
            "scan_failed": True,
            "wall_seconds": 0.1,
            "peak_memory_bytes": 10,
        },
    }
    budgets = {
        "performance": {
            "max_wall_seconds": 1.0,
            "max_peak_memory_bytes": 50,
        }
    }

    failures = _evaluate_budgets(performance, budgets)

    assert any("slow wall time" in failure for failure in failures)
    assert any("slow peak memory" in failure for failure in failures)
    assert "failed scan failed" in failures


def test_data_dependent_cgull_001_acceptance_cases():
    result = _acceptance_rule_checks()

    assert result["success"], result["failures"]
    assert [(case["expected"], case["detected"]) for case in result["cases"]] == [
        (True, True),
        (False, False),
    ]
