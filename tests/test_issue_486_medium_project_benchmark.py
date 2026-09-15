from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


MODULE_PATH = Path(__file__).parents[1] / "benchmarks" / "benchmark_medium_project.py"
SPEC = importlib.util.spec_from_file_location("benchmark_medium_project", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


def test_generated_medium_project_is_deterministic_and_exercises_nested_headers(tmp_path):
    project = benchmark.generate_medium_project(
        tmp_path,
        modules=3,
        functions_per_module=2,
        statements_per_function=2,
    )
    first = benchmark.workload_manifest(project)

    api = (project / "include" / "bench_api.h").read_text(encoding="utf-8")
    module = (project / "src" / "module_02.c").read_text(encoding="utf-8")
    assert '#include "bench_types.h"' in api
    assert '#include "bench_api.h"' in module
    assert "module_01_entry" in module
    assert "benchmark_known_issue" in module
    assert first["file_count"] == 5
    assert first["physical_lines"] > 0

    project = benchmark.generate_medium_project(
        tmp_path,
        modules=3,
        functions_per_module=2,
        statements_per_function=2,
    )
    assert benchmark.workload_manifest(project) == first


def test_tiny_end_to_end_sample_reports_required_phase_telemetry_and_volume(tmp_path):
    project = benchmark.generate_medium_project(
        tmp_path,
        modules=2,
        functions_per_module=1,
        statements_per_function=1,
    )

    sample = benchmark.run_sample(project, mode="tu", jobs=1, repetition=0)

    required = {
        "file_discovery_seconds",
        "tu_include_expansion_seconds",
        "parser_seconds",
        "project_preparation_seconds",
        "project_indexing_seconds",
        "project_summary_construction_seconds",
        "rule_execution_aggregate_seconds",
        "worker_execution_wall_seconds",
        "worker_startup_ipc_collection_residual_seconds",
        "aggregate_file_analysis_seconds",
        "total_wall_seconds",
    }
    assert required <= sample.phases.keys()
    assert sample.wall_seconds > 0.0
    assert sample.phases["total_wall_seconds"] == sample.wall_seconds
    assert sample.analyzed_lines > 0
    assert sample.unique_source_lines > 0
    assert sample.expanded_analysis_lines > sample.analyzed_lines
    assert sample.semantic_digest
    assert sample.semantics.files_failed == 0


def _sample(mode: str, jobs: int, semantics, *, expanded_analysis_lines: int = 1200):
    return benchmark.Sample(
        mode=mode,
        jobs=jobs,
        repetition=0,
        wall_seconds=1.0,
        analyzed_lines=1000,
        unique_source_lines=1000,
        expanded_analysis_lines=expanded_analysis_lines,
        throughput_kloc_per_sec=1.0,
        peak_rss_bytes=None,
        phases={"total_wall_seconds": 1.0},
        finding_count=len(semantics.findings),
        parse_fallback_count=0,
        semantic_digest=benchmark._semantic_digest(semantics),
        semantics=semantics,
    )


def test_parity_requires_identical_semantics_across_jobs_within_a_mode():
    baseline = benchmark.SemanticSnapshot(
        findings=(("fp", "CGULL-X", "a.c", 1, 1, "message"),),
        parser_status_counts=(("pycparser_success", 2),),
        files_discovered=2,
        files_analyzed=2,
        files_ignored=0,
        files_failed=0,
        scan_errors=(),
    )
    changed_accounting = benchmark.SemanticSnapshot(
        findings=baseline.findings,
        parser_status_counts=baseline.parser_status_counts,
        files_discovered=2,
        files_analyzed=1,
        files_ignored=0,
        files_failed=0,
        scan_errors=(),
    )

    result = benchmark.validate_parity(
        [_sample("file", 1, baseline), _sample("file", 2, changed_accounting)]
    )

    assert result["passes"] is False
    assert result["within_mode_jobs_and_repetitions_match"] is False


def test_parity_requires_identical_expanded_volume_across_jobs_within_a_mode():
    semantics = benchmark.SemanticSnapshot(
        findings=(),
        parser_status_counts=(("pycparser_success", 2),),
        files_discovered=2,
        files_analyzed=2,
        files_ignored=0,
        files_failed=0,
        scan_errors=(),
    )

    result = benchmark.validate_parity(
        [
            _sample("tu", 1, semantics, expanded_analysis_lines=1200),
            _sample("tu", 2, semantics, expanded_analysis_lines=1199),
        ]
    )

    assert result["passes"] is False
    assert result["within_mode_jobs_and_repetitions_match"] is False


def test_cross_mode_parity_compares_findings_without_requiring_same_file_accounting():
    file_semantics = benchmark.SemanticSnapshot(
        findings=(("fp", "CGULL-X", "a.c", 1, 1, "message"),),
        parser_status_counts=(("pycparser_success", 3),),
        files_discovered=3,
        files_analyzed=3,
        files_ignored=0,
        files_failed=0,
        scan_errors=(),
    )
    tu_semantics = benchmark.SemanticSnapshot(
        findings=file_semantics.findings,
        parser_status_counts=(("pycparser_success", 2),),
        files_discovered=3,
        files_analyzed=2,
        files_ignored=0,
        files_failed=0,
        scan_errors=(),
    )

    result = benchmark.validate_parity(
        [_sample("file", 1, file_semantics), _sample("tu", 1, tu_semantics)]
    )

    assert result["passes"] is True
    assert result["cross_mode_findings_match"] is True
