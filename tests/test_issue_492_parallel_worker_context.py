import pickle
from types import SimpleNamespace

from cgull import CGullScanner
from cgull.models import AnalysisEngine, Issue, ScanConfig, Severity
from cgull.parallel_workers import (
    ParallelScanWorkItem,
    _initialize_scan_worker,
    _prepare_local_summary_units,
    _scan_worker_item,
    build_parallel_work_item,
    serialized_work_item_size,
)
import cgull.parallel_workers as parallel_workers
from cgull.project_analysis import PreparedUnit, profile_key
from cgull.rules.base import BaseRule


class Issue492CustomRule(BaseRule):
    rule_id = "TEST-492"
    name = "Issue 492 custom rule"
    impact = Severity.LOW
    analysis_engine = AnalysisEngine.REGEX

    def scan_line(
        self,
        file_path,
        line_number,
        line_content,
        full_code,
        source_lines,
        masked_line_content="",
    ):
        if "issue492_marker" not in line_content:
            return []
        return [
            Issue(
                rule_id=self.rule_id,
                rule_name=self.name,
                impact=self.impact,
                file_path=file_path,
                line_number=line_number,
                message="issue 492 marker",
                engine="Regex",
            )
        ]


class Issue492OtherRule(Issue492CustomRule):
    rule_id = "TEST-492-B"
    name = "Issue 492 second custom rule"


def _issue_keys(result):
    return sorted(
        (issue.rule_id, issue.file_path, issue.line_number, issue.message)
        for issue in result.issues
    )


def test_compact_work_item_does_not_serialize_prepared_ast_graph(tmp_path):
    path = tmp_path / "large.c"
    source = "int f(void) { return 0; }\n" + ("/* prepared payload */\n" * 10000)
    path.write_text(source, encoding="utf-8")

    config = ScanConfig.create(
        rules=[Issue492CustomRule()],
        engine_mode=AnalysisEngine.HYBRID,
    )
    scanner = CGullScanner(config=config)
    key = profile_key(config.defined_syms)
    prepared = PreparedUnit(
        source=source,
        expanded=SimpleNamespace(expanded_text=source, line_map={}),
        _context=SimpleNamespace(
            project_summaries={"function": {"callee": "summary"}},
            analysis_session=object(),
        ),
    )
    scanner._project_units = {str(path): {key: prepared}}

    legacy_config = scanner._prepared_config_for_file(config, str(path))
    legacy_payload_size = len(
        pickle.dumps(
            (str(path), legacy_config, None, True, False),
            protocol=pickle.HIGHEST_PROTOCOL,
        )
    )
    work_item = build_parallel_work_item(
        scanner,
        config,
        str(path),
        include_project_summaries=False,
    )

    assert work_item.project_summaries is None
    assert all(name not in {"rules", "prepared_units"} for name, _ in work_item.config_overrides)
    assert serialized_work_item_size(work_item) * 20 < legacy_payload_size


def test_worker_context_is_reused_for_multiple_files_and_reinitialized_between_scans(tmp_path):
    first = tmp_path / "first.c"
    second = tmp_path / "second.c"
    first.write_text("int issue492_marker = 1;\n", encoding="utf-8")
    second.write_text("int issue492_marker = 2;\n", encoding="utf-8")

    config = ScanConfig.create(
        rules=[Issue492CustomRule()],
        engine_mode=AnalysisEngine.REGEX,
    )
    _initialize_scan_worker(config, None, True, False, None, None, {"old.c": {}})
    state = parallel_workers._WORKER_STATE
    assert state is not None
    rule_id = id(state.config.rules[0])

    first_result = _scan_worker_item(ParallelScanWorkItem(str(first)))
    second_result = _scan_worker_item(ParallelScanWorkItem(str(second)))
    assert [issue.rule_id for issue in first_result[0]] == ["TEST-492"]
    assert [issue.rule_id for issue in second_result[0]] == ["TEST-492"]
    assert id(parallel_workers._WORKER_STATE.config.rules[0]) == rule_id

    replacement = ScanConfig.create(
        rules=[Issue492OtherRule()],
        engine_mode=AnalysisEngine.REGEX,
    )
    _initialize_scan_worker(replacement, None, True, False, None, None, {"new.c": {}})
    reset_state = parallel_workers._WORKER_STATE
    assert reset_state is not None
    assert [rule.rule_id for rule in reset_state.config.rules] == ["TEST-492-B"]
    assert set(reset_state.project_units) == {"new.c"}
    assert "old.c" not in reset_state.project_units


def test_spawn_fallback_rebuilds_tu_locally_and_reattaches_project_summaries(tmp_path):
    path = tmp_path / "summary.c"
    path.write_text("int f(void) { return 0; }\n", encoding="utf-8")
    config = ScanConfig.create(rules=[], engine_mode=AnalysisEngine.AST)
    key = profile_key(config.defined_syms)
    summaries = {"function": {"external": "summary-marker"}}
    item = ParallelScanWorkItem(
        str(path),
        project_summaries={key: summaries},
    )

    units = _prepare_local_summary_units(item, config, None)

    assert key in units
    assert units[key].context.project_summaries == summaries
    assert units[key].context.analysis_session is None


def test_parallel_scan_preserves_custom_rule_semantics(tmp_path):
    for index in range(4):
        (tmp_path / f"file{index}.c").write_text(
            f"int issue492_marker = {index};\n",
            encoding="utf-8",
        )

    sequential = CGullScanner(
        rules=[Issue492CustomRule()],
        engine_mode=AnalysisEngine.REGEX,
    ).scan_path(str(tmp_path), jobs=1, quiet=True)
    parallel = CGullScanner(
        rules=[Issue492CustomRule()],
        engine_mode=AnalysisEngine.REGEX,
    ).scan_path(str(tmp_path), jobs=2, quiet=True)

    assert parallel.files_failed == 0
    assert _issue_keys(parallel) == _issue_keys(sequential)
    assert parallel.analysis_status_counts == sequential.analysis_status_counts


def test_independent_parallel_scans_do_not_reuse_prior_rule_state(tmp_path):
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    for directory in (first_dir, second_dir):
        for index in range(2):
            (directory / f"file{index}.c").write_text(
                f"int issue492_marker = {index};\n",
                encoding="utf-8",
            )

    first = CGullScanner(
        rules=[Issue492CustomRule()],
        engine_mode=AnalysisEngine.REGEX,
    ).scan_path(str(first_dir), jobs=2, quiet=True)
    second = CGullScanner(
        rules=[Issue492OtherRule()],
        engine_mode=AnalysisEngine.REGEX,
    ).scan_path(str(second_dir), jobs=2, quiet=True)

    assert {issue.rule_id for issue in first.issues} == {"TEST-492"}
    assert {issue.rule_id for issue in second.issues} == {"TEST-492-B"}
