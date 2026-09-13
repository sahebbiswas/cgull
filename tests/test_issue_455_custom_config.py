"""Compatibility regressions for issue #455 logging bootstrap."""

from pathlib import Path
import tempfile

from cgull.project_state import (
    DEFAULT_LOG_RETENTION_RUNS,
    read_logging_retention,
    resolve_project_state_root,
)


def test_custom_named_explicit_config_controls_logging_state():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        project = base / "project"
        target_dir = base / "other" / "src"
        project.mkdir()
        target_dir.mkdir(parents=True)
        config = project / "cgull-dev.toml"
        config.write_text("[logging]\nretention_runs = 7\n", encoding="utf-8")

        assert resolve_project_state_root([target_dir], str(config)) == str(project.resolve())
        assert read_logging_retention([target_dir], str(config)) == 7


def test_non_table_pyproject_tool_section_falls_back_for_retention():
    with tempfile.TemporaryDirectory() as tmpdir:
        project = Path(tmpdir)
        pyproject = project / "pyproject.toml"
        pyproject.write_text('tool = "not-a-table"\n', encoding="utf-8")

        assert read_logging_retention([project], str(pyproject)) == DEFAULT_LOG_RETENTION_RUNS
        assert resolve_project_state_root([project], str(pyproject)) == str(project.resolve())
