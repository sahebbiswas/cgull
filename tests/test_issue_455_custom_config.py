"""Compatibility regression for custom-named explicit C-GULL config files."""

from pathlib import Path
import tempfile

from cgull.project_state import read_logging_retention, resolve_project_state_root


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
