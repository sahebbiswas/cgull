from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "juliet-upstream.yml"
SOURCE_DOC = REPO_ROOT / "benchmarks" / "juliet" / "SOURCE.md"


def test_rule_changes_trigger_upstream_juliet_metrics_workflow():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert '"cgull/rules/**"' in text
    assert "run_juliet_upstream.py" in text
    assert "--format markdown" in text
    assert "--format json" in text
    assert "GITHUB_STEP_SUMMARY" in text
    assert "actions/upload-artifact@v4" in text


def test_upstream_snapshot_is_pinned_and_curated_subset_is_not_representative():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "f88433e3443648a17671398797a04ea1f8e1a274" in workflow

    source_doc = SOURCE_DOC.read_text(encoding="utf-8")
    assert "not** the canonical measurement" in source_doc
    assert "run_juliet_upstream.py" in source_doc
