from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "juliet-upstream.yml"
SOURCE_DOC = REPO_ROOT / "benchmarks" / "juliet" / "SOURCE.md"


def test_rule_changes_trigger_upstream_juliet_metrics_workflow():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert '"cgull/rules/**"' in text
    # Pull requests keep the bounded deterministic sample, while issue #352
    # adds one explicit workflow_dispatch path for a full CGULL-049 run.
    assert text.count("python benchmarks/run_juliet_upstream.py") == 2
    assert "--per-flow 2 --format markdown" in text
    assert "--json-output juliet-upstream.json" in text
    assert "full_cgull_049:" in text
    assert "--cwe CWE-194 --cwe CWE-195 --cwe CWE-196 --cwe CWE-197 --all" in text
    assert "--json-output cgull-049-full.json" in text
    assert "GITHUB_STEP_SUMMARY" in text
    assert "actions/upload-artifact@" in text


def test_upstream_snapshot_is_pinned_and_curated_subset_is_not_representative():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "f88433e3443648a17671398797a04ea1f8e1a274" in workflow

    source_doc = SOURCE_DOC.read_text(encoding="utf-8")
    assert "not** the canonical measurement" in source_doc
    assert "run_juliet_upstream.py" in source_doc
