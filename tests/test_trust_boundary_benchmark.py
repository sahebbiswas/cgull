import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks" / "interprocedural" / "trust_boundary"
HASH_SEEDS = (1, 2147483647)

_SUBPROCESS_SCAN = r"""
import json
from pathlib import Path
import sys

from benchmarks.security_fact_support import build_security_context
from cgull.config import CGullConfig
from cgull.rules.trust_boundary import UnvalidatedExternalDataSinkRule
from cgull.semantic_models import parse_semantic_models

source = Path(sys.argv[1]).read_text(encoding="utf-8")
models = parse_semantic_models({"profiles": ["embedded-security"]})
ctx = build_security_context(source)
ctx.source_lines = source.splitlines()
rule = UnvalidatedExternalDataSinkRule()
CGullConfig(semantic_models=models).apply_to_rules([rule])
issues = rule.scan_ast("fixture.c", ctx)
print(json.dumps({
    "detected": bool(issues),
    "messages": [issue.message for issue in issues],
}, sort_keys=True))
"""


def _scan_in_subprocess(fixture_path: Path, hash_seed: int):
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = str(hash_seed)
    completed = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS_SCAN, str(fixture_path)],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _metrics(cases):
    metrics = {"cases": 0, "expected_positives": 0, "expected_negatives": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0, "known_gaps": 0}
    regressions = []
    for case in cases:
        fixture_path = CORPUS / case["file"]
        runs = [_scan_in_subprocess(fixture_path, seed) for seed in HASH_SEEDS]
        if runs[0] != runs[1]:
            regressions.append(
                f"{case['id']}: nondeterministic result across PYTHONHASHSEED "
                f"{HASH_SEEDS}: {runs}"
            )
            continue
        actual = runs[0]["detected"]
        expected = case["vulnerable"]
        metrics["cases"] += 1
        metrics["expected_positives" if expected else "expected_negatives"] += 1
        outcome = "tp" if expected and actual else "fn" if expected else "fp" if actual else "tn"
        metrics[outcome] += 1
        if "known_gap" in case:
            metrics["known_gaps"] += 1
        elif actual != expected:
            regressions.append(f"{case['id']}: expected detected={expected}, got {actual}")
        if actual and case.get("evidence", {}).get("missing"):
            text = "\n".join(runs[0]["messages"])
            missing = case["evidence"]["missing"]
            if not any(prop in text for prop in missing):
                regressions.append(f"{case['id']}: finding did not identify expected missing validation {missing}")
    return metrics, regressions


def test_embedded_trust_boundary_quality_gate():
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    ids = [case["id"] for case in manifest["cases"]]
    assert len(ids) == len(set(ids))
    assert all((CORPUS / case["file"]).is_file() for case in manifest["cases"])
    metrics, regressions = _metrics(manifest["cases"])
    assert not regressions, "; ".join(regressions)
    assert metrics == manifest["baseline"]


def test_embedded_trust_boundary_corpus_has_required_coverage():
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    cases = manifest["cases"]
    families = {case["family"] for case in cases}
    scenarios = {case["scenario"] for case in cases}
    assert {"mailbox_flash", "dma", "firmware_update", "mmio", "debug"} <= families
    assert {"early_return_guard", "if_else", "loop", "switch", "validation_after_sink", "typed_validation", "multiple_properties", "interprocedural_source_wrapper"} <= scenarios
    assert any(case["vulnerable"] for case in cases)
    assert any(not case["vulnerable"] for case in cases)
