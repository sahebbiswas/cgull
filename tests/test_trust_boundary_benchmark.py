import json
from pathlib import Path

from benchmarks.security_fact_support import build_security_context
from cgull.config import CGullConfig
from cgull.rules.trust_boundary import UnvalidatedExternalDataSinkRule
from cgull.semantic_models import parse_semantic_models


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks" / "interprocedural" / "trust_boundary"


def _scan(source: str):
    models = parse_semantic_models({"profiles": ["embedded-security"]})
    ctx = build_security_context(source)
    ctx.source_lines = source.splitlines()
    rule = UnvalidatedExternalDataSinkRule()
    CGullConfig(semantic_models=models).apply_to_rules([rule])
    return rule.scan_ast("fixture.c", ctx)


def _metrics(cases):
    metrics = {"cases": 0, "expected_positives": 0, "expected_negatives": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0, "known_gaps": 0}
    regressions = []
    for case in cases:
        source = (CORPUS / case["file"]).read_text(encoding="utf-8")
        runs = [_scan(source), _scan(source)]
        detected = [bool(issues) for issues in runs]
        if detected[0] != detected[1]:
            regressions.append(f"{case['id']}: nondeterministic detection {detected}")
            continue
        actual = detected[0]
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
            text = "\n".join(issue.message for issue in runs[0])
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
