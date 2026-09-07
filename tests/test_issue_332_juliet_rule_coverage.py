import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmarks.run_juliet import CWE_RULE_MAP
from cgull.rules import RULE_REGISTRY


MATRIX_PATH = REPO_ROOT / "benchmarks" / "juliet" / "rule_coverage.json"
VALID_STATUSES = {"measured", "no-Juliet-equivalent", "not-yet-measured"}


def _load_matrix():
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


def _measured_cwes_by_rule():
    result = {}
    for cwe, rule_ids in CWE_RULE_MAP.items():
        for rule_id in rule_ids:
            result.setdefault(rule_id, set()).add(cwe)
    return result


def test_juliet_rule_coverage_matrix_covers_active_registry_exactly():
    matrix = _load_matrix()
    entries = matrix["rules"]
    rule_ids = [entry["rule_id"] for entry in entries]

    assert matrix["schema_version"] == 1
    assert len(rule_ids) == len(set(rule_ids)), "coverage matrix contains duplicate rule IDs"
    assert set(rule_ids) == set(RULE_REGISTRY), (
        "Juliet coverage matrix must classify every active rule and contain no stale rules"
    )


def test_measured_status_is_backed_by_canonical_juliet_mapping():
    entries = {entry["rule_id"]: entry for entry in _load_matrix()["rules"]}
    measured = _measured_cwes_by_rule()

    for rule_id, entry in entries.items():
        assert entry["status"] in VALID_STATUSES
        if entry["status"] == "measured":
            assert rule_id in measured, f"{rule_id} claims measured status without CWE_RULE_MAP coverage"
            assert set(entry.get("juliet_cwes", [])) == measured[rule_id]
        else:
            assert rule_id not in measured, (
                f"{rule_id} is wired into CWE_RULE_MAP and must be classified as measured"
            )
            assert entry.get("reason", "").strip(), f"{rule_id} needs an explicit coverage rationale"


def test_no_juliet_equivalent_entries_do_not_claim_measured_cwes():
    for entry in _load_matrix()["rules"]:
        if entry["status"] == "no-Juliet-equivalent":
            assert not entry.get("juliet_cwes"), (
                f"{entry['rule_id']} cannot claim Juliet CWE measurement while marked no-Juliet-equivalent"
            )
