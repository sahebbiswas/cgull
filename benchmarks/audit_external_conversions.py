#!/usr/bin/env python3
"""Reproduce #376's exact-CWE upstream measurement with per-entry evidence."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from benchmarks.run_juliet_upstream import run_benchmark, select_all_cases
from benchmarks.run_juliet import compute_metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('suite', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    suite = args.suite.resolve()
    cases = select_all_cases(suite, ['CWE-194', 'CWE-195', 'CWE-196'])
    if not cases:
        raise SystemExit('No CWE-194/195/196 Juliet cases found in the supplied suite')
    totals = {}
    entries = []
    scanned = evaluated = 0
    failed = []
    for index, (cwe, entry) in enumerate(cases):
        result = run_benchmark([(cwe, entry)])
        metrics = result['by_cwe'].get(cwe, {})
        counts = {key: metrics.get(key, 0) for key in ('tp', 'fp', 'tn', 'fn')}
        target = totals.setdefault(cwe, dict.fromkeys(counts, 0))
        for key, value in counts.items():
            target[key] += value
        entries.append({'cwe': cwe, 'entry': entry.relative_to(suite).as_posix(), **counts})
        scanned += result['scanned_files']
        evaluated += result['evaluated_functions']
        failed.extend(str(Path(p).relative_to(suite)) for p in result['failed_files'])
        if index % 100 == 0:
            print(f'{index}/{len(cases)} entries', flush=True)
    def revision(path):
        return subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    report = {
        'schema_version': 1, 'tool_revision': revision(ROOT),
        'juliet_revision': revision(suite), 'attribution': 'exact CWE for CGULL-049',
        'command': 'python benchmarks/audit_external_conversions.py /path/to/juliet --output docs/benchmarks/external-conversions-376.json',
        'selected_files': len(cases), 'scanned_files': scanned,
        'evaluated_functions': evaluated, 'failed_files': failed,
        'by_cwe': {cwe: compute_metrics(**counts) for cwe, counts in totals.items()},
        'entries': entries,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
