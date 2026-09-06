# Juliet benchmark sources

The fixtures in `benchmarks/juliet/testcases/` are small, self-contained
reductions of NIST Juliet 1.3. They are retained as fast regression fixtures;
they are **not** the canonical measurement of C-GULL's overall detection
precision or recall and their metrics should not be presented as representative
of the full Juliet suite.

The canonical detection-quality benchmark is `benchmarks/run_juliet_upstream.py`.
It runs against a pinned checkout of the upstream Juliet 1.3 C/C++ suite and
discovers ground-truth functions through Juliet's conventional `bad` and
`good*` names rather than a maintainer-authored per-file oracle. The PR workflow
uses a deterministic stratified selection across supported CWEs and flow
variants so results remain reproducible and bounded.

CI pins the public-domain Juliet mirror at commit
`f88433e3443648a17671398797a04ea1f8e1a274`. The source is the Juliet 1.3 C/C++
test suite published through NIST SARD. The upstream snapshot is intentionally
not copied into this repository; keeping it external avoids repository bloat
while making the exact benchmark source independently auditable.

Run the canonical benchmark against an existing checkout with:

```bash
python benchmarks/run_juliet_upstream.py /path/to/juliet-test-suite-c \
  --per-flow 2 --format markdown --output juliet-upstream.md
```

The legacy manifest runner (`benchmarks/run_juliet.py`) remains useful for fast,
focused regression testing. Each rule listed by one of those legacy oracles is
independently applicable to that function. The manifest's `rule_contracts`
section documents the source pattern and rationale for every expected rule.
