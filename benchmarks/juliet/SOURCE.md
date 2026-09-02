# Vendored Juliet subset

The fixtures in this directory are small, self-contained reductions of the
NIST Juliet 1.3 C/C++ test suite. They retain the CWE-specific vulnerable and
remediated sink patterns while removing the suite's support headers, network
inputs, and platform-specific build dependencies so C-GULL can scan each file
in isolation.

The upstream source is the [Juliet 1.3 C/C++ test suite](https://github.com/arichardson/juliet-test-suite-c), published from NIST's SARD suite. Each fixture's leading comment identifies its upstream CWE and pattern family.

Each rule listed by an oracle is independently applicable to that function.
The manifest's `rule_contracts` section documents the source pattern and
rationale for every expected rule. Tests verify that every oracle's rule IDs
belong to its CWE, have a contract, and match the declared source pattern in
the oracle function or its explicit helper functions.

The direct-null CWE-476 fixtures exercise `CGULL-004`, while the allocation
fixtures under CWE-690 exercise `CGULL-003`. The pointer-focused CWE-457
fixtures exercise `CGULL-021`; `CGULL-023` additionally applies only to the
interprocedural pair, where the local pointer is read as a call argument.
