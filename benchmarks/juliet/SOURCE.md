# Vendored Juliet subset

The fixtures in this directory are small, self-contained reductions of the
NIST Juliet 1.3 C/C++ test suite. They retain the CWE-specific vulnerable and
remediated sink patterns while removing the suite's support headers, network
inputs, and platform-specific build dependencies so C-GULL can scan each file
in isolation.

The upstream source is the [Juliet 1.3 C/C++ test suite](https://github.com/arichardson/juliet-test-suite-c), published from NIST's SARD suite. Each fixture's leading comment identifies its upstream CWE and pattern family.
