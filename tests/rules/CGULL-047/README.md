# CGULL-047 corpus notes

CGULL-047 is semantic-model driven. The local `.cgull.toml` models `external_read` as a source, `validate` as a `bounds_checked` validator, and `sink` as requiring that property. `positive.c` covers direct unvalidated use and validation performed too late; `negative.c` covers fail-closed validation and trusted local data. Additional interprocedural and unknown-provenance cases live in `tests/test_trust_boundary_rule.py`.
