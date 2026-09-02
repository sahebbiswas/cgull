# CGULL-047 corpus notes

CGULL-047 is semantic-model driven. Its executable regression coverage lives in `tests/test_trust_boundary_rule.py`, where source, validator, and sink models are supplied explicitly. Generic corpus scans do not load a project semantic-model configuration, so C fixtures here would not be meaningful without extending the corpus harness to carry per-rule semantic models.
