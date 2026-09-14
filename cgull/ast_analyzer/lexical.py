"""Coordinate-preserving helpers for lexical fallback extraction."""

import re


def body_statements(body):
    """Yield (physical offset, text), retaining simple multiline statements.

    Scope and control-flow boundaries remain separate. Unknown syntax is left
    conservative rather than assigning a continuation to the following line.
    """
    pending = []
    start = 0
    for index, line in enumerate(body.splitlines()):
        boundary = (
            not line.strip()
            or line.strip() in {"{", "}"}
            or re.match(r"\s*(?:if|else|while|for|switch|do)\b", line)
        )
        if boundary:
            if pending:
                yield start, "\n".join(pending)
                pending = []
            yield index, line
            continue
        if not pending:
            start = index
        pending.append(line)
        if ';' in line or line.rstrip().endswith(('}', '{')):
            yield start, "\n".join(pending)
            pending = []
    if pending:
        yield start, "\n".join(pending)
