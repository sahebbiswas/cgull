"""AST preprocessing coverage guarantees.

This module wraps the optimized parser with central checks for source constructs
whose security semantics depend on preprocessing.  These checks are deliberately
kept out of individual rules so a preprocessing failure cannot silently degrade
multiple consumers at once.
"""

from __future__ import annotations

from .performance import CASTParser as _PerformanceCASTParser
from .performance import ASTAnalyzer


class CoverageDegradedError(RuntimeError):
    """Raised when AST parsing succeeded but required preprocessing did not."""


def _has_unexpanded_offsetof(pycparser_ast) -> bool:
    """Return True when the parsed AST still contains a real ``offsetof`` call."""
    if pycparser_ast is None:
        return False

    try:
        from pycparser import c_ast
    except ImportError:
        return False

    class Visitor(c_ast.NodeVisitor):
        found = False

        def visit_FuncCall(self, node):
            if isinstance(node.name, c_ast.ID) and node.name.name == "offsetof":
                self.found = True
                return
            self.generic_visit(node)

    visitor = Visitor()
    visitor.visit(pycparser_ast)
    return visitor.found


class CASTParser(_PerformanceCASTParser):
    """Optimized parser that enforces security-relevant preprocessing coverage."""

    def parse(self, source_code, defined_syms=None, line_map=None):
        ctx = super().parse(source_code, defined_syms=defined_syms, line_map=line_map)

        # ``offsetof`` is a macro in supported C environments.  Container
        # recovery/layout reasoning expects it to have been expanded before
        # pycparser analysis.  If it survives as a FuncCall, continuing would
        # look like a successful AST scan while silently dropping that coverage.
        if ctx.has_pycparser and _has_unexpanded_offsetof(ctx.pycparser_ast):
            raise CoverageDegradedError(
                "AST preprocessing/layout precision degraded: offsetof(...) "
                "reached AST analysis unexpanded. Container-recovery and "
                "member-layout security checks cannot be considered complete."
            )

        return ctx


__all__ = ["CASTParser", "ASTAnalyzer", "CoverageDegradedError"]
