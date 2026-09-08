"""AST preprocessing coverage guarantees.

Coverage enforcement lives in :mod:`cgull.ast_analyzer.performance` so the
public parser remains the optimized parser class rather than a wrapper.
"""

from .performance import ASTAnalyzer, CASTParser, CoverageDegradedError

__all__ = ["CASTParser", "ASTAnalyzer", "CoverageDegradedError"]
