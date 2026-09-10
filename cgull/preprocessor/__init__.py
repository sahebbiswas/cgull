"""Symbolic preprocessor analysis; independent of concrete preprocessing."""

from .expressions import (
    BooleanAtom,
    Expression,
    Constant,
    Variable,
    Defined,
    Predicate,
    Negation,
    Conjunction,
    Disjunction,
    TRUE,
    FALSE,
    negate,
    conjunction,
    disjunction,
    simplify,
    normalize,
    format_expression,
    expression_atoms,
    ordered_atoms,
    expression_predicates,
    expression_to_dict,
    expression_from_dict,
)

__all__ = [
    "BooleanAtom",
    "Expression",
    "Constant",
    "Variable",
    "Defined",
    "Predicate",
    "Negation",
    "Conjunction",
    "Disjunction",
    "TRUE",
    "FALSE",
    "negate",
    "conjunction",
    "disjunction",
    "simplify",
    "normalize",
    "format_expression",
    "expression_atoms",
    "ordered_atoms",
    "expression_predicates",
    "expression_to_dict",
    "expression_from_dict",
]

from .directives import (
    SourceLocation,
    SourceRange,
    DirectiveToken,
    StructureDiagnostic,
    ConditionalDirective,
    ConditionalBranch,
    ConditionalBlock,
    ConditionalTree,
    parse_conditional_directives,
)

__all__ += [
    "SourceLocation", "SourceRange", "DirectiveToken", "StructureDiagnostic",
    "ConditionalDirective", "ConditionalBranch", "ConditionalBlock",
    "ConditionalTree", "parse_conditional_directives",
]

from .robdd import (
    AnalysisLimitExceeded,
    BDD,
    ResourceLimits,
    equivalent,
    satisfiable,
    implies,
    witness_assignment,
    exact_simplify,
)

__all__ += [
    "AnalysisLimitExceeded", "BDD", "ResourceLimits", "equivalent",
    "satisfiable", "implies", "witness_assignment", "exact_simplify",
]
