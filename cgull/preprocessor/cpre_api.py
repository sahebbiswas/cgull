"""Pinned CPRE public-API boundary for C-GULL preprocessor migration (#436).

C-GULL currently still owns its local symbolic preprocessor implementation under
``cgull.preprocessor``. This module is the explicit, versioned dependency
boundary that future migration work must use when consuming shared IR,
conditional structure, and exact Boolean reasoning from the ``cpre`` package.

Import only through this module (or the top-level ``cpre`` package symbols it
re-exports). Do **not** import ``cpre.model``, ``cpre.expressions``,
``cpre.structure``, ``cpre.proofs``, ``cpre.robdd``, ``cpre.parser``, or
``cpre.cpre`` from analyzer code — those are outside the supported downstream
contract documented by cpre.
"""

from __future__ import annotations

from importlib import metadata
from typing import Final, Mapping

import cpre

# Compatible release range for the symbolic-preprocessor migration surface.
# cpre 0.11.0 is the first release that exposes the public expression,
# lossless structure, and exact proof/witness APIs required by #436.
SUPPORTED_CPRE_VERSION_SPEC: Final[str] = ">=0.11.0,<0.12"
MIN_CPRE_VERSION: Final[tuple[int, int, int]] = (0, 11, 0)

# Accepted downstream-owned name mappings from cpre's symbolic migration gate.
# Keep these explicit so later adapters do not silently collapse categories.
STRUCTURE_DIAGNOSTIC_CODE_MAP: Final[Mapping[str, str]] = {
    # cgull local code -> cpre StructureDiagnosticCode value
    "invalid_macro": "malformed_macro_directive",
    "unexpected_tokens": "trailing_directive_text",
    "misplaced_directive": "unmatched_directive",
    "unterminated_block": "unterminated_conditional",
}

WITNESS_ATOM_KIND_MAP: Final[Mapping[str, str]] = {
    # cgull local witness category -> cpre WitnessAtomKind value
    "defined": "macro_defined",
    "macro_value": "macro_value",
    "predicate": "predicate",
}

# --- Symbolic expressions (top-level cpre only) ---
BooleanAtom = cpre.BooleanAtom
Expression = cpre.Expression
Constant = cpre.Constant
Variable = cpre.Variable
DefinedVariable = cpre.DefinedVariable
Predicate = cpre.Predicate
Negation = cpre.Negation
Conjunction = cpre.Conjunction
Disjunction = cpre.Disjunction
TRUE = cpre.TRUE
FALSE = cpre.FALSE
negate = cpre.negate
conjunction = cpre.conjunction
disjunction = cpre.disjunction
simplify = cpre.simplify
normalize = cpre.normalize
format_expression = cpre.format_expression
ordered_atoms = cpre.ordered_atoms
expression_predicates = cpre.expression_predicates
expression_to_dict = cpre.expression_to_dict
expression_from_dict = cpre.expression_from_dict

# --- Lossless conditional structure ---
parse_conditionals = cpre.parse_conditionals
ConditionalStructureTree = cpre.ConditionalStructureTree
ConditionalBlock = cpre.ConditionalBlock
ConditionalBranch = cpre.ConditionalBranch
ConditionalDirective = cpre.ConditionalDirective
DirectiveToken = cpre.DirectiveToken
StructuralSourceLocation = cpre.StructuralSourceLocation
StructuralSourceRange = cpre.StructuralSourceRange
StructureDiagnostic = cpre.StructureDiagnostic
StructureDiagnosticCode = cpre.StructureDiagnosticCode

# --- Exact Boolean proofs / witnesses ---
satisfiable = cpre.satisfiable
implies = cpre.implies
equivalent = cpre.equivalent
exact_simplify = cpre.exact_simplify
witness_assignment = cpre.witness_assignment
AnalysisOptions = cpre.AnalysisOptions
SatisfiabilityResult = cpre.SatisfiabilityResult
ProofResult = cpre.ProofResult
SimplificationResult = cpre.SimplificationResult
WitnessResult = cpre.WitnessResult
WitnessAssignment = cpre.WitnessAssignment
WitnessAtomKind = cpre.WitnessAtomKind

# --- Concrete preprocessing (separate readiness gate; not yet wired into AST) ---
preprocess_source = cpre.preprocess_source
PreprocessResult = cpre.PreprocessResult
MacroConfiguration = cpre.MacroConfiguration
PreprocessingContext = cpre.PreprocessingContext

__all__ = [
    "SUPPORTED_CPRE_VERSION_SPEC",
    "MIN_CPRE_VERSION",
    "STRUCTURE_DIAGNOSTIC_CODE_MAP",
    "WITNESS_ATOM_KIND_MAP",
    "installed_cpre_version",
    "assert_supported_cpre",
    "BooleanAtom",
    "Expression",
    "Constant",
    "Variable",
    "DefinedVariable",
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
    "ordered_atoms",
    "expression_predicates",
    "expression_to_dict",
    "expression_from_dict",
    "parse_conditionals",
    "ConditionalStructureTree",
    "ConditionalBlock",
    "ConditionalBranch",
    "ConditionalDirective",
    "DirectiveToken",
    "StructuralSourceLocation",
    "StructuralSourceRange",
    "StructureDiagnostic",
    "StructureDiagnosticCode",
    "satisfiable",
    "implies",
    "equivalent",
    "exact_simplify",
    "witness_assignment",
    "AnalysisOptions",
    "SatisfiabilityResult",
    "ProofResult",
    "SimplificationResult",
    "WitnessResult",
    "WitnessAssignment",
    "WitnessAtomKind",
    "preprocess_source",
    "PreprocessResult",
    "MacroConfiguration",
    "PreprocessingContext",
]


def installed_cpre_version() -> str:
    """Return the installed ``cpre`` distribution version string."""
    return metadata.version("cpre")


def _parse_version(version: str) -> tuple[int, ...]:
    """Parse a PEP 440-ish leading numeric release segment for range checks."""
    release = version.split("!", 1)[-1]
    release = release.split("+", 1)[0]
    release = release.split(".dev", 1)[0]
    release = release.split("a", 1)[0]
    release = release.split("b", 1)[0]
    release = release.split("rc", 1)[0]
    parts: list[int] = []
    for piece in release.split("."):
        if not piece.isdigit():
            break
        parts.append(int(piece))
    if not parts:
        raise ValueError(f"unrecognized cpre version: {version!r}")
    return tuple(parts)


def assert_supported_cpre(version: str | None = None) -> str:
    """Raise ``RuntimeError`` when *version* is outside the supported range.

    Returns the checked version string so callers can log or assert it.
    """
    checked = installed_cpre_version() if version is None else version
    parsed = _parse_version(checked)
    # SUPPORTED_CPRE_VERSION_SPEC is ">=0.11.0,<0.12"
    if parsed < MIN_CPRE_VERSION or parsed >= (0, 12):
        raise RuntimeError(
            f"cpre {checked} is outside the supported range "
            f"{SUPPORTED_CPRE_VERSION_SPEC} required by C-GULL (#436)"
        )
    return checked
