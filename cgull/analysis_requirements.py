"""Declarative analysis requirements for rule-driven project preparation."""
from __future__ import annotations


FUNCTION_SUMMARY = "function-summary"
OWNERSHIP_SUMMARY = "ownership-summary"
VALUE_SUMMARY = "value-summary"
SECURITY_SUMMARY = "security-summary"
SIZE_FACTS = "size-facts"
POINTER_RANGE_FACTS = "pointer-range-facts"

ANALYSIS_REQUIREMENTS = (
    FUNCTION_SUMMARY,
    OWNERSHIP_SUMMARY,
    VALUE_SUMMARY,
    SECURITY_SUMMARY,
    SIZE_FACTS,
    POINTER_RANGE_FACTS,
)
ALL_ANALYSIS_REQUIREMENTS = frozenset(ANALYSIS_REQUIREMENTS)

REQUIREMENT_DEPENDENCIES = {
    OWNERSHIP_SUMMARY: frozenset({FUNCTION_SUMMARY}),
    POINTER_RANGE_FACTS: frozenset({SIZE_FACTS, VALUE_SUMMARY}),
}

PROJECT_SUMMARY_REQUIREMENTS = {
    FUNCTION_SUMMARY: "function",
    OWNERSHIP_SUMMARY: "ownership",
    VALUE_SUMMARY: "value",
    SECURITY_SUMMARY: "security",
}
PROJECT_SUMMARY_REQUIREMENT_FOR_DOMAIN = {
    domain: requirement for requirement, domain in PROJECT_SUMMARY_REQUIREMENTS.items()
}
PROJECT_SUMMARY_DOMAINS = tuple(
    PROJECT_SUMMARY_REQUIREMENTS[requirement]
    for requirement in ANALYSIS_REQUIREMENTS
    if requirement in PROJECT_SUMMARY_REQUIREMENTS
)


def dependency_closure(requirements):
    """Return a deterministic transitive closure in canonical requirement order."""
    required = set(requirements)
    unknown = required - ALL_ANALYSIS_REQUIREMENTS
    if unknown:
        raise ValueError(f"unknown analysis requirements: {', '.join(sorted(unknown))}")

    pending = list(required)
    while pending:
        requirement = pending.pop()
        for dependency in REQUIREMENT_DEPENDENCIES.get(requirement, ()):
            if dependency not in required:
                required.add(dependency)
                pending.append(dependency)
    return tuple(requirement for requirement in ANALYSIS_REQUIREMENTS if requirement in required)


def required_analysis_for_rules(rules):
    """Return requirements for active rules, conservatively handling legacy rules.

    Built-in rules explicitly own an ``analysis_requirements`` class attribute.
    The attribute is deliberately read from the concrete class rather than via
    inheritance: a third-party subclass must opt in explicitly, otherwise it
    receives the historical all-analysis behavior.
    """
    required = set()
    for rule in rules:
        rule_type = rule if isinstance(rule, type) else type(rule)
        declared = rule_type.__dict__.get("analysis_requirements")
        if declared is None:
            return ANALYSIS_REQUIREMENTS
        try:
            declared = set(declared)
        except TypeError:
            return ANALYSIS_REQUIREMENTS
        if declared - ALL_ANALYSIS_REQUIREMENTS:
            return ANALYSIS_REQUIREMENTS
        required.update(declared)
    return dependency_closure(required)


def project_summary_domains(requirements):
    """Return project domains implied by analysis requirements and dependencies."""
    closed = dependency_closure(requirements)
    return tuple(
        PROJECT_SUMMARY_REQUIREMENTS[requirement]
        for requirement in closed
        if requirement in PROJECT_SUMMARY_REQUIREMENTS
    )


def normalize_project_summary_domains(domains):
    """Validate project domains and include their transitive domain dependencies."""
    if domains is None:
        return PROJECT_SUMMARY_DOMAINS
    requested = set(domains)
    unknown = requested - set(PROJECT_SUMMARY_REQUIREMENT_FOR_DOMAIN)
    if unknown:
        raise ValueError(f"unknown project summary domains: {', '.join(sorted(unknown))}")
    requirements = {
        PROJECT_SUMMARY_REQUIREMENT_FOR_DOMAIN[domain] for domain in requested
    }
    return project_summary_domains(requirements)
