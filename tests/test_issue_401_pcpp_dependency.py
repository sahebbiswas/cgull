"""Regression tests for issue #401: AST preprocessing must be a core capability."""

from pathlib import Path
import re


def test_ast_dependencies_are_core_runtime_dependencies():
    """A normal package install must include the parser and macro preprocessor."""
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    project_block = re.search(
        r"(?ms)^\[project\]\s*(.*?)(?=^\[[^]]+\])",
        pyproject,
    )

    assert project_block is not None
    dependencies_line = re.search(r"(?m)^dependencies\s*=\s*(\[[^\n]*\])", project_block.group(1))
    assert dependencies_line is not None
    assert '"pycparser>=2.21"' in dependencies_line.group(1)
    assert '"pcpp>=1.30"' in dependencies_line.group(1)


def test_requirements_do_not_describe_pcpp_as_optional():
    requirements = Path("requirements.txt").read_text(encoding="utf-8")

    assert "pcpp>=1.30" in requirements
    assert "Optional C preprocessor" not in requirements
    assert "zero mandatory external dependencies" not in requirements
