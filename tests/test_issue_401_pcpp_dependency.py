"""Regression tests for issue #401: AST preprocessing must be a core capability."""

from pathlib import Path
import tomllib


def test_ast_dependencies_are_core_runtime_dependencies():
    """A normal package install must include the parser and macro preprocessor."""
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    dependencies = pyproject["project"]["dependencies"]

    assert any(dep.startswith("pycparser>=") for dep in dependencies)
    assert any(dep.startswith("pcpp>=") for dep in dependencies)


def test_requirements_do_not_describe_pcpp_as_optional():
    requirements = Path("requirements.txt").read_text(encoding="utf-8")

    assert "pcpp>=1.30" in requirements
    assert "Optional C preprocessor" not in requirements
    assert "zero mandatory external dependencies" not in requirements
