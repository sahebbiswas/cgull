from pathlib import Path

from cgull.cli import build_parser
from cgull.fixes import apply_safe_fixes
from cgull.models import FixType, Issue, Severity


def _issue(path: Path, line: int, snippet: str, replacement: str | None, fix_type=FixType.SAFE_FIX):
    return Issue(
        rule_id="TEST-001",
        rule_name="test",
        impact=Severity.LOW,
        file_path=str(path),
        line_number=line,
        code_snippet=snippet,
        auto_fix_replacement=replacement,
        fix_type=fix_type,
    )


def test_parser_exposes_fix_and_write_flags():
    args = build_parser().parse_args(["scan", "sample.c", "--fix", "--write"])
    assert args.fix is True
    assert args.write is True


def test_noop_without_safe_fixes(tmp_path):
    source = tmp_path / "clean.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    result = apply_safe_fixes([], write=True)
    assert result.replacements == 0
    assert source.read_text(encoding="utf-8") == "int main(void) { return 0; }\n"


def test_multiple_safe_fixes_preserve_indentation_and_write_exact_output(tmp_path):
    source = tmp_path / "multi.c"
    source.write_text("void f(void) {\n    int *p;\n    int value;\n}\n", encoding="utf-8")
    issues = [
        _issue(source, 2, "int *p;", "int *p = NULL;"),
        _issue(source, 3, "int value;", "int value = 0;"),
    ]
    preview = apply_safe_fixes(issues, write=False)
    assert preview.replacements == 2
    assert source.read_text(encoding="utf-8") == "void f(void) {\n    int *p;\n    int value;\n}\n"

    applied = apply_safe_fixes(issues, write=True)
    assert applied.replacements == 2
    assert source.read_text(encoding="utf-8") == (
        "void f(void) {\n    int *p = NULL;\n    int value = 0;\n}\n"
    )


def test_suggested_fix_is_never_written(tmp_path):
    source = tmp_path / "suggested.c"
    source.write_text("strcpy(dst, src);\n", encoding="utf-8")
    issue = _issue(
        source,
        1,
        "strcpy(dst, src);",
        None,
        fix_type=FixType.SUGGESTED_FIX,
    )
    result = apply_safe_fixes([issue], write=True)
    assert result.replacements == 0
    assert source.read_text(encoding="utf-8") == "strcpy(dst, src);\n"


def test_conflicting_same_line_fixes_are_skipped(tmp_path):
    source = tmp_path / "conflict.c"
    source.write_text("int value;\n", encoding="utf-8")
    issues = [
        _issue(source, 1, "int value;", "int value = 0;"),
        _issue(source, 1, "int value;", "int value = 1;"),
    ]
    result = apply_safe_fixes(issues, write=True)
    assert result.replacements == 0
    assert len(result.conflicts) == 1
    assert source.read_text(encoding="utf-8") == "int value;\n"


def test_identical_same_line_fixes_are_deduplicated(tmp_path):
    source = tmp_path / "duplicate.c"
    source.write_text("int value;\n", encoding="utf-8")
    issue = _issue(source, 1, "int value;", "int value = 0;")
    result = apply_safe_fixes([issue, issue], write=True)
    assert result.eligible_issues == 2
    assert result.replacements == 1
    assert source.read_text(encoding="utf-8") == "int value = 0;\n"
