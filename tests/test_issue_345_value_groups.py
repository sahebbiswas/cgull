from pathlib import Path

import pytest

from cgull.call_effects import CallEffectConfigError, parse_call_effects
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.multifile import scan_translation_unit_group
from cgull.rules.format_string import FormatStringRule


def _format_scanner() -> CGullScanner:
    return CGullScanner(
        rules=[FormatStringRule()],
        engine_mode=AnalysisEngine.AST,
    )


def _format_issues(result):
    return [issue for issue in result.issues if issue.rule_id == "CGULL-002"]


def test_strcpy_literal_good_source_propagates_to_bad_style_sink():
    code = """
int printf(const char *fmt, ...);
char *strcpy(char *dst, const char *src);
static void sink(char *data) { printf(data); }
void entry(void) {
    char buffer[64] = "";
    char *data = buffer;
    strcpy(data, "fixedstringtest");
    sink(data);
}
"""
    result = _format_scanner().scan_text(code, file_path="issue345.c", quiet=True)
    assert _format_issues(result) == []


def test_bounded_memcpy_does_not_launder_prior_untrusted_destination():
    code = """
int printf(const char *fmt, ...);
void *memcpy(void *dst, const void *src, unsigned long n);
char *read_user(void);
void entry(void) {
    char *data = read_user();
    memcpy(data, "fixedstringtest", 1);
    printf(data);
}
"""
    result = _format_scanner().scan_text(code, file_path="issue345.c", quiet=True)
    assert len(_format_issues(result)) == 1


def test_bounded_strncpy_does_not_project_whole_literal_value():
    code = """
int printf(const char *fmt, ...);
char *strncpy(char *dst, const char *src, unsigned long n);
void entry(char *data) {
    strncpy(data, "fixedstringtest", 1);
    printf(data);
}
"""
    result = _format_scanner().scan_text(code, file_path="issue345.c", quiet=True)
    assert len(_format_issues(result)) == 1


def test_unknown_sink_parameter_remains_conservatively_reported():
    code = """
int printf(const char *fmt, ...);
void entry(char *data) { printf(data); }
"""
    result = _format_scanner().scan_text(code, file_path="issue345.c", quiet=True)
    assert len(_format_issues(result)) == 1


def test_grouped_source_files_preserve_literal_fact_across_direct_calls(tmp_path: Path):
    first = tmp_path / "flow54a.c"
    second = tmp_path / "flow54b.c"
    third = tmp_path / "flow54c.c"

    first.write_text(
        """
char *strcpy(char *dst, const char *src);
void stage_b(char *data);
void good(void) {
    char buffer[64] = "";
    char *data = buffer;
    strcpy(data, "fixedstringtest");
    stage_b(data);
}
""",
        encoding="utf-8",
    )
    second.write_text(
        """
void stage_c(char *data);
void stage_b(char *data) { stage_c(data); }
""",
        encoding="utf-8",
    )
    third.write_text(
        """
int printf(const char *fmt, ...);
void stage_c(char *data) { printf(data); }
""",
        encoding="utf-8",
    )

    isolated = _format_scanner().scan_path(str(third), quiet=True)
    assert len(_format_issues(isolated)) == 1

    grouped = scan_translation_unit_group(
        _format_scanner(),
        [first, second, third],
        quiet=True,
    )
    assert grouped.files_failed == 0
    assert _format_issues(grouped) == []


def test_grouped_source_findings_keep_original_member_location(tmp_path: Path):
    caller = tmp_path / "case_a.c"
    sink = tmp_path / "case_b.c"
    caller.write_text(
        "void sink(char *data);\nvoid bad(char *data) { sink(data); }\n",
        encoding="utf-8",
    )
    sink.write_text(
        "int printf(const char *fmt, ...);\nvoid sink(char *data) { printf(data); }\n",
        encoding="utf-8",
    )

    result = scan_translation_unit_group(_format_scanner(), [caller, sink], quiet=True)
    issues = _format_issues(result)
    assert len(issues) == 1
    assert Path(issues[0].file_path).resolve() == sink.resolve()
    assert issues[0].line_number == 2


def test_output_value_source_effect_can_be_declared_for_project_copy_wrapper():
    registry = parse_call_effects(
        [
            {
                "function": "copy_value",
                "outputs": [0],
                "output_value_sources": [[0, 1]],
            }
        ]
    )
    effect = registry.for_function("copy_value")
    assert effect is not None
    assert effect.output_value_sources == ((0, 1),)


def test_output_value_source_requires_declared_output_destination():
    with pytest.raises(CallEffectConfigError, match="must also be declared as an output parameter"):
        parse_call_effects(
            [
                {
                    "function": "copy_value",
                    "output_value_sources": [[0, 1]],
                }
            ]
        )


def test_bounded_output_cannot_declare_whole_value_source():
    with pytest.raises(CallEffectConfigError, match="cannot declare a whole-value source"):
        parse_call_effects(
            [
                {
                    "function": "copy_prefix",
                    "outputs": [0],
                    "output_value_sources": [[0, 1]],
                    "size_relationships": [[0, 2]],
                }
            ]
        )
