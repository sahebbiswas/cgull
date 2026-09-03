from cgull.ast_analyzer import CASTContext
from cgull.call_effects import BUILTIN_CALL_EFFECTS, CallEffectModel
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine, Confidence, FixType
from cgull.rules.format_string import FormatStringRule
from cgull.semantic_models import (
    SemanticLocation,
    SemanticLocationKind,
    SemanticModelRegistry,
    SourceModel,
)


def _scan(code: str, rule=None, engine=AnalysisEngine.HYBRID):
    scanner = CGullScanner(
        rules=[rule or FormatStringRule()],
        engine_mode=engine,
    )
    return scanner.scan_text(code, file_path="issue299.c", quiet=True)


def test_literal_format_through_three_helpers_is_safe():
    code = """
int printf(const char *fmt, ...);
const char *one(const char *value) { return value; }
const char *two(const char *value) { return one(value); }
const char *three(const char *value) { return two(value); }
void entry(void) { printf(three("fixed: %s"), "ok"); }
"""
    result = _scan(code)
    assert [issue for issue in result.issues if issue.rule_id == "CGULL-002"] == []


def test_untrusted_format_through_three_helpers_reports_source_to_sink_flow():
    code = """
int printf(const char *fmt, ...);
char *read_user(void);
const char *one(const char *value) { return value; }
const char *two(const char *value) { return one(value); }
const char *three(const char *value) { return two(value); }
void entry(void) { printf(three(read_user())); }
"""
    registry = SemanticModelRegistry(
        sources={
            "read_user": SourceModel(
                function="read_user",
                outputs=(SemanticLocation(SemanticLocationKind.RETURN),),
            )
        }
    )
    rule = FormatStringRule()
    rule._semantic_models = registry

    result = _scan(code, rule)
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-002"]
    assert len(issues) == 1
    assert issues[0].engine == "Interprocedural"
    assert "Caller-controlled non-literal format string" in issues[0].message
    assert "Flow:" in issues[0].message
    assert "read_user" in issues[0].message
    assert issues[0].line_number == 7


def test_unknown_unresolved_format_is_reported_with_limited_confidence():
    code = """
int printf(const char *fmt, ...);
char *unknown_format(void);
void entry(void) { printf(unknown_format()); }
"""
    result = _scan(code)
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-002"]
    assert len(issues) == 1
    assert issues[0].confidence is Confidence.LIMITED
    assert "could not be proven" in issues[0].message


def test_modeled_wrapper_format_argument_uses_same_value_fact_policy():
    code = """
void log_wrapper(const char *fmt, ...);
void entry(char *user) {
    log_wrapper(user);
    log_wrapper("fixed");
}
"""
    wrapper = CallEffectModel(function="log_wrapper", format_argument=0)
    registry = SemanticModelRegistry(
        call_effects=BUILTIN_CALL_EFFECTS.merged({"log_wrapper": wrapper})
    )
    rule = FormatStringRule()
    rule._semantic_models = registry

    result = _scan(code, rule)
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-002"]
    assert len(issues) == 1
    assert issues[0].line_number == 4
    assert "log_wrapper" in issues[0].message


def test_mutable_local_literal_requires_storage_integrity_before_suppression():
    code = """
int printf(const char *fmt, ...);
char *fgets(char *s, int n, void *stream);
void entry(void) {
    char format[32] = "fixed string";
    fgets(format, sizeof(format), 0);
    printf(format);
}
"""
    result = _scan(code)
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-002"]
    assert len(issues) == 1
    assert issues[0].line_number == 7


def test_directive_bearing_local_literal_is_not_suppressed():
    code = """
int printf(const char *fmt, ...);
void entry(void) {
    char format[] = "%x %x";
    printf(format);
}
"""
    result = _scan(code)
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-002"]
    assert len(issues) == 1


def test_single_argument_printf_keeps_safe_fix():
    code = """
int printf(const char *fmt, ...);
void entry(char *user) { printf(user); }
"""
    result = _scan(code)
    issue = next(issue for issue in result.issues if issue.rule_id == "CGULL-002")
    assert issue.fix_type is FixType.SAFE_FIX
    assert issue.auto_fix_replacement == 'printf("%s", user)'


def test_variadic_printf_does_not_offer_behavior_changing_safe_fix():
    code = """
int printf(const char *fmt, ...);
char *get_fmt(void);
void entry(int count) { printf(get_fmt(), count); }
"""
    result = _scan(code)
    issue = next(issue for issue in result.issues if issue.rule_id == "CGULL-002")
    assert issue.fix_type is FixType.SUGGESTED_FIX
    assert issue.auto_fix_replacement is None


def test_regex_mode_keeps_existing_syntactic_behavior():
    code = """
int printf(const char *fmt, ...);
void entry(char *user) { printf(user); }
"""
    result = _scan(code, engine=AnalysisEngine.REGEX)
    issues = [issue for issue in result.issues if issue.rule_id == "CGULL-002"]
    assert len(issues) == 1
    assert issues[0].engine == "Regex"


def test_ast_parse_fallback_keeps_finding_with_limited_semantics():
    code = """int printf(const char *fmt, ...);
void entry(char *user) { printf(user); }
"""
    context = CASTContext(
        functions=[],
        global_variables={},
        source_lines=code.splitlines(),
        raw_source=code,
        clean_source=code,
    )
    issues = FormatStringRule().scan_ast("issue299.c", context)
    assert len(issues) == 1
    assert issues[0].engine == "Regex"
