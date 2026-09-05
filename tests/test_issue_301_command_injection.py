from cgull.ast_analyzer import CASTParser
from cgull.rules.command_injection import CommandInjectionRule
from cgull.semantic_models import parse_semantic_models


def _scan(code: str, models=None):
    ctx = CASTParser().parse(code)
    rule = CommandInjectionRule()
    if models is not None:
        rule._semantic_models = parse_semantic_models(models)
    return rule.scan_ast("issue_301.c", ctx)


def _source_models(extra_effects=None):
    return {
        "sources": [{"function": "external_command", "outputs": ["return"]}],
        "effects": list(extra_effects or []),
    }


def _sanitizer_models():
    return _source_models([
        {"function": "allowlist_command", "sanitizes": [0]},
    ])


def test_untrusted_command_crosses_three_helpers():
    code = r'''
char *external_command(void);
int system(const char *);
static void sink3(char *cmd) { system(cmd); }
static void sink2(char *cmd) { sink3(cmd); }
static void sink1(char *cmd) { sink2(cmd); }
void entry(void) {
    char *cmd = external_command();
    sink1(cmd);
}
'''
    issues = _scan(code, _source_models())
    assert len(issues) == 1
    assert issues[0].engine == "Interprocedural"
    assert "Untrusted command data" in issues[0].message
    assert "system(cmd)" in issues[0].message


def test_constant_command_is_safe():
    code = r'''
int system(const char *);
void entry(void) { system("/bin/true"); }
'''
    assert _scan(code) == []


def test_explicit_complete_sanitizer_is_safe():
    code = r'''
char *external_command(void);
void allowlist_command(char *);
int system(const char *);
void entry(void) {
    char *cmd = external_command();
    allowlist_command(cmd);
    system(cmd);
}
'''
    assert _scan(code, _sanitizer_models()) == []


def test_sanitizer_proof_is_killed_by_reassignment():
    code = r'''
char *external_command(void);
void allowlist_command(char *);
int system(const char *);
void entry(void) {
    char *cmd = external_command();
    allowlist_command(cmd);
    cmd = external_command();
    system(cmd);
}
'''
    issues = _scan(code, _sanitizer_models())
    assert len(issues) == 1
    assert "Untrusted command data" in issues[0].message


def test_sanitizer_on_only_one_branch_is_not_safe_after_join():
    code = r'''
char *external_command(void);
void allowlist_command(char *);
int system(const char *);
void entry(int enabled) {
    char *cmd = external_command();
    if (enabled) {
        allowlist_command(cmd);
    }
    system(cmd);
}
'''
    issues = _scan(code, _sanitizer_models())
    assert len(issues) == 1
    assert "Untrusted command data" in issues[0].message


def test_unknown_call_after_sanitizer_invalidates_proof():
    code = r'''
char *external_command(void);
void allowlist_command(char *);
void unknown_transform(char *);
int system(const char *);
void entry(void) {
    char *cmd = external_command();
    allowlist_command(cmd);
    unknown_transform(cmd);
    system(cmd);
}
'''
    issues = _scan(code, _sanitizer_models())
    assert len(issues) == 1
    assert "Untrusted command data" in issues[0].message


def test_concatenating_untrusted_component_remains_unsafe():
    code = r'''
char *external_command(void);
int system(const char *);
void entry(void) {
    char *tail = external_command();
    char *cmd = "/bin/echo " + tail;
    system(cmd);
}
'''
    issues = _scan(code, _source_models())
    assert len(issues) == 1
    assert "Untrusted command data" in issues[0].message


def test_unknown_call_does_not_launder_command():
    code = r'''
char *external_command(void);
void unknown_transform(char *);
int system(const char *);
void entry(void) {
    char *cmd = external_command();
    unknown_transform(cmd);
    system(cmd);
}
'''
    issues = _scan(code, _source_models())
    assert len(issues) == 1
    assert "Untrusted command data" in issues[0].message


def test_declarative_allowlisted_sink_wrapper_is_checked():
    code = r'''
char *external_command(void);
void run_command(char *);
void entry(void) {
    char *cmd = external_command();
    run_command(cmd);
}
'''
    models = {
        "sources": [{"function": "external_command", "outputs": ["return"]}],
        "sinks": [{
            "function": "run_command",
            "requirements": {"arg:0": ["allowlisted"]},
        }],
    }
    issues = _scan(code, models)
    assert len(issues) == 1
    assert "run_command(cmd)" in issues[0].message


def test_parse_fallback_preserves_legacy_conservative_behavior():
    code = "void f(char *cmd) { system(cmd); }"
    ctx = CASTParser().parse(code)
    ctx.has_pycparser = False
    ctx.pycparser_ast = None
    issues = CommandInjectionRule().scan_ast("issue_301.c", ctx)
    assert len(issues) == 1
    assert issues[0].engine == "Regex"
