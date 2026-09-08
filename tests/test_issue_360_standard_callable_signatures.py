import pytest

from cgull.ast_analyzer import CASTParser, resolve_direct_call_signature
from cgull.cfg import find_function_def
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule
from cgull.semantic_models import SemanticModelRegistry


def _issues(source: str):
    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    return IntegerNarrowingCastRule().scan_ast("issue360.c", ctx)


def _signature(source: str):
    from pycparser import c_ast

    ctx = CASTParser().parse(source)
    assert ctx.has_pycparser
    funcdef = find_function_def(ctx.pycparser_ast, "caller")
    calls = []

    class Visitor(c_ast.NodeVisitor):
        def visit_FuncCall(self, node):
            calls.append(node)

    Visitor().visit(funcdef)
    assert len(calls) == 1
    return resolve_direct_call_signature(ctx, funcdef, calls[0])


_REQUIRED_CASES = [
    ("malloc(n);", "void *malloc(size_t);"),
    ("memcpy(dst, src, n);", "void *memcpy(void *, const void *, size_t);"),
    ("memmove(dst, src, n);", "void *memmove(void *, const void *, size_t);"),
    ("strncpy(dst, src, n);", "char *strncpy(char *, const char *, size_t);"),
]


def _source(call: str, prototype: str = "", safe: bool = False) -> str:
    guard = "if (n < 0) return;" if safe else ""
    return f"""
{prototype}
void caller(int n, char *dst, const char *src) {{
    {guard}
    {call}
}}
"""


@pytest.mark.parametrize("call,prototype", _REQUIRED_CASES)
def test_required_standard_apis_match_visible_prototype_classification(call, prototype):
    fallback = _issues(_source(call))
    visible = _issues(_source(call, prototype))
    assert [issue.cwe_id for issue in fallback] == ["CWE-195"]
    assert [issue.cwe_id for issue in visible] == ["CWE-195"]


@pytest.mark.parametrize("call,prototype", _REQUIRED_CASES)
def test_required_standard_apis_accept_range_proven_safe_signed_lengths(call, prototype):
    assert _issues(_source(call, safe=True)) == []
    assert _issues(_source(call, prototype, safe=True)) == []


def test_posix_read_uses_typedef_backed_size_parameter_without_host_width_inference():
    fallback = _issues("""
void caller(int n, char *buffer) {
    read(0, buffer, n);
}
""")
    visible = _issues("""
ssize_t read(int, void *, size_t);
void caller(int n, char *buffer) {
    read(0, buffer, n);
}
""")
    assert [issue.cwe_id for issue in fallback] == ["CWE-195"]
    assert [issue.cwe_id for issue in visible] == ["CWE-195"]

    signature = _signature("""
void caller(int n, char *buffer) {
    read(0, buffer, n);
}
""")
    assert signature is not None and signature.resolved
    assert signature.provenance == "posix"
    assert signature.return_type == "ssize_t"
    assert signature.parameters[2].type_name == "size_t"


def test_unnamed_visible_parameters_match_builtin_destination_types():
    fallback = _issues(_source("memcpy(dst, src, n);"))
    unnamed = _issues(_source("memcpy(dst, src, n);", "void *memcpy(void *, const void *, size_t);"))
    assert [issue.cwe_id for issue in fallback] == [issue.cwe_id for issue in unnamed] == ["CWE-195"]


def test_visible_declaration_overrides_builtin_even_when_it_disagrees():
    source = """
void *malloc(int size);
void caller(int n) {
    malloc(n);
}
"""
    signature = _signature(source)
    assert signature is not None and signature.resolved
    assert signature.provenance == "file-declaration"
    assert signature.parameters[0].type_name == "int"
    assert _issues(source) == []


def test_unspecified_or_conflicting_visible_declaration_never_falls_back():
    unspecified = """
void *malloc();
void caller(int n) { malloc(n); }
"""
    signature = _signature(unspecified)
    assert signature is not None and signature.resolved
    assert not signature.has_prototype
    assert signature.provenance == "file-declaration"
    assert _issues(unspecified) == []

    conflicting = """
void *malloc(int size);
void *malloc(unsigned int size);
void caller(int n) { malloc(n); }
"""
    signature = _signature(conflicting)
    assert signature is not None and not signature.resolved
    assert signature.provenance == "conflicting-declarations"
    assert _issues(conflicting) == []


@pytest.mark.parametrize(
    "binding",
    [
        "int malloc = 0;",
        "void *(*malloc)(int) = 0;",
    ],
)
def test_same_named_local_binding_blocks_builtin_fallback(binding):
    source = f"""
void caller(int n) {{
    {binding}
    malloc(n);
}}
"""
    assert _signature(source) is None
    assert _issues(source) == []


def test_variadic_model_checks_only_fixed_parameters():
    source = """
void caller(int n, int trailing, char *buffer) {
    snprintf(buffer, n, "%d", trailing);
}
"""
    signature = _signature(source)
    assert signature is not None and signature.resolved and signature.variadic
    assert len(signature.parameters) == 3
    issues = _issues(source)
    assert len(issues) == 1
    assert "buffer_size" in issues[0].message


def test_unknown_external_call_remains_unresolved():
    assert _signature("void caller(int n) { project_private_api(n); }") is None


def test_signature_models_do_not_create_security_semantics():
    registry = SemanticModelRegistry()
    # memmove is signature-modeled by issue #360.  Merely adding that shape must
    # not make it a source, validator, or sink in the separate semantic registry.
    assert not registry.for_function("memmove").is_modeled
