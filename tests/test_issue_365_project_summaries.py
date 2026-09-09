"""Cross-TU parity, resolution boundaries, profiles, and worker regressions."""
import pickle

import pytest

from benchmarks.security_fact_support import build_security_models
from cgull import CGullScanner
from cgull.analysis_session import AnalysisSession
from cgull.ast_analyzer import CASTParser
from cgull.cfg.security_dataflow import analyze_security_summaries
from cgull.cfg.value_facts import analyze_value_summaries
from cgull.models import AnalysisEngine, ConfigProfile, ScanConfig
from cgull.project_analysis import ProjectSummaryIndex, prepare_project, profile_key
from cgull.rules.memory_management import UseAfterFreeRule


def _index(sources, models=None, **kwargs):
    contexts = {name: CASTParser().parse(source) for name, source in sources.items()}
    assert all(ctx.has_pycparser for ctx in contexts.values())
    args = {} if models is None else {"semantic_models": models}
    return ProjectSummaryIndex(contexts, **args, **kwargs).build()


CALLEE = """
void free(void *);
void *malloc(unsigned long);
void release(void *p) { free(p); }
void *make(void) { return malloc(16); }
void *identity(void *p) { return p; }
void *saved;
void escape(void *p) { saved = p; }
"""
CALLER = """
void release(void *);
void *make(void);
void *identity(void *);
void escape(void *);
void caller(void *p) {
    release(p);
    *(int *)p = 1;
    p = make();
    p = identity(p);
    escape(p);
}
"""


def test_memory_and_ownership_summaries_match_single_tu():
    index = _index({"caller.c": CALLER, "callee.c": CALLEE})
    single = AnalysisSession(CASTParser().parse(CALLEE + CALLER))
    cross = index.contexts["caller.c"].analysis_session
    for name in ("release", "make", "identity", "escape", "caller"):
        assert cross.function_summaries[name] == single.function_summaries[name]
        assert cross.ownership_summaries[name] == single.ownership_summaries[name]
    assert cross.ownership_summaries["release"].freed_params == {0}
    from cgull.cfg import Nullness

    assert cross.function_summaries["make"].return_nullness is Nullness.MAYBE_NULL
    assert cross.ownership_summaries["make"].returns_allocation
    assert cross.ownership_summaries["identity"].returned_alias_params == {0}


@pytest.mark.parametrize("jobs", [1, 2])
def test_scanner_detects_previously_missed_caller_uaf(tmp_path, jobs):
    (tmp_path / "caller.c").write_text(CALLER)
    (tmp_path / "callee.c").write_text(CALLEE)
    scanner = CGullScanner(rules=[UseAfterFreeRule()], engine_mode=AnalysisEngine.AST)
    before = scanner.scan_text(CALLER)
    assert not before.issues
    result = scanner.scan_path(str(tmp_path), jobs=jobs, quiet=True)
    assert not result.scan_errors
    assert any(i.file_path == "caller.c" and "Use-After-Free" in i.message for i in result.issues)
    assert not scanner.project_diagnostics
    # No index leaks into the next scan or a subsequent text scan.
    assert not scanner.scan_text(CALLER).issues


def test_value_security_and_validation_parity():
    helper = """
    int external_read(void);
    int validate(int);
    int read_value(void) { return external_read(); }
    int identity(int x) { return x; }
    int check(int x) { return validate(x); }
    """
    caller = """
    int read_value(void); int identity(int); int check(int);
    void sink(int);
    void caller(void) {
        int x = identity(read_value());
        if (!check(x)) return;
        sink(x);
    }
    """
    models = build_security_models()
    index = _index({"a.c": caller, "b.c": helper}, models)
    ctx = index.contexts["a.c"]
    single = CASTParser().parse(helper + caller)
    security = analyze_security_summaries(ctx, models)
    value = analyze_value_summaries(ctx, models)
    for name in ("read_value", "identity", "check", "caller"):
        assert security[name] == analyze_security_summaries(single, models)[name]
        # Evidence locations differ naturally between separate and joined files.
        expected = analyze_value_summaries(single, models)[name]
        assert value[name].return_from_params == expected.return_from_params
        assert value[name].return_provenance == expected.return_provenance
    assert security["read_value"].external_return
    assert security["check"].validator_effects
    assert value["identity"].return_from_params == {0}
    assert not ctx.analysis_session.queries.unvalidated_sink_flows()


@pytest.mark.parametrize("declaration", ["static void release(void *);", "void release(int);", "void (*release)(void *);"])
def test_incompatible_or_internal_declarations_are_unresolved(declaration):
    index = _index({"a.c": declaration + "void caller(void *p) { release(p); }", "b.c": CALLEE})
    assert not index.bindings["a.c"]


def test_static_definitions_do_not_collide_or_export():
    index = _index({
        "a.c": "static void release(void *p) {} void a(void *p) { release(p); }",
        "b.c": "void free(void *); static void release(void *p) { free(p); } void b(void *p) { release(p); }",
        "c.c": "void release(void *); void c(void *p) { release(p); }",
    })
    assert not index.exports.get("release")
    assert all(not bindings for bindings in index.bindings.values())
    assert not index.diagnostics


def test_duplicate_definitions_are_deterministic():
    sources = {"a.c": CALLER, "b.c": CALLEE, "c.c": CALLEE}
    first = _index(sources)
    second = _index(dict(reversed(list(sources.items()))))
    assert first.diagnostics == second.diagnostics
    assert any("AMBIGUOUS_EXTERNAL: release" in d for d in first.diagnostics)
    assert not first.bindings["a.c"]


def test_recursive_tus_converge_or_discard_exports_at_limit():
    sources = {
        "a.c": "void free(void *); void b(void *); void a(void *p) { free(p); b(p); }",
        "b.c": "void a(void *); void b(void *p) { a(p); }",
        "c.c": "void b(void *); void caller(void *p) { b(p); }",
    }
    first = _index(sources)
    second = _index(dict(reversed(list(sources.items()))))
    assert first.outputs == second.outputs
    assert first.iterations == second.iterations
    assert not first.diagnostics
    assert first.contexts["c.c"].analysis_session.function_summaries["b"].freed_params == {0}
    limited = _index(sources, max_rounds=1)
    assert any("PROJECT_CONVERGENCE_LIMIT" in d for d in limited.diagnostics)
    assert limited.contexts["a.c"].project_summaries == {}
    assert not limited.contexts["c.c"].project_summaries["function"]


def test_profile_and_include_configuration_isolation(tmp_path):
    caller = tmp_path / "caller.c"
    callee = tmp_path / "callee.c"
    caller.write_text("void release(void *); void caller(void *p) { release(p); }")
    callee.write_text("void free(void *);\nvoid release(void *p) {\n#ifdef FREE\nfree(p);\n#endif\n}\n")
    profiles = [ConfigProfile("free", {"FREE": None}), ConfigProfile("keep", {})]
    config = ScanConfig.create(rules=[UseAfterFreeRule()], engine_mode=AnalysisEngine.AST)
    units, diagnostics = prepare_project([str(caller), str(callee)], lambda _: config, profiles)
    assert not diagnostics
    free = units[str(caller)][profile_key(profiles[0].flags)].context
    keep = units[str(caller)][profile_key(profiles[1].flags)].context
    assert free.analysis_session.function_summaries["release"].freed_params == {0}
    assert not keep.analysis_session.function_summaries["release"].freed_params
    assert pickle.loads(pickle.dumps(units))[str(caller)]
    other = ScanConfig.create(rules=[UseAfterFreeRule()], include_roots=[str(tmp_path / "other")])
    units, _ = prepare_project([str(caller), str(callee)], lambda path: config if path == str(caller) else other)
    assert not getattr(units[str(caller)][profile_key(None)].context, "project_summaries", {})


def test_missing_body_retains_lazy_intra_tu_path():
    index = _index({"a.c": CALLER, "b.c": "int unrelated(void) { return 0; }"})
    assert not index.outputs
    assert not getattr(index.contexts["a.c"], "analysis_session", None)


def test_modeled_ownership_transfer_and_escape_cross_tu():
    from cgull.call_effects import BUILTIN_CALL_EFFECTS, CallEffectModel
    from cgull.semantic_models import SemanticModelRegistry

    models = SemanticModelRegistry(call_effects=BUILTIN_CALL_EFFECTS.merged({
        "adopt": CallEffectModel(function="adopt", takes_ownership=frozenset({0})),
        "retain": CallEffectModel(function="retain", escapes=frozenset({0})),
    }))
    helper = "void adopt(void *); void retain(void *); void handoff(void *p) { adopt(p); } void escape(void *p) { retain(p); }"
    caller = "void handoff(void *); void escape(void *); void caller(void *p, void *q) { handoff(p); escape(q); }"
    index = _index({"a.c": caller, "b.c": helper}, models)
    cross = index.contexts["a.c"].analysis_session.ownership_summaries
    single = AnalysisSession(CASTParser().parse(helper + caller), semantic_models=models).ownership_summaries
    assert cross["caller"] == single["caller"]
    assert cross["handoff"].transferred_params == {0}
    assert cross["escape"].escaped_params == {0}


def test_named_typedefs_with_different_definitions_do_not_match():
    index = _index({
        "a.c": "typedef int value_t; void release(value_t); void caller(value_t p) { release(p); }",
        "b.c": "typedef void *value_t; void free(void *); void release(value_t p) { free(p); }",
    })
    assert not index.bindings["a.c"]
    assert any("INCOMPATIBLE_EXTERNAL" in d for d in index.diagnostics)


def test_duplicate_definitions_in_one_tu_do_not_export():
    index = _index({"a.c": CALLER, "b.c": CALLEE + "void release(void *p) {}"})
    assert "release" not in index.bindings["a.c"]
    assert any("AMBIGUOUS_EXTERNAL: release" in d for d in index.diagnostics)


def test_static_global_security_relationships_do_not_cross_tus():
    index = _index({
        "a.c": "int read_value(void); int saved; int caller(void) { return read_value(); }",
        "b.c": "static int saved; int read_value(void) { return saved; }",
    }, build_security_models())
    assert "read_value" not in index.contexts["a.c"].project_summaries["security"]


def test_security_query_observes_cross_tu_source_without_validation():
    index = _index({
        "a.c": "int read_value(void); void sink(int); void caller(void) { int x = read_value(); sink(x); }",
        "b.c": "int external_read(void); int read_value(void) { return external_read(); }",
    }, build_security_models())
    findings = index.contexts["a.c"].analysis_session.queries.unvalidated_sink_flows()
    assert len(findings) == 1
    assert not findings[0].degraded


@pytest.mark.parametrize("jobs", [1, 2])
def test_profile_reachability_in_public_scan(tmp_path, jobs):
    (tmp_path / "caller.c").write_text("void release(void *); void caller(void *p) { release(p); *(int *)p = 1; }")
    (tmp_path / "callee.c").write_text("void free(void *);\nvoid release(void *p) {\n#ifdef FREE\nfree(p);\n#endif\n}\n")
    scanner = CGullScanner(rules=[UseAfterFreeRule()], engine_mode=AnalysisEngine.AST)
    result = scanner.scan_path(str(tmp_path), quiet=True, jobs=jobs, profiles=[ConfigProfile("free", {"FREE": None}), ConfigProfile("keep", {})])
    assert not result.scan_errors
    assert len(result.issues) == 1
    assert result.issues[0].reachable_under == ["+free"]
