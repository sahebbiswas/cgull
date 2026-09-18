from cgull import CGullScanner
from cgull.ast_analyzer import CASTParser
from cgull.cfg import build_cfg, find_function_def
from cgull.models import AnalysisEngine, ScanConfig
from cgull.project_analysis import PreparedUnit
from cgull.rules.memory_management import MemoryLeakRule, UseAfterFreeRule


def _write_fixture(tmp_path):
    include_dir = tmp_path / "include"
    include_dir.mkdir()
    padding = include_dir / "padding.h"
    padding.write_text(
        "".join(f"typedef int issue525_pad_{index};\n" for index in range(180)),
        encoding="utf-8",
    )
    free_site = include_dir / "free_site.h"
    free_site.write_text("free(p);\n", encoding="utf-8")
    alloc_site = include_dir / "alloc_site.h"
    alloc_site.write_text(
        "int *leaked = (int *)malloc(sizeof(int));\n",
        encoding="utf-8",
    )

    source = tmp_path / "main.c"
    source.write_text(
        '#include "padding.h"\n'
        "void free(void *);\n"
        "void *malloc(unsigned long);\n"
        "int uaf(int *p) {\n"
        '#include "free_site.h"\n'
        "    return *p;\n"
        "}\n"
        "void leak(void) {\n"
        '#include "alloc_site.h"\n'
        "}\n",
        encoding="utf-8",
    )
    return source, include_dir, free_site, alloc_site


def test_prepared_tu_context_keeps_provenance_without_remapping_cfg_primary_lines(tmp_path):
    source, include_dir, free_site, _ = _write_fixture(tmp_path)
    ScanConfig.create(include_roots=[str(include_dir)], mode="tu")

    from cgull.includes import IncludeResolver, TUIncludeExpander

    resolver = IncludeResolver(include_roots=[str(include_dir)], base_dir=str(tmp_path))
    expanded = TUIncludeExpander(resolver=resolver).expand(
        source.read_text(encoding="utf-8"), str(source)
    )
    prepared = PreparedUnit(source=source.read_text(encoding="utf-8"), expanded=expanded)
    ctx = prepared.context

    assert ctx.line_map is not None
    expanded_free_line = next(
        line
        for line, location in expanded.line_map.items()
        if location.file_path == str(free_site.resolve()) and location.line_number == 1
    )
    assert expanded_free_line > len(source.read_text(encoding="utf-8").splitlines())

    cfg = build_cfg(find_function_def(ctx.pycparser_ast, "uaf"), line_map=ctx.line_map)
    free_event = next(node for node in cfg.nodes.values() if node.freed)
    assert free_event.line_number == expanded_free_line
    assert free_event.source_location.file_path == str(free_site.resolve())
    assert free_event.source_location.line_number == 1


def test_tu_findings_render_primary_and_related_sites_in_original_sources(tmp_path):
    _, include_dir, _, _ = _write_fixture(tmp_path)
    config = ScanConfig.create(
        rules=[UseAfterFreeRule(), MemoryLeakRule()],
        engine_mode=AnalysisEngine.AST,
        include_roots=[str(include_dir)],
        mode="tu",
    )
    result = CGullScanner(config=config).scan_path(str(tmp_path), jobs=1, quiet=True)

    assert result.files_failed == 0
    uaf = next(issue for issue in result.issues if issue.rule_id == "CGULL-022")
    assert uaf.file_path == "main.c"
    assert uaf.line_number == 6
    assert "freed at include/free_site.h:1" in uaf.message

    leak = next(issue for issue in result.issues if issue.rule_id == "CGULL-036")
    assert leak.file_path == "include/alloc_site.h"
    assert leak.line_number == 1
    assert "allocated for 'leaked' at line 1" in leak.message


def test_file_mode_related_site_wording_is_unchanged():
    source = (
        "void free(void *);\n"
        "int f(int *p) {\n"
        "    free(p);\n"
        "    return *p;\n"
        "}\n"
    )
    ctx = CASTParser().parse(source)
    issues = UseAfterFreeRule().scan_ast("test.c", ctx)

    assert len(issues) == 1
    assert issues[0].line_number == 4
    assert "freed at line 3 and accessed here" in issues[0].message
