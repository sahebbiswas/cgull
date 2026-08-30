"""
Unit tests for IncludeResolver and include root configuration.
"""

import os
import tempfile
from pathlib import Path
import pytest

from cgull.includes import IncludeResolver
from cgull.models import ScanConfig
from cgull.config import load_config, CGullConfig


def test_quote_vs_angle_resolution_order(tmp_path):
    # Setup directory hierarchy:
    # tmp_path/
    #   src/
    #     main.c
    #     header.h (local version)
    #   include1/
    #     header.h (include1 version)
    #     common.h (include1 version)
    #   include2/
    #     common.h (include2 version)
    #     nested/
    #       nested_hdr.h

    src_dir = tmp_path / "src"
    inc1_dir = tmp_path / "include1"
    inc2_dir = tmp_path / "include2"
    nested_dir = inc2_dir / "nested"

    src_dir.mkdir()
    inc1_dir.mkdir()
    inc2_dir.mkdir()
    nested_dir.mkdir()

    src_header = src_dir / "header.h"
    src_header.write_text("// local header\n")

    inc1_header = inc1_dir / "header.h"
    inc1_header.write_text("// inc1 header\n")

    inc1_common = inc1_dir / "common.h"
    inc1_common.write_text("// inc1 common\n")

    inc2_common = inc2_dir / "common.h"
    inc2_common.write_text("// inc2 common\n")

    nested_hdr = nested_dir / "nested_hdr.h"
    nested_hdr.write_text("// nested header\n")

    resolver = IncludeResolver(
        include_roots=[str(inc1_dir), str(inc2_dir)],
        base_dir=str(tmp_path),
        load_cgullincludes=False,
    )

    # 1. Quote form #include "header.h" from src_dir -> finds src/header.h first
    res_quote = resolver.resolve("header.h", str(src_dir), is_quote=True)
    assert res_quote == str(src_header.resolve())

    # 2. Angle form #include <header.h> from src_dir -> skips src_dir, finds include1/header.h
    res_angle = resolver.resolve("header.h", str(src_dir), is_quote=False)
    assert res_angle == str(inc1_header.resolve())

    # 3. Quote form when header is not in src_dir -> searches include roots in order
    res_common_quote = resolver.resolve("common.h", str(src_dir), is_quote=True)
    assert res_common_quote == str(inc1_common.resolve())

    # 4. Search order between multiple include roots (inc1 before inc2)
    res_common_angle = resolver.resolve("common.h", str(src_dir), is_quote=False)
    assert res_common_angle == str(inc1_common.resolve())


def test_nested_include_roots(tmp_path):
    inc_dir = tmp_path / "include"
    nested_dir = inc_dir / "a" / "b"
    nested_dir.mkdir(parents=True)

    hdr = nested_dir / "feature.h"
    hdr.write_text("// feature\n")

    # Include root pointing to nested dir
    resolver = IncludeResolver(
        include_roots=[str(nested_dir)],
        base_dir=str(tmp_path),
        load_cgullincludes=False,
    )

    res = resolver.resolve("feature.h", str(tmp_path), is_quote=True)
    assert res == str(hdr.resolve())

    # Subpath resolution from parent include root
    resolver2 = IncludeResolver(
        include_roots=[str(inc_dir)],
        base_dir=str(tmp_path),
        load_cgullincludes=False,
    )
    res2 = resolver2.resolve("a/b/feature.h", str(tmp_path), is_quote=False)
    assert res2 == str(hdr.resolve())


def test_missing_header_handling(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    resolver = IncludeResolver(
        include_roots=[str(tmp_path / "inc")],
        base_dir=str(tmp_path),
        load_cgullincludes=False,
    )

    # System headers or missing headers degrade gracefully to None
    assert resolver.resolve("<stdio.h>", str(src_dir)) is None
    assert resolver.resolve("<stdint.h>", str(src_dir)) is None
    assert resolver.resolve("non_existent.h", str(src_dir), is_quote=True) is None
    assert resolver.resolve("<missing_system.h>", str(src_dir), is_quote=False) is None


def test_cgullincludes_file_loading(tmp_path):
    inc1 = tmp_path / "inc1"
    inc2 = tmp_path / "inc2"
    inc1.mkdir()
    inc2.mkdir()

    hdr1 = inc1 / "hdr1.h"
    hdr1.write_text("// hdr1\n")

    cgullinc_file = tmp_path / ".cgullincludes"
    cgullinc_file.write_text(f"# Include paths file\ninc1\n{inc2}\n")

    resolver = IncludeResolver(base_dir=str(tmp_path), load_cgullincludes=True)

    assert str(inc1.resolve()) in resolver.include_roots
    assert str(inc2.resolve()) in resolver.include_roots

    res = resolver.resolve("hdr1.h", str(tmp_path), is_quote=False)
    assert res == str(hdr1.resolve())


def test_include_resolver_header_string_parsing(tmp_path):
    inc_dir = tmp_path / "inc"
    inc_dir.mkdir()
    hdr = inc_dir / "test.h"
    hdr.write_text("// test\n")

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))

    # Raw bracket/quote strings
    assert resolver.resolve("<test.h>", str(tmp_path)) == str(hdr.resolve())
    assert resolver.resolve('"test.h"', str(tmp_path)) == str(hdr.resolve())


def test_scanconfig_include_roots():
    config = ScanConfig.create(include_roots=["/path/one", "/path/two"])
    assert config.include_roots == ["/path/one", "/path/two"]

    cfg_dict = config.to_dict()
    assert cfg_dict["include_roots"] == ["/path/one", "/path/two"]

    restored = ScanConfig.from_dict(cfg_dict)
    assert restored.include_roots == ["/path/one", "/path/two"]


def test_cgullconfig_include_roots(tmp_path):
    inc_dir = tmp_path / "headers"
    inc_dir.mkdir()

    toml_file = tmp_path / ".cgull.toml"
    toml_file.write_text(
        '[paths]\ninclude_roots = ["headers"]\n'
        '[includes]\ninclude_roots = ["custom_inc"]\n'
    )

    cfg = load_config(config_path=str(toml_file))
    assert str(inc_dir.resolve()) in cfg.include_roots
    assert str((tmp_path / "custom_inc").resolve()) in cfg.include_roots


def test_standalone_cgullincludes_discovery(tmp_path):
    inc_dir = tmp_path / "standalone_inc"
    inc_dir.mkdir()
    cgullinc = tmp_path / ".cgullincludes"
    cgullinc.write_text("standalone_inc\n")

    cfg = load_config(config_path=None, target_path=str(tmp_path))
    assert str(inc_dir.resolve()) in cfg.include_roots


def test_scanner_config_include_roots_propagation(tmp_path):
    from cgull.engine import CGullScanner, _scan_file_content_profiles
    from cgull.models import ConfigProfile

    inc_dir = str((tmp_path / "inc").resolve())
    scan_cfg = ScanConfig.create(include_roots=[inc_dir])

    scanner = CGullScanner(config=scan_cfg)
    assert scanner.config.include_roots == [inc_dir]
    assert scanner._get_active_config().include_roots == [inc_dir]

    profile = ConfigProfile(name="test", flags={"FOO": None})
    _, _, _, _, _, _, _, _ = _scan_file_content_profiles(
        content="int main(void) { return 0; }\n",
        file_path="main.c",
        config=scan_cfg,
        profiles=[profile],
    )


def test_include_resolver_edge_cases(tmp_path):
    resolver = IncludeResolver(base_dir=str(tmp_path), load_cgullincludes=False)

    # Empty root
    resolver.add_include_root("   ")

    # Non-existent file in load_from_file
    resolver.load_from_file(str(tmp_path / "does_not_exist"))

    # load_from_text
    abs_inc_dir = str((tmp_path / "abs_inc").resolve())
    resolver.load_from_text(f"# comment\n   \nrel_inc\n{abs_inc_dir}", base_dir=str(tmp_path))
    assert str((tmp_path / "rel_inc").resolve()) in resolver.include_roots
    assert abs_inc_dir in resolver.include_roots

    # empty header resolve
    assert resolver.resolve("", str(tmp_path)) is None
    assert resolver.resolve('""', str(tmp_path)) is None

    # absolute path header resolve
    hdr = tmp_path / "abs.h"
    hdr.write_text("// abs\n")
    non_existent_abs = str((tmp_path / "non_existent_abs.h").resolve())
    assert resolver.resolve(str(hdr.resolve()), str(tmp_path)) == str(hdr.resolve())
    assert resolver.resolve(non_existent_abs, str(tmp_path)) is None

    # source_dir passed as a file path
    src_file = tmp_path / "src" / "foo.c"
    src_file.parent.mkdir()
    src_file.write_text("// src\n")
    local_hdr = tmp_path / "src" / "local.h"
    local_hdr.write_text("// local\n")
    assert resolver.resolve("local.h", str(src_file), is_quote=True) == str(local_hdr.resolve())


def test_tu_include_expander_depth_first_recursion(tmp_path):
    from cgull.includes import TUIncludeExpander, IncludeResolver

    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    hdr_a = inc_dir / "a.h"
    hdr_b = inc_dir / "b.h"

    hdr_a.write_text('#include "b.h"\nint a = 1;\n')
    hdr_b.write_text("int b = 2;\n")

    main_c = tmp_path / "main.c"
    main_c.write_text('#include "a.h"\nint main(void) { return a + b; }\n')

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))
    expander = TUIncludeExpander(resolver=resolver)

    expanded = expander.expand(main_c.read_text(), str(main_c))
    assert "int b = 2;" in expanded
    assert "int a = 1;" in expanded
    assert expanded.index("int b = 2;") < expanded.index("int a = 1;")
    assert expanded.index("int a = 1;") < expanded.index("int main(void)")


def test_tu_include_expander_guards_and_pragma_once(tmp_path):
    from cgull.includes import TUIncludeExpander, IncludeResolver

    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    hdr_once = inc_dir / "once.h"
    hdr_once.write_text("#pragma once\nstruct Once { int x; };\n")

    hdr_guard = inc_dir / "guard.h"
    hdr_guard.write_text("#ifndef GUARD_H\n#define GUARD_H\nstruct Guard { int y; };\n#endif\n")

    main_c = tmp_path / "main.c"
    main_c.write_text(
        '#include "once.h"\n'
        '#include "once.h"\n'
        '#include "guard.h"\n'
        '#include "guard.h"\n'
        "int main(void) { return 0; }\n"
    )

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))
    expander = TUIncludeExpander(resolver=resolver)

    expanded = expander.expand(main_c.read_text(), str(main_c))

    assert expanded.count("struct Once") == 1
    assert expanded.count("struct Guard") == 1


def test_tu_include_expander_circular_includes(tmp_path, caplog):
    import logging
    from cgull.includes import TUIncludeExpander, IncludeResolver

    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    hdr_a = inc_dir / "a.h"
    hdr_b = inc_dir / "b.h"

    hdr_a.write_text('#include "b.h"\nint a = 1;\n')
    hdr_b.write_text('#include "a.h"\nint b = 2;\n')

    main_c = tmp_path / "main.c"
    main_c.write_text('#include "a.h"\nint main(void) { return 0; }\n')

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))
    expander = TUIncludeExpander(resolver=resolver)

    with caplog.at_level(logging.WARNING):
        expanded = expander.expand(main_c.read_text(), str(main_c))

    assert "Circular include detected" in caplog.text
    assert "int a = 1;" in expanded
    assert "int b = 2;" in expanded


def test_tu_include_expander_limits(tmp_path, caplog):
    import logging
    from cgull.includes import TUIncludeExpander, IncludeResolver

    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    hdr1 = inc_dir / "hdr1.h"
    hdr2 = inc_dir / "hdr2.h"
    hdr1.write_text('#include "hdr2.h"\n')
    hdr2.write_text("int deep = 1;\n")

    main_c = tmp_path / "main.c"
    main_c.write_text('#include "hdr1.h"\n')

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))

    # 1. Depth limit test (max_depth=1)
    expander_depth = TUIncludeExpander(resolver=resolver, max_depth=1)
    with caplog.at_level(logging.WARNING):
        expanded_depth = expander_depth.expand(main_c.read_text(), str(main_c))
    assert "Max include depth (1) exceeded" in caplog.text

    # 2. Size limit test (max_total_bytes=5)
    caplog.clear()
    hdr_large = inc_dir / "large.h"
    hdr_large.write_text("char large_buf[1000];\n")
    main_large = tmp_path / "main_large.c"
    main_large.write_text('#include "large.h"\n')

    expander_size = TUIncludeExpander(resolver=resolver, max_total_bytes=5)
    with caplog.at_level(logging.WARNING):
        expanded_size = expander_size.expand(main_large.read_text(), str(main_large))
    assert "Max total expanded include size" in caplog.text


def test_tu_include_expansion_integration_with_scanner(tmp_path):
    from cgull.engine import CGullScanner
    from cgull.models import ScanConfig

    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    # Create header with a vulnerability (gets usage)
    hdr = inc_dir / "vulnerable.h"
    hdr.write_text("void unsafe_func(char *buf) { gets(buf); }\n")

    main_c = tmp_path / "main.c"
    main_c.write_text('#include "vulnerable.h"\nint main(void) { char b[10]; unsafe_func(b); return 0; }\n')

    # Also create a .cgullignore that ignores header files directly in include/
    cgullignore = tmp_path / ".cgullignore"
    cgullignore.write_text("include/\n")

    config = ScanConfig.create(include_roots=[str(inc_dir)])
    scanner = CGullScanner(config=config)

    res = scanner.scan_path(str(main_c))

    assert res.scanned_files_count == 1
    # Vulnerability in included header is found in main.c TU!
    gets_issues = [i for i in res.issues if "gets" in i.message.lower() or i.rule_id == "CGULL-005"]
    assert len(gets_issues) >= 1
    # Check that the reported issue's file_path and line_number match the original header file
    assert gets_issues[0].file_path == os.path.relpath(str(hdr.resolve()), str(tmp_path))
    assert gets_issues[0].line_number == 1


def test_inactive_include_in_untaken_branch_does_not_mutate_guards(tmp_path):
    from cgull.includes import TUIncludeExpander, IncludeResolver

    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    hdr_once = inc_dir / "once.h"
    hdr_once.write_text("#pragma once\nint once_val = 1;\n")

    main_c = tmp_path / "main.c"
    main_c.write_text(
        "#ifdef UNTAKEN_MACRO\n"
        '#include "once.h"\n'
        "#endif\n"
        '#include "once.h"\n'
        "int main(void) { return once_val; }\n"
    )

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))
    expander = TUIncludeExpander(resolver=resolver, defined_syms={})

    tu = expander.expand(main_c.read_text(), str(main_c))

    # "once.h" should be active and expanded on line 4, NOT muted by line 2
    assert "int once_val = 1;" in tu.expanded_text


def test_partial_header_guard_rejection(tmp_path):
    from cgull.includes import _detect_header_guard

    # Whole-file header guard
    valid_guard = "#ifndef MY_GUARD_H\n#define MY_GUARD_H\nint x;\n#endif\n"
    assert _detect_header_guard(valid_guard) == "MY_GUARD_H"

    # Partial guard (code outside the guard)
    partial_guard = "int external_var = 0;\n#ifndef MY_GUARD_H\n#define MY_GUARD_H\nint x;\n#endif\n"
    assert _detect_header_guard(partial_guard) is None

    # Premature endif
    premature_guard = "#ifndef MY_GUARD_H\n#define MY_GUARD_H\nint x;\n#endif\nint y;\n"
    assert _detect_header_guard(premature_guard) is None

    # Branching guard (has #else or #elif)
    branching_guard = "#ifndef MY_GUARD_H\n#define MY_GUARD_H\nint x;\n#else\nint bad;\n#endif\n"
    assert _detect_header_guard(branching_guard) is None

    # Nested conditional inside guard is fine
    nested_guard = "#ifndef MY_GUARD_H\n#define MY_GUARD_H\n#if 1\nint x;\n#endif\n#endif\n"
    assert _detect_header_guard(nested_guard) == "MY_GUARD_H"


def test_boundary_containment_rejection(tmp_path):
    from cgull.includes import IncludeResolver

    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_hdr = outside_dir / "outside.h"
    outside_hdr.write_text("int secret = 42;\n")

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(inc_dir), allow_external_includes=False)

    # Attempt path traversal escape
    resolved = resolver.resolve("../outside/outside.h", str(inc_dir), is_quote=True)
    assert resolved is None


def test_streamed_bounded_reads_and_caching(tmp_path):
    from cgull.includes import TUIncludeExpander, IncludeResolver

    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    hdr = inc_dir / "hdr.h"
    hdr.write_text("int data = 1234567890;\n")

    main_c = tmp_path / "main.c"
    main_c.write_text('#include "hdr.h"\n#include "hdr.h"\n')

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))
    expander = TUIncludeExpander(resolver=resolver, max_total_bytes=10)

    tu = expander.expand(main_c.read_text(), str(main_c))

    assert str(hdr.resolve()) in expander.rejected_paths


def test_cross_file_line_provenance_nested_includes(tmp_path):
    from cgull.includes import TUIncludeExpander, IncludeResolver

    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    hdr_c = inc_dir / "c.h"
    hdr_c.write_text("// c.h line 1\nint c_func(void) { return 42; }\n// c.h line 3\n")

    hdr_b = inc_dir / "b.h"
    hdr_b.write_text("// b.h line 1\n#include \"c.h\"\n// b.h line 3\nint b_var = 10;\n")

    main_c = tmp_path / "main.c"
    main_c.write_text("// main line 1\n#include \"b.h\"\n// main line 3\nint main(void) { return b_var + c_func(); }\n")

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))
    expander = TUIncludeExpander(resolver=resolver)

    tu = expander.expand(main_c.read_text(), str(main_c))

    # Verify every line in expanded TU resolves to the correct (file_path, line_number)
    line_map = tu.line_map
    lines = tu.expanded_text.splitlines()

    # Find c_func in expanded text
    c_func_line_idx = next(i for i, line in enumerate(lines, 1) if "c_func(void)" in line)
    src_loc = line_map[c_func_line_idx]
    assert src_loc.file_path == str(hdr_c.resolve())
    assert src_loc.line_number == 2
    assert "c_func(void)" in src_loc.line_content

    # Find b_var in expanded text
    b_var_line_idx = next(i for i, line in enumerate(lines, 1) if "b_var = 10" in line)
    src_loc_b = line_map[b_var_line_idx]
    assert src_loc_b.file_path == str(hdr_b.resolve())
    assert src_loc_b.line_number == 4
    assert "b_var = 10" in src_loc_b.line_content

    # Find main in expanded text
    main_line_idx = next(i for i, line in enumerate(lines, 1) if "int main(void)" in line)
    src_loc_main = line_map[main_line_idx]
    assert src_loc_main.file_path == str(main_c.resolve())
    assert src_loc_main.line_number == 4
    assert "int main(void)" in src_loc_main.line_content


def test_prelude_and_pcpp_composition_underneath_tu_map(tmp_path):
    """
    Tests that AST-level prelude offsets (_PRELUDE_LINE_COUNT) and pcpp line reconstruction
    compose correctly underneath the TU-level line_map.
    Scenario: A macro-using function inside an included header containing an AST-only finding (CGULL-041 unused variable).
    Explicitly requires pycparser and pcpp, asserts parse_tier is pcpp+pycparser, and verifies
    the exact AST-only rule finding maps back to the original header file path, line number, and snippet.
    """
    try:
        import pycparser  # noqa: F401
        import pcpp  # noqa: F401
    except ImportError:
        pytest.skip("pycparser and pcpp both required for pcpp composition test")

    from cgull.engine import CGullScanner
    from cgull.models import ScanConfig, AnalysisEngine

    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    # Create header containing a macro-using function with an AST-only finding (CGULL-041 unused local variable 'unused_var')
    hdr = inc_dir / "macro_header.h"
    hdr.write_text(
        "#define BUFFER_SIZE 256\n"
        "#define UNUSED_MACRO 1\n"
        "// line 3 comment\n"
        "void process_input(void) {\n"
        "    int unused_var;\n"
        "    char buf[BUFFER_SIZE];\n"
        "    buf[0] = 'a';\n"
        "}\n"
    )

    main_c = tmp_path / "main.c"
    main_c.write_text(
        "// main.c line 1\n"
        '#include "macro_header.h"\n'
        "int main(void) {\n"
        "    process_input();\n"
        "    return 0;\n"
        "}\n"
    )

    config = ScanConfig.create(include_roots=[str(inc_dir)], engine_mode=AnalysisEngine.HYBRID)
    scanner = CGullScanner(config=config)

    res = scanner.scan_path(str(main_c))

    assert res.scanned_files_count == 1
    assert res.file_summaries[0].parse_tier == "pcpp+pycparser"

    # CGULL-041 is UnusedLocalVariablesRule (AST-only engine)
    ast_issues = [i for i in res.issues if i.rule_id == "CGULL-041" or "unused_var" in i.message]
    assert len(ast_issues) >= 1

    issue = ast_issues[0]
    # Check that the AST finding maps to the header file at line 5 (int unused_var;)
    assert issue.file_path == os.path.relpath(str(hdr.resolve()), str(tmp_path))
    assert issue.line_number == 5
    assert "unused_var" in issue.code_snippet


def test_nested_guard_propagation_and_reuse(tmp_path):
    from cgull.includes import TUIncludeExpander, IncludeResolver, HEADER_CACHE

    HEADER_CACHE.clear()
    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    nested_h = inc_dir / "nested.h"
    nested_h.write_text("#pragma once\nint nested_val = 1;\n")

    parent_h = inc_dir / "parent.h"
    parent_h.write_text('#pragma once\n#include "nested.h"\nint parent_val = 2;\n')

    # TU1: parent.h first, then nested.h
    tu1_c = tmp_path / "tu1.c"
    tu1_c.write_text('#include "parent.h"\n#include "nested.h"\nint main(void) { return parent_val + nested_val; }\n')

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))
    expander = TUIncludeExpander(resolver=resolver)

    expanded1 = expander.expand(tu1_c.read_text(), str(tu1_c))
    assert expanded1.count("int nested_val = 1;") == 1
    assert expanded1.count("int parent_val = 2;") == 1

    # TU2: nested.h first, then parent.h
    tu2_c = tmp_path / "tu2.c"
    tu2_c.write_text('#include "nested.h"\n#include "parent.h"\nint main(void) { return parent_val + nested_val; }\n')

    expanded2 = expander.expand(tu2_c.read_text(), str(tu2_c))
    assert expanded2.count("int nested_val = 1;") == 1
    assert expanded2.count("int parent_val = 2;") == 1


def test_expansion_byte_budget_enforcement_cached_and_nested(tmp_path, caplog):
    import logging
    from cgull.includes import TUIncludeExpander, IncludeResolver, HEADER_CACHE

    HEADER_CACHE.clear()
    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    big_child = inc_dir / "big_child.h"
    big_child.write_text("char large_buffer[500] = {0};\n")

    parent = inc_dir / "parent.h"
    parent.write_text('#include "big_child.h"\nint p_flag = 1;\n')

    main_c = tmp_path / "main.c"
    main_c.write_text('#include "parent.h"\nint main(void) { return 0; }\n')

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))

    # max_total_bytes=100 will allow reading main.c and parent.h, but big_child.h (500 bytes) will exceed remaining budget
    expander = TUIncludeExpander(resolver=resolver, max_total_bytes=100)
    with caplog.at_level(logging.WARNING):
        expanded = expander.expand(main_c.read_text(), str(main_c))

    assert "exceeds remaining expansion budget" in caplog.text or "Max total expanded include size" in caplog.text
    assert "large_buffer" not in expanded

    # Test cache hit exceeding budget
    caplog.clear()
    HEADER_CACHE.clear()
    leaf_h = inc_dir / "leaf.h"
    leaf_h.write_text("char leaf_buf[200] = \"" + "A" * 200 + "\";\n")

    # First expand with plenty of budget to populate cache
    expander_large = TUIncludeExpander(resolver=resolver, max_total_bytes=1000)
    expander_large.expand('#include "leaf.h"\n', str(main_c))

    # Next expand with small budget: cache hit must enforce budget
    expander_small = TUIncludeExpander(resolver=resolver, max_total_bytes=100)
    with caplog.at_level(logging.WARNING):
        expanded_small = expander_small.expand('#include "leaf.h"\n', str(main_c))

    assert "exceeds remaining expansion budget" in caplog.text
    assert "leaf_buf" not in expanded_small


def test_include_depth_limit_enforced_on_cached_headers(tmp_path, caplog):
    import logging
    from cgull.includes import TUIncludeExpander, IncludeResolver, HEADER_CACHE

    HEADER_CACHE.clear()
    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    leaf = inc_dir / "leaf.h"
    leaf.write_text("int leaf_target = 42;\n")

    d2 = inc_dir / "d2.h"
    d2.write_text('#include "leaf.h"\n')

    d1 = inc_dir / "d1.h"
    d1.write_text('#include "d2.h"\n')

    main1 = tmp_path / "main1.c"
    main1.write_text('#include "leaf.h"\n')

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))

    # 1. Populate cache at depth 0
    expander_deep = TUIncludeExpander(resolver=resolver, max_depth=10)
    exp1 = expander_deep.expand(main1.read_text(), str(main1))
    assert "int leaf_target = 42;" in exp1

    # 2. Re-include leaf.h via d1 -> d2 with max_depth=2
    # main2 (depth 0) -> d1 (depth 1) -> d2 (depth 2) -> leaf.h (depth 3 >= max_depth 2)
    main2 = tmp_path / "main2.c"
    main2.write_text('#include "d1.h"\n')

    caplog.clear()
    expander_shallow = TUIncludeExpander(resolver=resolver, max_depth=2)
    with caplog.at_level(logging.WARNING):
        exp2 = expander_shallow.expand(main2.read_text(), str(main2))

    assert "Max include depth (2) exceeded" in caplog.text
    assert "int leaf_target = 42;" not in exp2


def test_nested_dependency_invalidation(tmp_path):
    from cgull.includes import TUIncludeExpander, IncludeResolver, HEADER_CACHE

    HEADER_CACHE.clear()
    inc_dir = tmp_path / "include"
    inc_dir.mkdir()

    child = inc_dir / "child.h"
    child.write_text("int child_v1 = 1;\n")

    parent = inc_dir / "parent.h"
    parent.write_text('#include "child.h"\nint parent_val = 10;\n')

    main_c = tmp_path / "main.c"
    main_c.write_text('#include "parent.h"\nint main(void) { return parent_val; }\n')

    resolver = IncludeResolver(include_roots=[str(inc_dir)], base_dir=str(tmp_path))
    expander = TUIncludeExpander(resolver=resolver)

    # Initial expansion
    exp1 = expander.expand(main_c.read_text(), str(main_c))
    assert "int child_v1 = 1;" in exp1

    # Invalidate child by modifying child.h on disk (parent.h remains unchanged)
    child.write_text("int child_v2 = 2;\n")

    exp2 = expander.expand(main_c.read_text(), str(main_c))
    assert "int child_v2 = 2;" in exp2
    assert "int child_v1 = 1;" not in exp2


def test_resolver_roots_cache_isolation(tmp_path):
    from cgull.includes import TUIncludeExpander, IncludeResolver, HEADER_CACHE

    HEADER_CACHE.clear()
    inc1 = tmp_path / "inc1"
    inc2 = tmp_path / "inc2"
    inc1.mkdir()
    inc2.mkdir()

    target1 = inc1 / "target.h"
    target1.write_text("int from_inc1 = 100;\n")

    target2 = inc2 / "target.h"
    target2.write_text("int from_inc2 = 200;\n")

    shared = tmp_path / "shared.h"
    shared.write_text('#include "target.h"\n')

    main_c = tmp_path / "main.c"
    main_c.write_text('#include "shared.h"\n')

    resolver1 = IncludeResolver(include_roots=[str(inc1)], base_dir=str(tmp_path))
    expander1 = TUIncludeExpander(resolver=resolver1)
    exp1 = expander1.expand(main_c.read_text(), str(main_c))
    assert "int from_inc1 = 100;" in exp1

    resolver2 = IncludeResolver(include_roots=[str(inc2)], base_dir=str(tmp_path))
    expander2 = TUIncludeExpander(resolver=resolver2)
    exp2 = expander2.expand(main_c.read_text(), str(main_c))
    assert "int from_inc2 = 200;" in exp2
    assert "int from_inc1 = 100;" not in exp2

