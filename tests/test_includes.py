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
        '[includes]\ninclude_roots = ["/custom/inc"]\n'
    )

    cfg = load_config(config_path=str(toml_file))
    assert "headers" in cfg.include_roots
    assert "/custom/inc" in cfg.include_roots


def test_include_resolver_edge_cases(tmp_path):
    resolver = IncludeResolver(base_dir=str(tmp_path), load_cgullincludes=False)

    # Empty root
    resolver.add_include_root("   ")

    # Non-existent file in load_from_file
    resolver.load_from_file(str(tmp_path / "does_not_exist"))

    # load_from_text
    resolver.load_from_text("# comment\n   \nrel_inc\n/abs_inc", base_dir=str(tmp_path))
    assert str((tmp_path / "rel_inc").resolve()) in resolver.include_roots
    assert os.path.abspath("/abs_inc") in resolver.include_roots

    # empty header resolve
    assert resolver.resolve("", str(tmp_path)) is None
    assert resolver.resolve('""', str(tmp_path)) is None

    # absolute path header resolve
    hdr = tmp_path / "abs.h"
    hdr.write_text("// abs\n")
    assert resolver.resolve(str(hdr.resolve()), str(tmp_path)) == str(hdr.resolve())
    assert resolver.resolve("/non_existent_abs.h", str(tmp_path)) is None

    # source_dir passed as a file path
    src_file = tmp_path / "src" / "foo.c"
    src_file.parent.mkdir()
    src_file.write_text("// src\n")
    local_hdr = tmp_path / "src" / "local.h"
    local_hdr.write_text("// local\n")
    assert resolver.resolve("local.h", str(src_file), is_quote=True) == str(local_hdr.resolve())
