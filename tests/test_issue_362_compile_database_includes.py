import json
import os

from cgull.compile_database import CompileCommandIncludeDatabase, CompileDatabaseCGullScanner
from cgull.models import AnalysisEngine, ScanConfig
from cgull.rules.types_and_arrays import IntegerNarrowingCastRule


def _write_database(path, entries):
    path.write_text(json.dumps(entries), encoding="utf-8")
    return CompileCommandIncludeDatabase.from_file(path)


def test_arguments_and_command_entries_produce_equivalent_ordered_roots(tmp_path):
    build = tmp_path / "build"
    project = tmp_path / "project"
    include_one = project / "include-one"
    include_two = project / "include two"
    system = project / "system"
    build.mkdir()
    include_one.mkdir(parents=True)
    include_two.mkdir()
    system.mkdir()

    source_a = project / "a.c"
    source_b = project / "b.c"
    source_a.write_text("int a;\n", encoding="utf-8")
    source_b.write_text("int b;\n", encoding="utf-8")

    entries = [
        {
            "directory": str(build),
            "file": str(source_a),
            "arguments": [
                "cc",
                "-I../project/include-one",
                "-I",
                "../project/include two",
                "-isystem",
                "../project/system",
                "-I../project/include-one/../include-one",
                "-c",
                str(source_a),
            ],
        },
        {
            "directory": str(build),
            "file": str(source_b),
            "command": (
                f'cc -I../project/include-one -I "../project/include two" '
                f'-isystem ../project/system -I../project/include-one/../include-one -c "{source_b}"'
            ),
        },
    ]

    database = _write_database(tmp_path / "compile_commands.json", entries)
    expected = (
        str(include_one.resolve()),
        str(include_two.resolve()),
        str(system.resolve()),
    )
    assert database.roots_for(str(source_a)) == expected
    assert database.roots_for(str(source_b)) == expected


def test_relative_directory_and_per_tu_roots_do_not_leak(tmp_path):
    project = tmp_path / "project"
    build = project / "build"
    inc_a = project / "inc-a"
    inc_b = project / "inc-b"
    build.mkdir(parents=True)
    inc_a.mkdir()
    inc_b.mkdir()
    source_a = project / "a.c"
    source_b = project / "b.c"
    source_a.write_text("int a;\n", encoding="utf-8")
    source_b.write_text("int b;\n", encoding="utf-8")

    database = CompileCommandIncludeDatabase.from_data(
        [
            {
                "directory": "build",
                "file": "../a.c",
                "arguments": ["cc", "-I", "../inc-a", "-c", "../a.c"],
            },
            {
                "directory": "build",
                "file": "../b.c",
                "arguments": ["cc", "-I../inc-b", "-c", "../b.c"],
            },
        ],
        database_dir=str(project),
    )

    assert database.roots_for(str(source_a)) == (str(inc_a.resolve()),)
    assert database.roots_for(str(source_b)) == (str(inc_b.resolve()),)
    assert str(inc_b.resolve()) not in database.roots_for(str(source_a))
    assert str(inc_a.resolve()) not in database.roots_for(str(source_b))


def test_unsupported_include_affecting_flags_are_diagnosed_not_approximated(tmp_path):
    source = tmp_path / "main.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

    database = CompileCommandIncludeDatabase.from_data(
        [
            {
                "directory": str(tmp_path),
                "file": str(source),
                "arguments": [
                    "cc",
                    "-iquote",
                    "quotes-only",
                    "--sysroot=/toolchain",
                    "-nostdinc",
                    "-c",
                    str(source),
                ],
            }
        ],
        database_dir=str(tmp_path),
    )

    assert database.roots_for(str(source)) == ()
    warning_text = "\n".join(database.warnings)
    assert "-iquote" in warning_text
    assert "--sysroot=/toolchain" in warning_text
    assert "-nostdinc" in warning_text


def test_compile_database_header_context_recovers_declaration_only_signature(tmp_path):
    include_dir = tmp_path / "generated headers"
    include_dir.mkdir()
    header = include_dir / "api.h"
    header.write_text("void sink(unsigned char value);\n", encoding="utf-8")
    source = tmp_path / "main.c"
    source.write_text(
        "#include <api.h>\n"
        "int caller(unsigned int value) { sink(value); return 0; }\n",
        encoding="utf-8",
    )

    database = _write_database(
        tmp_path / "compile_commands.json",
        [
            {
                "directory": str(tmp_path),
                "file": str(source),
                "arguments": ["cc", "-I", str(include_dir), "-c", str(source)],
            }
        ],
    )
    config = ScanConfig.create(
        rules=[IntegerNarrowingCastRule()],
        engine_mode=AnalysisEngine.AST,
    )

    without_database = CompileDatabaseCGullScanner(config=config).scan_path(str(source), quiet=True)
    with_database = CompileDatabaseCGullScanner(
        config=config,
        compile_database=database,
    ).scan_path(str(source), quiet=True)

    assert [issue.cwe_id for issue in without_database.issues] == []
    assert [issue.cwe_id for issue in with_database.issues] == ["CWE-197"]
    assert "parameter 'value'" in with_database.issues[0].message


def test_parallel_scan_uses_same_per_file_config_hook(tmp_path):
    include_dir = tmp_path / "include"
    include_dir.mkdir()
    (include_dir / "api.h").write_text("void sink(unsigned char value);\n", encoding="utf-8")
    source = tmp_path / "main.c"
    source.write_text(
        "#include <api.h>\n"
        "int caller(unsigned int value) { sink(value); return 0; }\n",
        encoding="utf-8",
    )
    database = _write_database(
        tmp_path / "compile_commands.json",
        [{
            "directory": str(tmp_path),
            "file": str(source),
            "arguments": ["cc", "-I", str(include_dir), "-c", str(source)],
        }],
    )
    config = ScanConfig.create(
        rules=[IntegerNarrowingCastRule()],
        engine_mode=AnalysisEngine.AST,
    )

    result = CompileDatabaseCGullScanner(config=config, compile_database=database).scan_path(
        str(source), jobs=2, quiet=True
    )
    assert [issue.cwe_id for issue in result.issues] == ["CWE-197"]


def test_explicit_include_roots_precede_compile_database_roots(tmp_path):
    explicit = tmp_path / "explicit"
    build_root = tmp_path / "build-root"
    explicit.mkdir()
    build_root.mkdir()
    (explicit / "api.h").write_text("void sink(unsigned int value);\n", encoding="utf-8")
    (build_root / "api.h").write_text("void sink(unsigned char value);\n", encoding="utf-8")
    source = tmp_path / "main.c"
    source.write_text(
        "#include <api.h>\n"
        "int caller(unsigned int value) { sink(value); return 0; }\n",
        encoding="utf-8",
    )

    database = _write_database(
        tmp_path / "compile_commands.json",
        [
            {
                "directory": str(tmp_path),
                "file": str(source),
                "arguments": ["cc", "-I", str(build_root), "-c", str(source)],
            }
        ],
    )
    config = ScanConfig.create(
        rules=[IntegerNarrowingCastRule()],
        engine_mode=AnalysisEngine.AST,
        include_roots=[str(explicit)],
    )

    result = CompileDatabaseCGullScanner(
        config=config,
        compile_database=database,
    ).scan_path(str(source), quiet=True)

    assert result.issues == []


def test_cli_loads_compile_database_json_only_once(monkeypatch, tmp_path):
    import cgull.cli as cli

    source = tmp_path / "main.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    db_path = tmp_path / "compile_commands.json"
    db_path.write_text(json.dumps([{
        "directory": str(tmp_path),
        "file": str(source),
        "arguments": ["cc", "-DVALUE=7", "-I", str(tmp_path), "-c", str(source)],
    }]), encoding="utf-8")

    original_loader = cli.load_compile_commands_data
    calls = []

    def counting_loader(path):
        calls.append(os.path.realpath(os.fspath(path)))
        return original_loader(path)

    monkeypatch.setattr(cli, "load_compile_commands_data", counting_loader)
    args = cli.build_parser().parse_args([
        "scan", str(source), "--compile-commands", str(db_path), "--mode", "tu", "--quiet"
    ])

    assert cli.handle_scan(args) == 0
    assert calls == [os.path.realpath(str(db_path))]
