"""Regression coverage for concrete conditional resolution on the shared IR."""

import re

import pytest

import cgull.ast_analyzer.preprocessor as prep


def _legacy_reference(code: str, defined_syms=None) -> str:
    """Reference the pre-#428 concrete resolver for differential fixtures."""
    macros = prep._normalize_macro_dict(defined_syms)
    lines = code.splitlines()
    output = []
    stack = []
    i = 0

    def active():
        return True if not stack else stack[-1]["parent_active"] and stack[-1]["is_taken"]

    while i < len(lines):
        line = lines[i]
        if not line.lstrip().startswith("#"):
            output.append(line if active() else "")
            i += 1
            continue

        parts = []
        indices = []
        cursor = i
        while cursor < len(lines):
            current = lines[cursor]
            indices.append(cursor)
            stripped = current.rstrip()
            if stripped.endswith("\\"):
                parts.append(stripped[:-1])
                cursor += 1
            else:
                parts.append(stripped)
                break
        i = cursor + 1
        body = " ".join(parts).strip().lstrip("#").strip()

        m_ifdef = re.match(r"^ifdef\s+([a-zA-Z_]\w*)", body)
        m_ifndef = re.match(r"^ifndef\s+([a-zA-Z_]\w*)", body)
        m_if = re.match(r"^if\b\s*(.*)", body)
        m_elif = re.match(r"^elif\b\s*(.*)", body)
        m_else = re.match(r"^else\b", body)
        m_endif = re.match(r"^endif\b", body)
        m_define = re.match(r"^define\s+([a-zA-Z_]\w*)(?:\([^)]*\))?(?:\s+(.*))?$", body)
        m_undef = re.match(r"^undef\s+([a-zA-Z_]\w*)", body)
        parent_active = active()

        if m_ifdef or m_ifndef or m_if:
            if m_ifdef:
                expr = f"defined({m_ifdef.group(1)})"
            elif m_ifndef:
                expr = f"!defined({m_ifndef.group(1)})"
            else:
                expr = m_if.group(1)
            taken = prep.eval_preprocessor_expr(expr, macros) if parent_active else False
            stack.append({"has_taken": taken, "is_taken": taken, "parent_active": parent_active})
            output.extend("" for _ in indices)
        elif m_elif:
            if stack:
                top = stack[-1]
                if top["has_taken"]:
                    top["is_taken"] = False
                else:
                    taken = prep.eval_preprocessor_expr(m_elif.group(1), macros) if top["parent_active"] else False
                    top["is_taken"] = taken
                    top["has_taken"] = taken
            output.extend("" for _ in indices)
        elif m_else:
            if stack:
                top = stack[-1]
                top["is_taken"] = False if top["has_taken"] else top["parent_active"]
                top["has_taken"] = True
            output.extend("" for _ in indices)
        elif m_endif:
            if stack:
                stack.pop()
            output.extend("" for _ in indices)
        elif m_define:
            if parent_active:
                name = m_define.group(1)
                raw = (m_define.group(2) or "").strip()
                if not raw or raw.startswith("//") or raw.startswith("/*"):
                    macros[name] = 1
                else:
                    clean = re.sub(r"/\*.*?\*/|//.*", "", raw).strip()
                    number = re.match(r"^-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*$", clean)
                    if number:
                        parsed = prep._parse_c_int_literal(clean)
                        macros[name] = parsed if parsed is not None else 1
                    elif prep.eval_preprocessor_expr(clean, macros):
                        tokens = prep._tokenize_c_prep_expr(clean, macros)
                        macros[name] = prep._eval_c_prep_tokens(tokens) if tokens else 1
                    else:
                        macros[name] = 1
                output.extend(lines[index] for index in indices)
            else:
                output.extend("" for _ in indices)
        elif m_undef:
            if parent_active:
                macros.pop(m_undef.group(1), None)
                output.extend(lines[index] for index in indices)
            else:
                output.extend("" for _ in indices)
        elif parent_active:
            output.extend(lines[index] for index in indices)
        else:
            output.extend("" for _ in indices)

    result = "\n".join(output)
    if code.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


@pytest.mark.parametrize(
    ("source", "defined_syms"),
    [
        (
            "#define MODE 2\n"
            "#if MODE == 1\nint a;\n"
            "#elif MODE == 2\nint b;\n"
            "#else\nint c;\n#endif\n",
            None,
        ),
        (
            "#ifdef OUTER\n"
            "#define INNER 4\n"
            "#if INNER > 3\nint nested;\n#endif\n"
            "#undef INNER\n"
            "#else\nint fallback;\n#endif\n",
            {"OUTER": 1},
        ),
        (
            "#if defined(A) \\\n"
            " || defined(B)\n"
            "int selected;\n"
            "#else\nint other;\n#endif\n",
            {"B"},
        ),
    ],
)
def test_shared_ir_resolver_matches_legacy_reference(source, defined_syms):
    assert prep.resolve_preprocessor_conditionals(source, defined_syms) == _legacy_reference(source, defined_syms)


def test_shared_ir_parser_is_the_structural_source(monkeypatch):
    real_parser = prep.parse_conditional_directives
    calls = []

    def recording_parser(source):
        calls.append(source)
        return real_parser(source)

    monkeypatch.setattr(prep, "parse_conditional_directives", recording_parser)
    source = "#if 0\nint hidden;\n#else\nint visible;\n#endif\n"
    result = prep.resolve_preprocessor_conditionals(source)

    assert calls == [source]
    assert "int visible;" in result
    assert "int hidden;" not in result


def test_multiline_directive_alignment_is_exact():
    source = (
        "#if defined(A) \\\n"
        " || defined(B)\n"
        "int selected;\n"
        "#else\n"
        "int other;\n"
        "#endif\n"
    )
    result = prep.resolve_preprocessor_conditionals(source, {"B"})

    assert len(result.splitlines()) == len(source.splitlines())
    assert result.count("\n") == source.count("\n")
    assert result.splitlines()[0:2] == ["", ""]
    assert result.splitlines()[2] == "int selected;"


def test_define_and_undef_mutations_still_control_later_conditions():
    source = (
        "#define FEATURE 2\n"
        "#if FEATURE == 2\nint first;\n#endif\n"
        "#undef FEATURE\n"
        "#ifdef FEATURE\nint second;\n#else\nint third;\n#endif\n"
    )
    result = prep.resolve_preprocessor_conditionals(source)

    assert "int first;" in result
    assert "int second;" not in result
    assert "int third;" in result


def test_refactor_does_not_add_elifdef_concrete_semantics():
    source = (
        "#if 0\n"
        "int first;\n"
        "#elifdef FEATURE\n"
        "int second;\n"
        "#else\n"
        "int fallback;\n"
        "#endif\n"
    )
    result = prep.resolve_preprocessor_conditionals(source, {"FEATURE"})

    assert result == _legacy_reference(source, {"FEATURE"})
    assert "int second;" not in result
    assert "int fallback;" in result


def test_continued_conditional_at_eof_without_newline_blanks_every_physical_line():
    source = "#if defined(A) \\\n && defined(B)"

    result = prep.resolve_preprocessor_conditionals(source, {"A", "B"})

    assert result == _legacy_reference(source, {"A", "B"})
    assert result == "\n"
