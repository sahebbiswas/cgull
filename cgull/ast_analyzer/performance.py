"""Performance-focused overrides for C AST fallback extraction.

The legacy extractor remains in :mod:`cgull.ast_analyzer.visitor` for
backward compatibility.  This module provides the public parser class with
line-number and function-range bookkeeping that stays linear (or n log n)
on files containing thousands of small functions.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..utils import mask_string_and_char_literals, strip_comments_keep_lines
from .configuration import _STATEMENT_KEYWORDS, is_unsigned_type
from .fallback_functions import extract_fallback_functions
from .types import CFunction, CVariable, _map_line, resolve_typedef_shape
from .visitor import CASTParser as _LegacyCASTParser


class CoverageDegradedError(RuntimeError):
    """Raised when required preprocessing coverage cannot be guaranteed."""


def _masked_source_code(source_code: str) -> str:
    """Return source with comments and literal contents hidden from code matching."""
    _, comment_free = strip_comments_keep_lines(source_code)
    return "\n".join(mask_string_and_char_literals(line) for line in comment_free.splitlines())


def _fallback_macro_brace_sequence(
    text: str,
    macros: Dict[str, Tuple[bool, str]],
    expanding: Optional[Set[str]] = None,
) -> str:
    """Return braces contributed by text and known macro expansions in source order."""
    masked_text = mask_string_and_char_literals(text)
    active = expanding or set()
    braces: List[str] = []
    position = 0

    for match in re.finditer(r"\b[A-Za-z_]\w*\b", masked_text):
        braces.extend(char for char in masked_text[position:match.start()] if char in "{}")

        macro_name = match.group(0)
        macro = macros.get(macro_name)
        if macro is not None and macro_name not in active:
            function_like, replacement = macro
            invoked = not function_like or masked_text[match.end():].lstrip().startswith("(")
            if invoked:
                braces.extend(
                    _fallback_macro_brace_sequence(
                        replacement,
                        macros,
                        active | {macro_name},
                    )
                )

        position = match.end()

    braces.extend(char for char in masked_text[position:] if char in "{}")
    return "".join(braces)


def _record_fallback_macro_directive(
    directive: str,
    macros: Dict[str, Tuple[bool, str]],
) -> None:
    """Update fallback macro state from one complete logical directive."""
    undef = re.match(r"^\s*#\s*undef\s+([A-Za-z_]\w*)\b", directive)
    if undef:
        macros.pop(undef.group(1), None)
        return

    define = re.match(r"^\s*#\s*define\s+([A-Za-z_]\w*)(.*)$", directive)
    if not define:
        return

    macro_name = define.group(1)
    tail = define.group(2)
    function_like = tail.startswith("(")
    if function_like:
        params_end = tail.find(")")
        if params_end < 0:
            return
        replacement = tail[params_end + 1:].lstrip()
    else:
        replacement = tail.lstrip()

    macros[macro_name] = (function_like, replacement)


def _fallback_file_scope_depths(lines: List[str]):
    """Yield lexical brace depth at each physical line's first token.

    ``lines`` is the fallback pipeline's already comment-stripped and
    conditionally-resolved source. String/character literal contents are masked
    before brace accounting. Preprocessor directive bodies are excluded from
    source-level brace counting, while known macro definitions are tracked so
    braces contributed by unexpanded macro uses still affect lexical scope.
    """
    depth = 0
    in_directive = False
    directive_parts: List[str] = []
    macros: Dict[str, Tuple[bool, str]] = {}

    for line in lines:
        directive_line = in_directive or line.lstrip().startswith("#")
        yield depth, directive_line

        if directive_line:
            directive_part = line.rstrip()
            continued = directive_part.endswith("\\")
            if continued:
                directive_part = directive_part[:-1]
            directive_parts.append(directive_part)
            in_directive = continued
            if not continued:
                _record_fallback_macro_directive(" ".join(directive_parts), macros)
                directive_parts.clear()
            continue

        in_directive = False
        for char in _fallback_macro_brace_sequence(line, macros):
            if char == "{":
                depth += 1
            else:
                depth = max(0, depth - 1)


def _declares_offsetof_function(masked_source: str) -> bool:
    """Return True for an explicit user function declaration/definition named offsetof."""
    declaration = re.compile(
        r"(?m)^[ \t]*(?!(?:return|if|for|while|switch|sizeof)\b)"
        r"(?:[A-Za-z_]\w*[ \t*]+)+offsetof\s*\([^;{}]*\)\s*(?:;|\{)"
    )
    return bool(declaration.search(masked_source))


def _source_has_builtin_offsetof_use(source_code: str) -> bool:
    """Detect genuine code uses of offsetof while excluding literals and user functions."""
    masked_source = _masked_source_code(source_code)
    if _declares_offsetof_function(masked_source):
        return False
    return bool(re.search(r"\boffsetof\s*\(", masked_source))


def _has_unexpanded_offsetof(pycparser_ast) -> bool:
    """Return True when a parsed AST contains an unresolved macro-style offsetof call."""
    if pycparser_ast is None:
        return False

    try:
        from pycparser import c_ast
    except ImportError:
        return False

    class Visitor(c_ast.NodeVisitor):
        def __init__(self):
            self.found_call = False
            self.has_function_declaration = False

        def visit_Decl(self, node):
            if node.name == "offsetof" and isinstance(node.type, c_ast.FuncDecl):
                self.has_function_declaration = True
            self.generic_visit(node)

        def visit_FuncCall(self, node):
            if isinstance(node.name, c_ast.ID) and node.name.name == "offsetof":
                self.found_call = True
                return
            self.generic_visit(node)

    visitor = Visitor()
    visitor.visit(pycparser_ast)
    return visitor.found_call and not visitor.has_function_declaration


class CASTParser(_LegacyCASTParser):
    """CAST parser with optimized extraction and preprocessing coverage guards."""

    def parse(self, source_code, defined_syms=None, line_map=None):
        ctx = super().parse(source_code, defined_syms=defined_syms, line_map=line_map)

        # ``offsetof`` is a macro in supported C environments.  If a genuine
        # macro-style use remains in code but parsing fell below the
        # pcpp+pycparser tier, the security-relevant container/layout recovery
        # path is no longer trustworthy.  Comments, literals, and explicit
        # user-defined functions named ``offsetof`` are excluded.
        source_has_offsetof = _source_has_builtin_offsetof_use(source_code)
        coverage_degraded = (
            source_has_offsetof and ctx.parse_tier != "pcpp+pycparser"
        ) or _has_unexpanded_offsetof(ctx.pycparser_ast)
        if coverage_degraded:
            raise CoverageDegradedError(
                "AST preprocessing/layout precision degraded: offsetof(...) "
                "reached analysis unexpanded or preprocessing fell back before "
                "macro expansion. Container-recovery and member-layout security "
                "checks cannot be considered complete."
            )

        return ctx

    def _extract_functions(
        self,
        lines: List[str],
        full_code: str,
        custom_typedefs: Optional[Set[str]] = None,
        line_map: Optional[Dict[int, Any]] = None,
    ) -> List[CFunction]:
        return extract_fallback_functions(
            self,
            lines,
            full_code,
            custom_typedefs=custom_typedefs,
            line_map=line_map,
        )

    def _extract_global_vars(
        self,
        lines: List[str],
        functions: List[CFunction],
        custom_typedefs: Optional[Set[str]] = None,
        line_map: Optional[Dict[int, Any]] = None,
    ) -> Dict[str, CVariable]:
        global_vars: Dict[str, CVariable] = {}

        # ``functions`` remains part of the compatibility signature, but file
        # scope must not depend on successful fallback function recognition.
        # Lexical brace depth is the independent safety boundary.
        del functions

        var_decl_regex = re.compile(
            r'^[ \t]*((?:volatile\s+|static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*|\w|\s)*?)\s*(\w+)(?:\[([^\]]*)\])?(?:\s*=\s*([^;]+))?;'
        )

        for line_no_exp, (line, scope_info) in enumerate(
            zip(lines, _fallback_file_scope_depths(lines)),
            1,
        ):
            scope_depth, directive_line = scope_info
            if directive_line or scope_depth != 0:
                continue

            line_no = _map_line(line_no_exp, line_map)
            m = var_decl_regex.match(line)
            if not m:
                continue

            type_prefix = m.group(1).strip()
            v_name = m.group(2).strip()
            type_tokens = type_prefix.split()
            if type_tokens and type_tokens[-1] in _STATEMENT_KEYWORDS:
                continue
            if v_name in ("typedef", "#include", "#define", "#ifdef", "#ifndef"):
                continue

            shape = resolve_typedef_shape(type_prefix, self.typedef_shapes) if getattr(self, "typedef_shapes", None) else None
            v_is_array = (m.group(3) is not None) or (shape.is_array if shape else False)
            v_is_pointer = ("*" in type_prefix) or (shape.is_pointer if shape else False)
            v_arr_dim = m.group(3) if m.group(3) is not None else (
                str(shape.array_size) if shape and shape.array_size is not None else None
            )
            global_vars[v_name] = CVariable(
                name=v_name,
                type_name=type_prefix,
                is_pointer=v_is_pointer,
                is_signed=not is_unsigned_type(type_prefix, custom_typedefs),
                is_volatile="volatile" in type_prefix,
                is_vla=False,
                array_size_expr=v_arr_dim,
                has_initializer=m.group(4) is not None,
                declaration_line=line_no,
                is_array=v_is_array,
            )

        return global_vars


ASTAnalyzer = CASTParser

__all__ = ["CASTParser", "ASTAnalyzer", "CoverageDegradedError"]
