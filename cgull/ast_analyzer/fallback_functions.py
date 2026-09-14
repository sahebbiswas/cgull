"""Balanced lexical extraction for regex-fallback C function models."""

from bisect import bisect_left
import re
from typing import Any, Dict, List, Optional, Set

from ..utils import extract_balanced_parens, split_call_args
from .types import CFunction, CParameter, _map_line


_FUNCTION_NAME_EXCLUSIONS = {
    "if", "for", "while", "switch", "catch", "sizeof", "return",
    "__attribute__", "__declspec", "_Pragma",
}
_FUNCTION_PREFIX_FORBIDDEN = {
    "typedef", "return", "if", "for", "while", "switch", "case", "else",
    "do", "goto", "sizeof",
}
_FUNCTION_PREFIX_QUALIFIERS = {
    "static", "extern", "inline", "const", "volatile", "register", "restrict",
    "_Noreturn",
}
_FUNCTION_DECORATORS = {"__attribute__", "__declspec", "_Pragma"}
_FUNCTION_POINTER_PARAM_RE = re.compile(
    r"\(\s*(?:(?:[A-Za-z_]\w*)\s+)*"
    r"(?P<stars>\*+)\s*"
    r"(?:(?:(?:const|volatile|restrict|_Atomic)\s+)*)"
    r"(?P<name>[A-Za-z_]\w*)"
    r"(?P<arrays>(?:\s*\[[^\]]*\])*)\s*\)"
)


def _top_level_identifiers(text: str) -> List[str]:
    identifiers: List[str] = []
    paren_depth = bracket_depth = 0
    in_string = in_char = escape = False
    i = 0
    while i < len(text):
        ch = text[i]
        if escape:
            escape = False
            i += 1
            continue
        if ch == "\\" and (in_string or in_char):
            escape = True
            i += 1
            continue
        if ch == '"' and not in_char:
            in_string = not in_string
            i += 1
            continue
        if ch == "'" and not in_string:
            in_char = not in_char
            i += 1
            continue
        if in_string or in_char:
            i += 1
            continue
        if ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth = max(0, paren_depth - 1)
        elif ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif paren_depth == 0 and bracket_depth == 0 and (ch.isalpha() or ch == "_"):
            end = i + 1
            while end < len(text) and (text[end].isalnum() or text[end] == "_"):
                end += 1
            identifiers.append(text[i:end])
            i = end
            continue
        i += 1
    return identifiers


def _plausible_function_prefix(prefix: str) -> bool:
    """Return whether text before a function name looks like a declaration prefix."""
    if not prefix.strip() or any(ch in prefix for ch in ";={}"):
        return False
    identifiers = _top_level_identifiers(prefix)
    if not identifiers or any(token in _FUNCTION_PREFIX_FORBIDDEN for token in identifiers):
        return False
    substantive = [
        token for token in identifiers
        if token not in _FUNCTION_PREFIX_QUALIFIERS and token not in _FUNCTION_DECORATORS
    ]
    if substantive:
        return True
    # Preserve the legacy fallback's C89 implicit-int recovery for definitions
    # whose prefix consists only of storage/qualifier keywords, e.g. static foo().
    return all(
        token in _FUNCTION_PREFIX_QUALIFIERS or token in _FUNCTION_DECORATORS
        for token in identifiers
    )


def _find_definition_body_start(text: str, start: int) -> Optional[int]:
    """Find a definition's opening brace after its declarator, rejecting prototypes."""
    paren_depth = bracket_depth = 0
    in_string = in_char = escape = False
    i = start
    while i < len(text):
        ch = text[i]
        if escape:
            escape = False
        elif ch == "\\" and (in_string or in_char):
            escape = True
        elif ch == '"' and not in_char:
            in_string = not in_string
        elif ch == "'" and not in_string:
            in_char = not in_char
        elif not in_string and not in_char:
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth = max(0, paren_depth - 1)
            elif ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif paren_depth == 0 and bracket_depth == 0:
                if ch == "{":
                    return i
                if ch in ";=,}":
                    return None
                if ch == "#" and (i == 0 or text[i - 1] == "\n"):
                    return None
        i += 1
    return None


def _find_matching_brace(text: str, opening_brace: int) -> Optional[int]:
    depth = 0
    in_string = in_char = escape = False
    i = opening_brace
    while i < len(text):
        ch = text[i]
        if escape:
            escape = False
        elif ch == "\\" and (in_string or in_char):
            escape = True
        elif ch == '"' and not in_char:
            in_string = not in_string
        elif ch == "'" and not in_string:
            in_char = not in_char
        elif not in_string and not in_char:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return None


def _directive_end(text: str, start: int) -> int:
    """Return the first position after a file-scope preprocessor directive."""
    i = start
    while i < len(text):
        newline = text.find("\n", i)
        if newline < 0:
            return len(text)
        backslash = newline - 1
        while backslash >= start and text[backslash] in " \t\r":
            backslash -= 1
        if backslash >= start and text[backslash] == "\\":
            i = newline + 1
            continue
        return newline + 1
    return len(text)


def _parse_parameter(token: str, line_number: int) -> Optional[CParameter]:
    token = token.strip()
    if not token or token == "...":
        return None

    fn_ptr = _FUNCTION_POINTER_PARAM_RE.search(token)
    if fn_ptr:
        name = fn_ptr.group("name")
        type_name = (token[: fn_ptr.start("name")] + token[fn_ptr.end("name") :]).strip()
        is_array = bool(fn_ptr.group("arrays")) or bool(re.search(r"\)\s*\[", token))
        return CParameter(
            name=name,
            type_name=type_name,
            is_pointer=True,
            line_number=line_number,
            is_array=is_array,
        )

    is_pointer = "*" in token
    parts = token.replace("*", " * ").split()
    if len(parts) >= 2:
        name = parts[-1]
        type_name = " ".join(parts[:-1])
    elif len(parts) == 1:
        name = parts[0]
        type_name = "int"
    else:
        return None

    is_array = False
    array_match = re.match(r"^([A-Za-z_]\w*)\s*(\[[^\]]*\])$", name)
    if array_match:
        name = array_match.group(1)
        type_name = f"{type_name}{array_match.group(2)}"
        is_array = True
    if "[" in type_name:
        is_array = True

    return CParameter(
        name=name,
        type_name=type_name,
        is_pointer=is_pointer,
        line_number=line_number,
        is_array=is_array,
    )


def extract_fallback_functions(
    parser: Any,
    lines: List[str],
    full_code: str,
    custom_typedefs: Optional[Set[str]] = None,
    line_map: Optional[Dict[int, Any]] = None,
) -> List[CFunction]:
    """Extract file-scope function definitions using balanced declarator boundaries."""
    functions: List[CFunction] = []
    newline_offsets = [i for i, ch in enumerate(full_code) if ch == "\n"]

    def line_at(pos: int) -> int:
        return bisect_left(newline_offsets, pos) + 1

    n = len(full_code)
    i = 0
    segment_start = 0
    brace_depth = paren_depth = bracket_depth = 0
    in_string = in_char = escape = False

    while i < n:
        ch = full_code[i]
        if escape:
            escape = False
            i += 1
            continue
        if ch == "\\" and (in_string or in_char):
            escape = True
            i += 1
            continue
        if ch == '"' and not in_char:
            in_string = not in_string
            i += 1
            continue
        if ch == "'" and not in_string:
            in_char = not in_char
            i += 1
            continue
        if in_string or in_char:
            i += 1
            continue

        if brace_depth == 0 and paren_depth == 0 and bracket_depth == 0 and ch == "#":
            line_start = full_code.rfind("\n", 0, i) + 1
            if full_code[line_start:i].strip():
                i += 1
                continue
            i = _directive_end(full_code, i)
            segment_start = i
            continue

        if ch == "{":
            brace_depth += 1
            i += 1
            continue
        if ch == "}":
            brace_depth = max(0, brace_depth - 1)
            if brace_depth == 0:
                segment_start = i + 1
            i += 1
            continue
        if ch == "(":
            paren_depth += 1
            i += 1
            continue
        if ch == ")":
            paren_depth = max(0, paren_depth - 1)
            i += 1
            continue
        if ch == "[":
            bracket_depth += 1
            i += 1
            continue
        if ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
            i += 1
            continue
        if brace_depth == 0 and paren_depth == 0 and bracket_depth == 0 and ch == ";":
            segment_start = i + 1
            i += 1
            continue

        if brace_depth != 0 or paren_depth != 0 or bracket_depth != 0 or not (ch.isalpha() or ch == "_"):
            i += 1
            continue

        name_end = i + 1
        while name_end < n and (full_code[name_end].isalnum() or full_code[name_end] == "_"):
            name_end += 1
        name = full_code[i:name_end]
        open_paren = name_end
        while open_paren < n and full_code[open_paren].isspace():
            open_paren += 1
        if open_paren >= n or full_code[open_paren] != "(" or name in _FUNCTION_NAME_EXCLUSIONS:
            i = name_end
            continue

        params_str, close_paren = extract_balanced_parens(full_code, open_paren)
        if params_str is None:
            i = name_end
            continue

        start_pos = segment_start
        while start_pos < i and full_code[start_pos].isspace():
            start_pos += 1
        return_type = full_code[start_pos:i].strip()
        plausible_prefix = _plausible_function_prefix(return_type)
        if not plausible_prefix:
            line_end = full_code.find("\n", close_paren + 1)
            if line_end < 0:
                line_end = n
            tail = full_code[close_paren + 1 : line_end].strip()
            if tail in ("", ";"):
                segment_start = min(n, line_end + 1)
            i = close_paren + 1
            continue

        body_open = _find_definition_body_start(full_code, close_paren + 1)
        if body_open is None:
            i = close_paren + 1
            continue
        body_close = _find_matching_brace(full_code, body_open)
        if body_close is None:
            i = close_paren + 1
            continue

        start_line_exp = line_at(start_pos)
        start_line = _map_line(start_line_exp, line_map)
        body_start_pos = body_open + 1
        end_line_exp = line_at(body_close + 1)
        end_line = _map_line(end_line_exp, line_map)
        body_start_line_exp = line_at(body_start_pos)
        body_start_line = _map_line(body_start_line_exp, line_map)

        params: List[CParameter] = []
        stripped_params = params_str.strip()
        if stripped_params and stripped_params != "void":
            for token in split_call_args(params_str):
                parameter = _parse_parameter(token, start_line)
                if parameter is not None:
                    params.append(parameter)

        function = CFunction(
            name=name,
            return_type=return_type,
            parameters=params,
            start_line=start_line,
            end_line=end_line,
            body=full_code[body_start_pos:body_close],
            has_void_param_list=stripped_params == "void",
            is_empty_param_list=stripped_params == "",
            body_start_line=body_start_line,
            body_start_line_exp=body_start_line_exp,
            start_line_exp=start_line_exp,
            end_line_exp=end_line_exp,
        )
        parser._analyze_function_body(function, lines, custom_typedefs, line_map=line_map)
        functions.append(function)

        i = body_close + 1
        segment_start = i
        brace_depth = paren_depth = bracket_depth = 0

    return functions


__all__ = ["extract_fallback_functions"]
