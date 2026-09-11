"""Preprocessor condition evaluation and source-normalization helpers."""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from ..preprocessor.directives import ConditionalDirective, parse_conditional_directives


@dataclass
class _CondFrame:
    has_taken: bool
    is_taken: bool
    parent_active: bool


def _parse_c_int_literal(literal_str: str) -> Optional[int]:
    """
    Parses a C integer literal string into an int.
    Supports hexadecimal (0x/0X), binary (0b/0B), legacy octal (leading 0 followed by octal digits),
    decimal numbers, leading signs (+/-), and C integer suffixes (U, L, UL, ULL, etc.).
    Returns None if parsing fails.
    """
    if not literal_str:
        return None
    s = literal_str.strip()
    sign = 1
    if s.startswith('-'):
        sign = -1
        s = s[1:].strip()
    elif s.startswith('+'):
        s = s[1:].strip()

    s = re.sub(r'[uUlL]+$', '', s)
    if not s:
        return None

    try:
        if s.startswith(('0x', '0X')):
            return sign * int(s[2:], 16)
        elif s.startswith(('0b', '0B')):
            return sign * int(s[2:], 2)
        elif s.startswith('0') and len(s) > 1 and s.isdigit():
            return sign * int(s, 8)
        else:
            return sign * int(s, 10)
    except ValueError:
        return None


_C_PREP_TOKEN_RE = re.compile(
    r'(?P<WHITESPACE>[ \t\r\n]+)|'
    r'(?P<NUMBER>(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*)|'
    r'(?P<IDENT>[a-zA-Z_]\w*)|'
    r'(?P<LOGICAL_OR>\|\|)|'
    r'(?P<LOGICAL_AND>&&)|'
    r'(?P<EQUAL>==)|'
    r'(?P<NOT_EQUAL>!=)|'
    r'(?P<LESS_EQUAL><=)|'
    r'(?P<GREATER_EQUAL>>=)|'
    r'(?P<LSHIFT><<)|'
    r'(?P<RSHIFT>>>)|'
    r'(?P<LPAREN>\()|'
    r'(?P<RPAREN>\))|'
    r'(?P<LOGICAL_NOT>!)|'
    r'(?P<BITWISE_NOT>~)|'
    r'(?P<ADD>\+)|'
    r'(?P<SUB>-)|'
    r'(?P<MUL>\*)|'
    r'(?P<DIV>/)|'
    r'(?P<MOD>%)|'
    r'(?P<LESS><)|'
    r'(?P<GREATER>>)|'
    r'(?P<BITWISE_AND>&)|'
    r'(?P<BITWISE_XOR>\^)|'
    r'(?P<BITWISE_OR>\|)'
)


def _tokenize_c_prep_expr(expr_str: str, macros: Dict[str, int]) -> Optional[List[Tuple[str, Any]]]:
    s = expr_str.strip()

    # Pre-resolve defined(SYM) and defined SYM
    def replace_defined(m):
        sym = m.group(1) or m.group(2)
        return " 1 " if sym in macros else " 0 "

    s = re.sub(
        r'\bdefined\s*\(\s*([a-zA-Z_]\w*)\s*\)|\bdefined\s+([a-zA-Z_]\w*)',
        replace_defined,
        s
    )

    tokens: List[Tuple[str, Any]] = []
    pos = 0
    n = len(s)

    while pos < n:
        m = _C_PREP_TOKEN_RE.match(s, pos)
        if not m:
            return None  # Unrecognized character
        pos = m.end()

        kind = m.lastgroup
        if kind == 'WHITESPACE':
            continue

        raw_text = m.group(kind)

        if kind == 'NUMBER':
            val = _parse_c_int_literal(raw_text)
            if val is not None:
                tokens.append(('NUMBER', val))
            else:
                return None
        elif kind == 'IDENT':
            if raw_text == 'true':
                tokens.append(('NUMBER', 1))
            elif raw_text == 'false':
                tokens.append(('NUMBER', 0))
            elif raw_text in macros:
                val = macros[raw_text]
                try:
                    num_val = int(val) if val is not None else 1
                except (TypeError, ValueError):
                    num_val = 1
                tokens.append(('NUMBER', num_val))
            else:
                tokens.append(('NUMBER', 0))
        else:
            tokens.append((kind, None))

    if len(tokens) > 500:
        return None  # DoS guard

    return tokens


_INFIX_BP = {
    'LOGICAL_OR':    (1, 2),
    'LOGICAL_AND':   (3, 4),
    'BITWISE_OR':    (5, 6),
    'BITWISE_XOR':   (7, 8),
    'BITWISE_AND':   (9, 10),
    'EQUAL':         (11, 12),
    'NOT_EQUAL':     (11, 12),
    'LESS':          (13, 14),
    'LESS_EQUAL':    (13, 14),
    'GREATER':       (13, 14),
    'GREATER_EQUAL': (13, 14),
    'LSHIFT':        (15, 16),
    'RSHIFT':        (15, 16),
    'ADD':           (17, 18),
    'SUB':           (17, 18),
    'MUL':           (19, 20),
    'DIV':           (19, 20),
    'MOD':           (19, 20),
}


def _eval_c_prep_tokens(tokens: List[Tuple[str, Any]]) -> int:
    pos = 0
    n = len(tokens)

    def parse_expr(min_bp: int = 0) -> int:
        nonlocal pos
        if pos >= n:
            return 0

        tok_type, tok_val = tokens[pos]
        pos += 1

        if tok_type == 'NUMBER':
            left = tok_val
        elif tok_type == 'LPAREN':
            left = parse_expr(0)
            if pos < n and tokens[pos][0] == 'RPAREN':
                pos += 1
        elif tok_type == 'LOGICAL_NOT':
            right = parse_expr(21)
            left = 1 if (right == 0) else 0
        elif tok_type == 'BITWISE_NOT':
            right = parse_expr(21)
            left = ~right
        elif tok_type == 'ADD':
            left = parse_expr(21)
        elif tok_type == 'SUB':
            left = -parse_expr(21)
        else:
            return 0

        while pos < n:
            op_type = tokens[pos][0]
            if op_type not in _INFIX_BP:
                break
            lbp, rbp = _INFIX_BP[op_type]
            if lbp < min_bp:
                break
            pos += 1  # consume op

            right = parse_expr(rbp)

            if op_type == 'LOGICAL_OR':
                left = 1 if (left != 0 or right != 0) else 0
            elif op_type == 'LOGICAL_AND':
                left = 1 if (left != 0 and right != 0) else 0
            elif op_type == 'BITWISE_OR':
                left = left | right
            elif op_type == 'BITWISE_XOR':
                left = left ^ right
            elif op_type == 'BITWISE_AND':
                left = left & right
            elif op_type == 'EQUAL':
                left = 1 if (left == right) else 0
            elif op_type == 'NOT_EQUAL':
                left = 1 if (left != right) else 0
            elif op_type == 'LESS':
                left = 1 if (left < right) else 0
            elif op_type == 'LESS_EQUAL':
                left = 1 if (left <= right) else 0
            elif op_type == 'GREATER':
                left = 1 if (left > right) else 0
            elif op_type == 'GREATER_EQUAL':
                left = 1 if (left >= right) else 0
            elif op_type == 'LSHIFT':
                shift_amt = max(0, min(63, right))
                left = left << shift_amt
            elif op_type == 'RSHIFT':
                shift_amt = max(0, min(63, right))
                left = left >> shift_amt
            elif op_type == 'ADD':
                left = left + right
            elif op_type == 'SUB':
                left = left - right
            elif op_type == 'MUL':
                left = left * right
            elif op_type == 'DIV':
                left = left // right if right != 0 else 0
            elif op_type == 'MOD':
                left = left % right if right != 0 else 0

        return left

    try:
        return parse_expr(0)
    except Exception:
        return 0


def _normalize_macro_dict(defined_syms: Optional[Any]) -> Dict[str, int]:
    """
    Normalizes defined_syms into a Dict[str, int] suitable for preprocessor expression evaluation.
    Handles sets/lists/tuples (mapping symbols to 1) and dicts/Mapping (converting values
    including None for presence toggles, bools, ints, and string integers to int).
    Note: Entries whose value is explicitly False (e.g. from #undef in a seed header) are omitted
    so defined(SYM) returns False and sym in macros evaluates to False.
    """
    if not defined_syms:
        return {}

    if isinstance(defined_syms, (set, list, tuple, frozenset)):
        return {str(s): 1 for s in defined_syms}

    if isinstance(defined_syms, (dict, Mapping)):
        macros: Dict[str, int] = {}
        for k, v in defined_syms.items():
            key = str(k)
            if v is False:
                continue
            elif v is None:
                macros[key] = 1
            elif isinstance(v, bool):
                macros[key] = 1 if v else 0
            elif isinstance(v, int):
                macros[key] = v
            elif isinstance(v, str):
                v_clean = v.strip()
                parsed_int = _parse_c_int_literal(v_clean)
                if parsed_int is not None:
                    macros[key] = parsed_int
                else:
                    macros[key] = 1 if v_clean else 0
            else:
                try:
                    macros[key] = int(v)
                except (TypeError, ValueError):
                    macros[key] = 1
        return macros

    return {}


def eval_preprocessor_expr(expr_str: str, defined_syms: Optional[Any] = None) -> bool:
    """
    Evaluates a C preprocessor condition expression (for #if / #elif) under
    the assumption of `defined_syms` / `macros`. Any undefined identifier evaluates to 0 (false).
    Supports C operator precedence, numeric macro expansion, integer suffixes (U, L, UL, etc.),
    and contains DoS protections against extreme shifts or division by zero.
    """
    if not expr_str or not expr_str.strip():
        return False

    macros = _normalize_macro_dict(defined_syms)

    tokens = _tokenize_c_prep_expr(expr_str, macros)
    if tokens is None or len(tokens) == 0:
        return False

    val = _eval_c_prep_tokens(tokens)
    return bool(val != 0)


_CONCRETE_CONDITIONAL_KINDS = frozenset(("if", "ifdef", "ifndef", "elif", "else", "endif"))


def _conditional_directives_by_line(code: str) -> Dict[int, ConditionalDirective]:
    """Index concrete-supported conditional directives by physical start line."""
    tree = parse_conditional_directives(code)
    return {
        directive.source_range.start.line - 1: directive
        for directive in tree.directives
        if directive.kind in _CONCRETE_CONDITIONAL_KINDS
    }


def _directive_line_count(code: str, directive: ConditionalDirective) -> int:
    """Return the number of IR physical lines occupied by a directive range."""
    text = directive.source_range.text(code)
    return max(1, len(text.split("\n")) - (1 if text.endswith("\n") else 0))


def _conditional_expr(directive: ConditionalDirective) -> str:
    """Recover the concrete expression without depending on symbolic interpretation."""
    if directive.kind == "ifdef":
        symbol = directive.tokens[0].text if directive.tokens else ""
        return f"defined({symbol})"
    if directive.kind == "ifndef":
        symbol = directive.tokens[0].text if directive.tokens else ""
        return f"!defined({symbol})"
    return directive.logical_condition or ""


def resolve_preprocessor_conditionals(code: str, defined_syms: Optional[Any] = None) -> str:
    """Resolve concrete preprocessor branches using the shared directive IR.

    Structural recognition and physical directive ranges come from
    :func:`parse_conditional_directives`; concrete C-integer expression semantics
    and macro mutation remain local to this resolver. Directive lines and inactive
    branch bodies are blanked to preserve exact source line alignment.
    """
    macros: Dict[str, int] = _normalize_macro_dict(defined_syms)
    # The directive IR numbers only '\n' as a physical line boundary. Use the
    # identical model here so directive indices remain aligned even when source
    # contains lone '\r', form-feed, vertical-tab, or Unicode separators. Drop
    # the terminal split sentinel to preserve the legacy splitlines()/join output
    # contract, which does not retain a source-final newline.
    lines = code.split("\n")
    if code.endswith("\n"):
        lines.pop()
    output_lines: List[str] = []
    cond_stack: List[_CondFrame] = []
    conditional_by_line = _conditional_directives_by_line(code)

    i = 0
    n = len(lines)
    while i < n:
        directive = conditional_by_line.get(i)
        if directive is not None:
            line_count = min(_directive_line_count(code, directive), n - i)
            parent_act = True if not cond_stack else (
                cond_stack[-1].parent_active and cond_stack[-1].is_taken
            )

            if directive.kind in ("if", "ifdef", "ifndef"):
                val = eval_preprocessor_expr(_conditional_expr(directive), macros) if parent_act else False
                cond_stack.append(_CondFrame(has_taken=val, is_taken=val, parent_active=parent_act))
            elif directive.kind == "elif":
                if cond_stack:
                    top = cond_stack[-1]
                    if top.has_taken:
                        top.is_taken = False
                    else:
                        val = eval_preprocessor_expr(_conditional_expr(directive), macros) if top.parent_active else False
                        top.is_taken = val
                        if val:
                            top.has_taken = True
            elif directive.kind == "else":
                if cond_stack:
                    top = cond_stack[-1]
                    if top.has_taken:
                        top.is_taken = False
                    else:
                        top.is_taken = top.parent_active
                        top.has_taken = True
            elif directive.kind == "endif" and cond_stack:
                cond_stack.pop()

            output_lines.extend("" for _ in range(line_count))
            i += line_count
            continue

        line = lines[i]
        line_lstrip = line.lstrip()
        if line_lstrip.startswith('#'):
            directive_parts: List[str] = []
            directive_line_indices: List[int] = []
            curr_i = i
            while curr_i < n:
                curr_line = lines[curr_i]
                directive_line_indices.append(curr_i)
                curr_rstrip = curr_line.rstrip()
                if curr_rstrip.endswith('\\'):
                    directive_parts.append(curr_rstrip[:-1])
                    curr_i += 1
                else:
                    directive_parts.append(curr_rstrip)
                    break

            full_directive_str = " ".join(directive_parts).strip()
            dir_body = full_directive_str.lstrip('#').strip()
            m_define = re.match(r'^define\s+([a-zA-Z_]\w*)(?:\([^)]*\))?(?:\s+(.*))?$', dir_body)
            m_undef = re.match(r'^undef\s+([a-zA-Z_]\w*)', dir_body)
            current_active = True if not cond_stack else (
                cond_stack[-1].parent_active and cond_stack[-1].is_taken
            )

            if m_define and current_active:
                m_name = m_define.group(1)
                m_val_raw = (m_define.group(2) or "").strip()
                if not m_val_raw or m_val_raw.startswith('//') or m_val_raw.startswith('/*'):
                    macros[m_name] = 1
                else:
                    val_clean = re.sub(r'/\*.*?\*/|//.*', '', m_val_raw).strip()
                    m_num = re.match(r'^-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*$', val_clean)
                    if m_num:
                        parsed_int = _parse_c_int_literal(val_clean)
                        macros[m_name] = parsed_int if parsed_int is not None else 1
                    elif eval_preprocessor_expr(val_clean, macros):
                        tokens = _tokenize_c_prep_expr(val_clean, macros)
                        macros[m_name] = _eval_c_prep_tokens(tokens) if tokens else 1
                    else:
                        macros[m_name] = 1
                output_lines.extend(lines[idx] for idx in directive_line_indices)
            elif m_undef and current_active:
                macros.pop(m_undef.group(1), None)
                output_lines.extend(lines[idx] for idx in directive_line_indices)
            elif current_active:
                output_lines.extend(lines[idx] for idx in directive_line_indices)
            else:
                output_lines.extend("" for _ in directive_line_indices)

            i = curr_i + 1
            continue

        current_active = True if not cond_stack else (
            cond_stack[-1].parent_active and cond_stack[-1].is_taken
        )
        output_lines.append(line if current_active else "")
        i += 1

    return "\n".join(output_lines)


def _strip_attributes_and_specifiers(code: str) -> str:
    """
    Strips GNU/Clang __attribute__((...)) and MSVC __declspec(...) constructs
    from C source code while preserving character/line offsets (replacing
    stripped tokens with spaces/newlines).
    """
    result = []
    i = 0
    n = len(code)
    targets = [('__attribute__', 13), ('__declspec', 10)]
    while i < n:
        matched = False
        for kw, kw_len in targets:
            if code[i:i + kw_len] == kw:
                j = i + kw_len
                while j < n and code[j].isspace():
                    j += 1
                if j < n and code[j] == '(':
                    paren_depth = 0
                    k = j
                    while k < n:
                        if code[k] == '(':
                            paren_depth += 1
                        elif code[k] == ')':
                            paren_depth -= 1
                            if paren_depth == 0:
                                k += 1
                                break
                        k += 1
                    chunk = code[i:k]
                    spaces = ''.join('\n' if c == '\n' else ' ' for c in chunk)
                    result.append(spaces)
                    i = k
                    matched = True
                    break
        if not matched:
            result.append(code[i])
            i += 1
    return ''.join(result)