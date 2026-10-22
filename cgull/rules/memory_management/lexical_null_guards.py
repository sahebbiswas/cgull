"""
Lexical NULL-guard reasoning for CGULL-004's regex-fallback path (#587).

When a function has no usable CFG (for example the file fell back to the
regex-fallback parser because an export macro such as ``CJSON_PUBLIC(type)`` is
not defined), CGULL-004 judges parameter uses from source text.  This module
lets that path honor the same guards the CFG path honors:

* an enclosing ``while (p != NULL)``, ``for (...; p; ...)`` or ``if (p)`` body
  (and the ``else`` branch of ``if (p == NULL)``);
* an early-exit guard such as ``if (!p) return NULL;`` or
  ``if (!IsFoo(p)) { return NULL; }`` that dominates the use;
* a same-statement short circuit: ``p && p->x``, ``!p || p->x``, ``p ? p->x : 0``;
* same-translation-unit ``Is*``-style predicates that return a falsy constant
  for a NULL parameter, so a truthy result proves the argument non-NULL.

The reasoning is deliberately conservative about *what counts as a guard*: a
guard must dominate the use (it cannot sit in a block that closed before the
use) and an early-exit guard must actually leave the function or loop.  A use
with no such guard is still reported.
"""

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from ...utils import extract_balanced_parens, mask_string_and_char_literals, split_call_args

_NULL = r"(?:NULL|nullptr|0|0x0)"
_FALSY_LITERALS = {"", "0", "0x0", "0.0", "0.0f", "NULL", "nullptr", "false", "FALSE"}
_EXIT_RE = re.compile(r"\b(?:return|goto|break|continue|abort|exit|_Exit|quick_exit)\b")
_CONTROL_RE = re.compile(r"\b(if|while|for)\b\s*\(")
_CAST_PREFIX_RE = re.compile(r"^\(\s*[A-Za-z_][\w\s\*]*\)\s*(.+)$", re.DOTALL)
_CALL_RE = re.compile(r"^([A-Za-z_]\w*)\s*\((.*)\)$", re.DOTALL)

Predicates = Dict[str, FrozenSet[int]]


def _matching_close(text: str, open_pos: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def _strip_parens(text: str) -> str:
    text = text.strip()
    while text.startswith("(") and text.endswith(")") and _matching_close(text, 0, "(", ")") == len(text) - 1:
        text = text[1:-1].strip()
    return text


def _split_top_level(text: str, operator: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    i = 0
    width = len(operator)
    while i < len(text):
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and text.startswith(operator, i):
            parts.append(text[start:i])
            start = i + width
            i += width
            continue
        i += 1
    parts.append(text[start:])
    return parts


def _strip_casts(text: str) -> str:
    text = _strip_parens(text)
    while True:
        match = _CAST_PREFIX_RE.match(text)
        if not match:
            return text
        text = _strip_parens(match.group(1))


def is_falsy_return(expr: str) -> bool:
    """Whether a return expression is a definite falsy/nullish constant (or bare ``return;``)."""
    return _strip_casts(expr) in _FALSY_LITERALS


def _predicate_call_matches(expr: str, var: str, predicates: Predicates) -> bool:
    """True for ``IsFoo(.., var, ..)`` where IsFoo proves that argument non-NULL when truthy."""
    match = _CALL_RE.match(_strip_parens(expr))
    if not match:
        return False
    indexes = predicates.get(match.group(1))
    if not indexes:
        return False
    args = split_call_args(match.group(2))
    return any(index < len(args) and _strip_casts(args[index]) == var for index in indexes)


def _is_nonnull_form(term: str, var: str, predicates: Predicates) -> bool:
    """Whether *term* being true proves *var* is non-NULL."""
    term = _strip_parens(term)
    n = re.escape(var)
    if term == var:
        return True
    if re.fullmatch(rf"{n}\s*!=\s*{_NULL}|{_NULL}\s*!=\s*{n}", term):
        return True
    negated = re.fullmatch(r"!\s*(.+)", term, re.DOTALL)
    if negated:
        inner = _strip_parens(negated.group(1))
        if re.fullmatch(rf"{n}\s*==\s*{_NULL}|{_NULL}\s*==\s*{n}", inner):
            return True
        if _is_null_form(inner, var, predicates):
            return True
        return False
    return _predicate_call_matches(term, var, predicates)


def _is_null_form(term: str, var: str, predicates: Predicates) -> bool:
    """Whether *term* being false proves *var* is non-NULL (term is a 'var is NULL/falsy' test)."""
    term = _strip_parens(term)
    n = re.escape(var)
    if re.fullmatch(rf"{n}\s*==\s*{_NULL}|{_NULL}\s*==\s*{n}", term):
        return True
    negated = re.fullmatch(r"!\s*(.+)", term, re.DOTALL)
    if negated:
        inner = _strip_parens(negated.group(1))
        if inner == var:
            return True
        if re.fullmatch(rf"{n}\s*!=\s*{_NULL}|{_NULL}\s*!=\s*{n}", inner):
            return True
        return _predicate_call_matches(inner, var, predicates)
    return False


def cond_true_proves_nonnull(cond: str, var: str, predicates: Predicates) -> bool:
    """``cond`` evaluating true implies *var* is non-NULL (some ``&&`` conjunct proves it)."""
    cond = _strip_parens(cond)
    conjuncts = _split_top_level(cond, "&&")
    if len(conjuncts) > 1:
        return any(cond_true_proves_nonnull(c, var, predicates) for c in conjuncts)
    return _is_nonnull_form(cond, var, predicates)


def cond_false_proves_nonnull(cond: str, var: str, predicates: Predicates) -> bool:
    """``cond`` evaluating false implies *var* is non-NULL (some ``||`` disjunct is a NULL test)."""
    cond = _strip_parens(cond)
    disjuncts = _split_top_level(cond, "||")
    if len(disjuncts) > 1:
        return any(cond_false_proves_nonnull(d, var, predicates) for d in disjuncts)
    return _is_null_form(cond, var, predicates)


@dataclass(frozen=True)
class _Control:
    kind: str  # "if" | "while" | "for"
    cond: str
    keyword_pos: int
    guard_start: int  # first offset at which the (true) condition has been established
    then_start: int
    then_end: int
    else_start: int
    else_end: int
    depth: int

    @property
    def end(self) -> int:
        return max(self.then_end, self.else_end)


class LexicalBody:
    """A function body as masked text plus its control constructs."""

    def __init__(self, lines: Sequence[str]):
        masked = [mask_string_and_char_literals(line) for line in lines]
        self.text = "\n".join(masked)
        self.line_starts: List[int] = []
        offset = 0
        for line in masked:
            self.line_starts.append(offset)
            offset += len(line) + 1
        self._depth_at: List[int] = [0] * (len(self.text) + 1)
        depth = 0
        for i, ch in enumerate(self.text):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            self._depth_at[i + 1] = depth
        self.controls: List[_Control] = self._find_controls()

    # -- construction ------------------------------------------------------

    def _skip_space(self, pos: int) -> int:
        while pos < len(self.text) and self.text[pos].isspace():
            pos += 1
        return pos

    def _statement_end(self, pos: int) -> int:
        """Offset one past the statement starting at *pos* (after whitespace)."""
        text = self.text
        pos = self._skip_space(pos)
        if pos >= len(text):
            return len(text)
        if text[pos] == "{":
            return _matching_close(text, pos, "{", "}") + 1
        keyword = re.match(r"(if|while|for)\b\s*\(", text[pos:])
        if keyword:
            inside, close = extract_balanced_parens(text, pos + keyword.end() - 1)
            if inside is None:
                return len(text)
            body_end = self._statement_end(close + 1)
            if keyword.group(1) == "if":
                after = self._skip_space(body_end)
                if re.match(r"else\b", text[after:]):
                    return self._statement_end(after + 4)
            return body_end
        if re.match(r"do\b", text[pos:]):
            body_end = self._statement_end(pos + 2)
            after = self._skip_space(body_end)
            if re.match(r"while\b", text[after:]):
                semi = text.find(";", after)
                return len(text) if semi < 0 else semi + 1
            return body_end
        depth = 0
        for i in range(pos, len(text)):
            ch = text[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == ";" and depth <= 0:
                return i + 1
        return len(text)

    def _find_controls(self) -> List[_Control]:
        text = self.text
        controls: List[_Control] = []
        for match in _CONTROL_RE.finditer(text):
            kind = match.group(1)
            open_pos = match.end() - 1
            inside, close = extract_balanced_parens(text, open_pos)
            if inside is None:
                continue
            after = self._skip_space(close + 1)
            if kind == "while" and after < len(text) and text[after] == ";":
                continue  # tail of a do { } while (cond); loop
            cond = inside
            guard_start = close + 1
            if kind == "for":
                clauses = _split_top_level(inside, ";")
                cond = clauses[1] if len(clauses) == 3 else ""
                # Both the condition and the increment clause run after the
                # condition has been established for that iteration.
                guard_start = open_pos + 1 + len(clauses[0]) + 1 + len(clauses[1]) + 1 if len(clauses) == 3 else close + 1
            then_start = close + 1
            then_end = self._statement_end(then_start)
            else_start = else_end = then_end
            if kind == "if":
                nxt = self._skip_space(then_end)
                if re.match(r"else\b", text[nxt:]):
                    else_start = nxt + 4
                    else_end = self._statement_end(else_start)
            controls.append(
                _Control(
                    kind=kind,
                    cond=cond,
                    keyword_pos=match.start(),
                    guard_start=guard_start,
                    then_start=then_start,
                    then_end=then_end,
                    else_start=else_start,
                    else_end=else_end,
                    depth=self._depth_at[match.start()],
                )
            )
        return controls

    # -- queries -----------------------------------------------------------

    def position(self, line_index: int, column: int) -> int:
        return self.line_starts[line_index] + column

    def _dominates(self, control: _Control, use_pos: int) -> bool:
        """The construct ends before *use_pos* without its enclosing block closing in between."""
        if control.end > use_pos:
            return False
        return all(self._depth_at[k] >= control.depth for k in range(control.end, use_pos + 1))

    def _always_exits(self, start: int, end: int) -> bool:
        text = self.text
        region = text[start:end]
        if not region.strip():
            return False
        first = self._skip_space(start)
        if first < len(text) and text[first] == "{":
            base = self._depth_at[first + 1]
            return any(
                self._depth_at[start + m.start()] == base for m in _EXIT_RE.finditer(region)
            )
        return _EXIT_RE.search(region) is not None

    def _statement_prefix(self, use_pos: int) -> str:
        i = use_pos
        while i > 0 and self.text[i - 1] not in ";{}":
            i -= 1
        return self.text[i:use_pos]

    def is_guarded(self, var: str, use_pos: int, predicates: Predicates) -> bool:
        """Whether *use_pos* is dominated by a guard that proves *var* non-NULL."""
        for control in self.controls:
            if control.cond and control.kind in ("if", "while") and control.then_start <= use_pos < control.then_end:
                if cond_true_proves_nonnull(control.cond, var, predicates):
                    return True
            elif control.cond and control.kind == "for" and control.guard_start <= use_pos < control.then_end:
                if cond_true_proves_nonnull(control.cond, var, predicates):
                    return True
            if (
                control.kind == "if"
                and control.else_end > control.else_start
                and control.else_start <= use_pos < control.else_end
                and cond_false_proves_nonnull(control.cond, var, predicates)
            ):
                return True
            if (
                control.kind == "if"
                and cond_false_proves_nonnull(control.cond, var, predicates)
                and self._dominates(control, use_pos)
                and self._always_exits(control.then_start, control.then_end)
            ):
                return True
        return self._short_circuit_guard(var, use_pos, predicates)

    def _short_circuit_guard(self, var: str, use_pos: int, predicates: Predicates) -> bool:
        prefix = self._statement_prefix(use_pos)
        n = re.escape(var)
        lead = r"(?<![\w.>!-])"
        positive = (
            rf"{lead}{n}\s*&&",
            rf"{lead}{n}\s*!=\s*{_NULL}\s*&&",
            rf"{lead}{_NULL}\s*!=\s*{n}\s*&&",
            rf"{lead}{n}\s*\?",
            rf"{lead}{n}\s*!=\s*{_NULL}\s*\?",
        )
        negative = (
            rf"{lead}{n}\s*==\s*{_NULL}\s*\|\|",
            rf"{lead}{_NULL}\s*==\s*{n}\s*\|\|",
            rf"!\s*{n}\s*\|\|",
        )
        if any(re.search(pattern, prefix) for pattern in positive + negative):
            return True
        for match in re.finditer(r"(!?)\s*([A-Za-z_]\w*)\s*\(", prefix):
            inside, close = extract_balanced_parens(prefix, match.end() - 1)
            if inside is None:
                continue
            tail = prefix[close + 1:].lstrip()
            call = f"{match.group(2)}({inside})"
            if not match.group(1) and tail.startswith("&&") and _predicate_call_matches(call, var, predicates):
                return True
            if match.group(1) and tail.startswith("||") and _predicate_call_matches(call, var, predicates):
                return True
        return False

    # -- predicate derivation ---------------------------------------------

    def returns(self) -> List[Tuple[int, str]]:
        found: List[Tuple[int, str]] = []
        for match in re.finditer(r"\breturn\b([^;]*);", self.text):
            found.append((match.start(), match.group(1).strip()))
        return found


def derive_truthy_nonnull_predicates(functions: Iterable) -> Predicates:
    """Same-TU functions whose truthy result proves a pointer argument non-NULL.

    A function qualifies for parameter ``p`` when every return that is not a
    falsy constant is dominated by an early-exit ``if (p == NULL) return <falsy>;``
    guard, mirroring the CFG summary's ``truthy_implies_nonnull`` contract.
    """
    predicates: Dict[str, FrozenSet[int]] = {}
    for fn in functions:
        name = getattr(fn, "name", None)
        body = getattr(fn, "body", None)
        params = list(getattr(fn, "parameters", None) or [])
        if not name or not body or not params:
            continue
        lexical = LexicalBody(body.splitlines())
        returns = lexical.returns()
        truthy_returns = [(pos, expr) for pos, expr in returns if not is_falsy_return(expr)]
        if not truthy_returns:
            continue
        indexes = set()
        for index, param in enumerate(params):
            p_name = getattr(param, "name", None)
            if not p_name or not getattr(param, "is_pointer", False):
                continue
            guards = []
            for control in lexical.controls:
                if control.kind != "if" or not cond_false_proves_nonnull(control.cond, p_name, {}):
                    continue
                inside = [expr for pos, expr in returns if control.then_start <= pos < control.then_end]
                if not inside or not all(is_falsy_return(expr) for expr in inside):
                    continue
                if not lexical._always_exits(control.then_start, control.then_end):
                    continue
                guards.append(control)
            if guards and all(
                any(lexical._dominates(guard, pos) for guard in guards) for pos, _expr in truthy_returns
            ):
                indexes.add(index)
        if indexes:
            predicates[str(name)] = frozenset(indexes)
    return predicates
