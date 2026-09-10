"""Lossless conditional structure, independent of macro configuration.

Offsets are Python string offsets, ranges are half-open, and line/column values
are one-based. Parsing recovers after errors and never chooses active branches.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
import re

from .expressions import (
    Constant, Defined, Expression, Predicate, Variable, Negation,
    Conjunction, Disjunction, negate,
)


@dataclass(frozen=True)
class SourceLocation:
    offset: int
    line: int
    column: int


@dataclass(frozen=True)
class SourceRange:
    start: SourceLocation
    end: SourceLocation

    def text(self, source: str) -> str:
        return source[self.start.offset:self.end.offset]


@dataclass(frozen=True)
class DirectiveToken:
    text: str
    source_range: SourceRange


@dataclass(frozen=True)
class StructureDiagnostic:
    code: str
    message: str
    source_range: SourceRange


@dataclass(frozen=True)
class ConditionalDirective:
    kind: str
    source_range: SourceRange
    condition_range: SourceRange | None
    condition_text: str | None
    logical_condition: str | None
    condition: Expression | None
    tokens: tuple[DirectiveToken, ...]


@dataclass(eq=False)
class ConditionalBranch:
    directive: ConditionalDirective
    body_range: SourceRange
    block: ConditionalBlock = field(repr=False)
    children: list[ConditionalBlock] = field(default_factory=list)


@dataclass(eq=False)
class ConditionalBlock:
    source_range: SourceRange
    parent: ConditionalBranch | None = field(default=None, repr=False)
    branches: list[ConditionalBranch] = field(default_factory=list)
    endif: ConditionalDirective | None = None


@dataclass
class ConditionalTree:
    source: str
    blocks: list[ConditionalBlock]
    directives: tuple[ConditionalDirective, ...]
    diagnostics: tuple[StructureDiagnostic, ...]


_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
# A preprocessing number owns its digit separators; prefixes such as u8 on
# character literals are identifiers, not numbers.
_PP_NUMBER = r"(?:[0-9]|\.[0-9])(?:[eEpP][+-]|[A-Za-z0-9_.]|'[A-Za-z0-9_])*"
_NUMBER = re.compile(_PP_NUMBER)
_TOKEN = re.compile(r'''[A-Za-z_][A-Za-z0-9_]*|''' + _PP_NUMBER + r'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|&&|\|\||==|!=|<=|>=|<<|>>|[^\s]''')
_FORMS = frozenset(('if', 'ifdef', 'ifndef', 'elif', 'elifdef', 'elifndef', 'else', 'endif'))


def _logical_source(source: str) -> tuple[str, str, list[int]]:
    """Splice before recognizing comments; retain every surviving offset."""
    chars: list[str] = []
    offsets: list[int] = []
    i = 0
    while i < len(source):
        if source.startswith('\\\r\n', i):
            i += 3
        elif source.startswith('\\\n', i):
            i += 2
        else:
            chars.append(source[i])
            offsets.append(i)
            i += 1
    # Mask comments and literals separately: literals must prevent recognition
    # of comment delimiters, but their contents remain available in conditions.
    text = ''.join(chars)
    hidden: list[tuple[int, int]] = []
    i = 0
    while i < len(text):
        if i == 0 or not (text[i - 1].isalnum() or text[i - 1] == '_'):
            number = _NUMBER.match(text, i)
            if number:
                i = number.end()
                continue
        raw = re.match(r'R"([^ ()\\\t\r\n]{0,16})\(', text[i:i + 20]) if text.startswith('R"', i) else None
        if raw:
            end_marker = ')' + raw[1] + '"'
            end = text.find(end_marker, i + raw.end())
            end = len(text) if end < 0 else end + len(end_marker)
            hidden.append((i, end))
            i = end
            continue
        if text.startswith('//', i):
            end = text.find('\n', i)
            end = len(text) if end < 0 else end
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            end = len(text) if end < 0 else end + 2
        elif text[i] in '\"\'':
            literal_start = i
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == '\\':
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            hidden.append((literal_start, min(i, len(text))))
            continue
        else:
            i += 1
            continue
        for j in range(i, end):
            if chars[j] not in '\r\n':
                chars[j] = ' '
        i = end
    masked = chars.copy()
    for start, end in hidden:
        for j in range(start, end):
            if masked[j] not in '\r\n':
                masked[j] = '@'
    return ''.join(chars), ''.join(masked), offsets


def _atom(text: str) -> Expression:
    """Recognize unambiguous atoms; retain value-bearing syntax opaquely.

    Deliberately do not split arbitrary C expressions on Boolean operators:
    ternaries, comma expressions and macro calls require a C expression parser.
    """
    if _IDENTIFIER.fullmatch(text):
        return Variable(text)
    match = re.fullmatch(r'defined\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|\s+([A-Za-z_]\w*))', text, re.ASCII)
    if match:
        return Defined(match[1] or match[2])
    if re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)[uUlL]*', text):
        digits = text.rstrip('uUlL')
        base = 16 if digits.lower().startswith('0x') else 2 if digits.lower().startswith('0b') else 8 if digits.startswith('0') else 10
        value_digits = digits[2:] if base in (2, 16) else digits
        return Constant(any(char != "0" for char in value_digits))
    return Predicate(text)


def _condition(text: str) -> Expression:
    """Extract Boolean structure only where C operator precedence permits it."""
    tokens = list(_TOKEN.finditer(text))
    depth = 0
    top: list[re.Match[str]] = []
    for token in tokens:
        if token[0] == '(':
            depth += 1
        elif token[0] == ')':
            depth -= 1
            if depth < 0:
                return Predicate(text)
        elif depth == 0:
            top.append(token)
    if depth:
        return Predicate(text)
    # These bind less tightly than ||; decomposing them would change semantics.
    if any(t[0] in ('?', ':', ',', '=') for t in top):
        return Predicate(text)
    for operator, node in (('||', Disjunction), ('&&', Conjunction)):
        splits = [t for t in top if t[0] == operator]
        if splits:
            parts = []
            start = 0
            for token in splits:
                parts.append(text[start:token.start()].strip())
                start = token.end()
            parts.append(text[start:].strip())
            return node(tuple(_condition(part) for part in parts)) if all(parts) else Predicate(text)
    if tokens and tokens[0][0] == '(' and not top:
        # Verify the first opening parenthesis encloses the entire expression.
        depth = 0
        for index, token in enumerate(tokens):
            depth += (token[0] == '(') - (token[0] == ')')
            if depth == 0:
                if index == len(tokens) - 1 and text[1:-1].strip():
                    return _condition(text[1:-1].strip())
                break
    if top and top[0][0] == '!' and not any(
        t[0] in ('+', '-', '*', '/', '%', '<', '>', '<=', '>=', '==', '!=', '&', '|', '^', '<<', '>>')
        for t in top[1:]
    ):
        operand = text[1:].strip()
        if operand:
            return Negation(_condition(operand))
    return _atom(text)


def parse_conditional_directives(source: str) -> ConditionalTree:
    """Build ordered blocks and branches, preserving malformed directives too.

    Structural errors are returned in source order. Invalid conditions have no
    symbolic expression; complex C expressions are opaque Predicate nodes, not
    validated or evaluated. An unclosed block extends to EOF. A branch after
    #else is retained with a diagnostic so no source structure is discarded.
    """
    starts = [0] + [m.end() for m in re.finditer('\n', source)]

    def location(offset: int) -> SourceLocation:
        line = bisect_right(starts, offset)
        return SourceLocation(offset, line, offset - starts[line - 1] + 1)

    def span(start: int, end: int) -> SourceRange:
        return SourceRange(location(start), location(end))

    logical, masked, offsets = _logical_source(source)
    roots: list[ConditionalBlock] = []
    stack: list[ConditionalBlock] = []
    directives: list[ConditionalDirective] = []
    errors: list[StructureDiagnostic] = []

    def error(code: str, message: str, where: SourceRange) -> None:
        errors.append(StructureDiagnostic(code, message, where))

    seen_else: set[int] = set()
    cursor = 0
    for line_match in re.finditer(r'[^\n]*\n|[^\n]+$', logical):
        line = line_match[0]
        line_start = cursor
        cursor += len(line)
        match = re.match(r'^[ \t\v\f\r]*#[ \t]*([A-Za-z_][A-Za-z0-9_]*)', masked[line_start:cursor])
        if match is None or match[1] not in _FORMS:
            continue
        kind = match[1]
        begin = offsets[line_start - 1] + 1 if line_start else 0
        end = offsets[cursor - 1] + 1 if line.endswith('\n') else len(source)
        directive_range = span(begin, end)
        tokens = tuple(DirectiveToken(m[0], span(offsets[line_start + m.start()], offsets[line_start + m.end() - 1] + 1))
                       for m in _TOKEN.finditer(line, match.end()))
        condition_range = span(tokens[0].source_range.start.offset, tokens[-1].source_range.end.offset) if tokens else None
        original = condition_range.text(source) if condition_range else None
        condition_text = line[match.end():].strip()
        expression = None
        if kind in ('else', 'endif'):
            if tokens:
                error('unexpected_tokens', f'#{kind} does not accept a condition', tokens[0].source_range)
        elif not tokens:
            error('missing_condition', f'#{kind} requires a condition', span(offsets[line_start + match.start(1)], offsets[line_start + match.end(1) - 1] + 1))
        elif kind in ('ifdef', 'ifndef', 'elifdef', 'elifndef'):
            if not _IDENTIFIER.fullmatch(tokens[0].text) or len(tokens) != 1:
                error('invalid_macro', f'#{kind} requires exactly one macro identifier', tokens[1 if len(tokens) > 1 else 0].source_range)
            else:
                expression = Defined(tokens[0].text)
                if kind in ('ifndef', 'elifndef'):
                    expression = negate(expression)
        else:
            try:
                expression = _condition(condition_text)
            except RecursionError:
                # Structural parsing remains usable for deeply nested C syntax.
                expression = Predicate(condition_text)
        directive = ConditionalDirective(kind, directive_range, condition_range, original,
                                         condition_text or None, expression, tokens)
        directives.append(directive)
        if kind in ('if', 'ifdef', 'ifndef'):
            parent = stack[-1].branches[-1] if stack else None
            block = ConditionalBlock(span(begin, len(source)), parent)
            (parent.children if parent else roots).append(block)
            block.branches.append(ConditionalBranch(directive, span(end, len(source)), block))
            stack.append(block)
        elif not stack:
            error('misplaced_directive', f'#{kind} has no matching opening directive', directive_range)
        else:
            block = stack[-1]
            previous = block.branches[-1]
            previous.body_range = span(previous.body_range.start.offset, begin)
            if kind == 'endif':
                block.endif = directive
                block.source_range = span(block.source_range.start.offset, end)
                stack.pop()
            else:
                if id(block) in seen_else:
                    code = 'duplicate_else' if kind == 'else' else 'branch_after_else'
                    error(code, f'#{kind} follows #else', directive_range)
                if kind == 'else':
                    seen_else.add(id(block))
                block.branches.append(ConditionalBranch(directive, span(end, len(source)), block))
    for block in stack:
        error('unterminated_block', 'conditional block has no #endif', block.branches[0].directive.source_range)
    errors.sort(key=lambda item: item.source_range.start.offset)
    return ConditionalTree(source, roots, tuple(directives), tuple(errors))
