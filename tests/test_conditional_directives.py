"""Structural preprocessor parsing never selects or rewrites branches."""
import pytest

from cgull.preprocessor import (
    Constant, Defined, Predicate, Variable, Negation, Conjunction, Disjunction,
    negate, parse_conditional_directives,
)


@pytest.mark.parametrize(('kind', 'text', 'expression'), [
    ('if', 'FLAG', Variable('FLAG')),
    ('if', 'defined ( FLAG )', Defined('FLAG')),
    ('if', 'defined FLAG', Defined('FLAG')),
    ('if', '0', Constant(False)),
    ('if', '0xffUL', Constant(True)),
    ('if', '077', Constant(True)),
    ('if', '0b10', Constant(True)),
    ('if', '42', Constant(True)),
    ('if', 'VERSION >= 3', Predicate('VERSION >= 3')),
    ('ifdef', 'FLAG', Defined('FLAG')),
    ('ifndef', 'FLAG', negate(Defined('FLAG'))),
    ('elif', 'OTHER', Variable('OTHER')),
    ('elifdef', 'OTHER', Defined('OTHER')),
    ('elifndef', 'OTHER', negate(Defined('OTHER'))),
])
def test_forms(kind, text, expression):
    prefix = '#if FIRST\n' if kind.startswith('elif') else ''
    source = prefix + f'#{kind} {text}\nbody\n#else\nfallback\n#endif\n'
    tree = parse_conditional_directives(source)
    assert not tree.diagnostics
    branch = tree.blocks[0].branches[-2]
    assert branch.directive.kind == kind
    assert branch.directive.condition == expression
    assert branch.directive.condition_text == text
    assert branch.body_range.text(source) == 'body\n'
    assert tree.blocks[0].branches[-1].directive.condition is None
    assert tree.blocks[0].endif.kind == 'endif'
    assert tree.source == source


def test_nested_order_parent_and_exact_ranges():
    source = 'before\n  #if A\nfirst\n#ifdef B\nnested\n#endif\n#elif C\nlast\n#endif\nafter\n#if D\n#endif'
    tree = parse_conditional_directives(source)
    assert not tree.diagnostics
    outer, second = tree.blocks
    a, c = outer.branches
    child, = a.children
    assert child.parent is a
    assert a.block is outer and c.block is outer
    assert outer.parent is None and second.parent is None
    assert child.branches[0].body_range.text(source) == 'nested\n'
    assert a.body_range.text(source) == 'first\n#ifdef B\nnested\n#endif\n'
    assert c.body_range.text(source) == 'last\n'
    assert outer.source_range.text(source).endswith('#endif\n')
    assert a.directive.source_range.text(source) == '  #if A\n'
    assert a.directive.tokens[0].source_range.start.line == 2
    assert a.directive.tokens[0].source_range.start.column == 7
    assert [d.kind for d in tree.directives] == ['if', 'ifdef', 'endif', 'elif', 'endif', 'if', 'endif']


@pytest.mark.parametrize('newline', ['\n', '\r\n'])
def test_continuations_and_per_token_diagnostic_locations(newline):
    source = newline.join(['  #if DEFI\\', 'NED', 'body', '#elifdef \\', '  GOOD \\', '  BAD', '#endif', ''])
    tree = parse_conditional_directives(source)
    assert tree.blocks[0].branches[0].directive.condition == Variable('DEFINED')
    token = tree.directives[0].tokens[0]
    assert (token.source_range.start.line, token.source_range.start.column) == (1, 7)
    assert (token.source_range.end.line, token.source_range.end.column) == (2, 4)
    assert token.source_range.text(source) == 'DEFI\\' + newline + 'NED'
    error, = tree.diagnostics
    assert error.code == 'invalid_macro'
    assert (error.source_range.start.line, error.source_range.start.column) == (6, 3)
    directive = tree.directives[1]
    assert directive.source_range.start.line == 4
    assert directive.condition_text == 'GOOD \\' + newline + '  BAD'
    assert directive.source_range.end.line == 7


@pytest.mark.parametrize(('source', 'codes'), [
    ('#elif A\n#else\n#endif\n', ['misplaced_directive'] * 3),
    ('#if A\n#else\n#else\n#elif B\n#endif', ['duplicate_else', 'branch_after_else']),
    ('#if A\n#ifdef B\n', ['unterminated_block'] * 2),
    ('#if\n#endif', ['missing_condition']),
    ('#ifdef 23\n#endif', ['invalid_macro']),
    ('#ifndef A B\n#endif', ['invalid_macro']),
    ('#if A\n#else bad\n#endif bad', ['unexpected_tokens'] * 2),
])
def test_structured_errors_and_recovery(source, codes):
    tree = parse_conditional_directives(source)
    assert [d.code for d in tree.diagnostics] == codes
    assert len(tree.directives) == source.count('#')
    assert all(d.message and d.source_range.text(source) for d in tree.diagnostics)


def test_unterminated_ranges_reach_eof():
    source = '#if A\nfoo\n#else\nbar'
    tree = parse_conditional_directives(source)
    block, = tree.blocks
    assert block.endif is None
    assert block.source_range.text(source) == source
    assert block.branches[-1].body_range.text(source) == 'bar'


def test_comments_strings_nonconditional_directives_and_spliced_line_comment():
    source = ('/*\n#if FAKE\n*/\n// hide \\\n#if HIDDEN\n'
              'char *s = "#if STRING // /*";\n#define X 1\n'
              '/* prefix */ #if FLAG /* comment */\n'
              'body\n#endif // end\n')
    tree = parse_conditional_directives(source)
    assert not tree.diagnostics
    assert [d.kind for d in tree.directives] == ['if', 'endif']
    assert tree.directives[0].condition == Variable('FLAG')
    assert tree.blocks[0].branches[0].body_range.text(source) == 'body\n'


def test_opaque_conditions_preserve_literal_whitespace_and_precedence():
    for text in ['A ? B || C : D', '!A == B', "' ' == 'x'", 'CHECK("a  b")']:
        tree = parse_conditional_directives(f'#if {text}\n#endif')
        assert tree.directives[0].condition == Predicate(text)


def test_empty_input_and_deep_nesting_are_iterative():
    assert parse_conditional_directives('').blocks == []
    depth = 1500
    tree = parse_conditional_directives('#if A\n' * depth + '#endif\n' * depth)
    assert not tree.diagnostics
    branch = tree.blocks[0].branches[0]
    for _ in range(depth - 1):
        branch = branch.children[0].branches[0]
    assert not branch.children


def test_deterministic_flat_directives_and_diagnostics():
    source = '#if Z\n#ifdef A\n#endif\n#else\n#else\n#endif'
    first = parse_conditional_directives(source)
    second = parse_conditional_directives(source)
    assert first.directives == second.directives
    assert first.diagnostics == second.diagnostics


def test_boolean_structure_obeys_c_precedence():
    tree = parse_conditional_directives('#if A || B && !(defined(C) || N > 3)\n#endif')
    assert tree.directives[0].condition == Disjunction((
        Variable('A'), Conjunction((Variable('B'), Negation(Disjunction((
            Defined('C'), Predicate('N > 3'),
        ))))),
    ))


@pytest.mark.parametrize('text', ['A)', '(A', 'A &&', '()', '(A)(B)', 'A, B || C', '!'])
def test_unsupported_expression_remains_opaque(text):
    assert parse_conditional_directives(f'#if {text}\n#endif').directives[0].condition == Predicate(text)


def test_cpp_raw_strings_cannot_introduce_directives():
    source = 'auto x = R"tag(\n#if FAKE\n/* ignore */\n)tag";\n#if REAL\n#endif'
    tree = parse_conditional_directives(source)
    assert not tree.diagnostics
    assert [d.kind for d in tree.directives] == ['if', 'endif']


def test_vertical_whitespace_does_not_start_a_new_logical_line():
    tree = parse_conditional_directives('code;\v#if FAKE\n\f#if REAL\n#endif')
    assert not tree.diagnostics
    assert tree.directives[0].condition == Variable('REAL')


@pytest.mark.parametrize('source', ['/* #if A', '// #if A', '"unterminated', 'R"(unterminated'])
def test_incomplete_non_directive_lexical_material(source):
    assert not parse_conditional_directives(source).directives


def test_leading_splice_belongs_to_its_logical_directive():
    source = '\\\n#if A\nbody\n\\\n#endif\n'
    tree = parse_conditional_directives(source)
    assert not tree.diagnostics
    assert tree.directives[0].source_range.text(source) == '\\\n#if A\n'
    assert tree.directives[1].source_range.text(source) == '\\\n#endif\n'
    assert tree.blocks[0].branches[0].body_range.text(source) == 'body\n'


def test_deep_condition_is_retained_without_aborting_structure():
    condition = '(' * 1500 + 'FLAG' + ')' * 1500
    tree = parse_conditional_directives(f'#if {condition}\n#endif')
    assert not tree.diagnostics
    assert tree.directives[0].condition == Predicate(condition)


@pytest.mark.parametrize('literal', ["1'024", "1'000'000", "0xFF'AB", "0b10'01", "1.2'5e+1'0", ".1'25"])
def test_digit_separators_do_not_hide_following_directives(literal):
    source = f"auto value = {literal};\n#if FEATURE\nbody\n#endif\n"
    tree = parse_conditional_directives(source)
    assert not tree.diagnostics
    assert [d.kind for d in tree.directives] == ['if', 'endif']
    assert tree.directives[0].source_range.start.line == 2
    assert tree.blocks[0].branches[0].body_range.text(source) == 'body\n'


def test_digit_separator_condition_tokens_and_following_character_literal():
    source = "#if LIMIT > 1'024\nchar c = 'x';\n#endif\n"
    tree = parse_conditional_directives(source)
    assert not tree.diagnostics
    assert [t.text for t in tree.directives[0].tokens] == ['LIMIT', '>', "1'024"]
    assert tree.directives[0].tokens[-1].source_range.text(source) == "1'024"
    assert tree.directives[-1].kind == 'endif'


@pytest.mark.parametrize('prefix', ['', 'L', 'u', 'U', 'u8'])
def test_character_literal_prefixes_still_hide_comment_delimiters(prefix):
    source = f"auto c = {prefix}'/*';\n#if FLAG\n#endif\n"
    tree = parse_conditional_directives(source)
    assert not tree.diagnostics
    assert [d.kind for d in tree.directives] == ['if', 'endif']
