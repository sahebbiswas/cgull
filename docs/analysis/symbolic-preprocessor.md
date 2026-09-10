# Symbolic preprocessor expression API

`cgull.preprocessor` provides the expression IR introduced in issue #420. It is
independent of `cgull.ast_analyzer.preprocessor`: it does not replace
`eval_preprocessor_expr`, resolve active branches, or emit
scanner diagnostics. The model and local Boolean identities are adapted from
the [CPRE prototype](https://github.com/sahebbiswas/tools/blob/084cf086b93aeaf559c4ffd3d9940abb3850bda0/preprocessor_conditions.py).

## Nodes and atom identity

All nodes are frozen, hashable dataclasses. `Conjunction` and `Disjunction` own
tuples of operands (iterable constructor inputs are copied). Leaf payloads and
child types are validated on construction.

| Type | Meaning |
| --- | --- |
| `Constant(bool)` | Boolean truth; `TRUE` and `FALSE` are shared conveniences |
| `Variable(name)` | Boolean truth of a macro's value |
| `Defined(name)` | Whether the macro is defined |
| `Predicate(text)` | An opaque value-bearing C expression |
| `Negation(operand)` | Logical negation |
| `Conjunction(operands)` | Logical conjunction; empty means true |
| `Disjunction(operands)` | Logical disjunction; empty means false |

`Variable("X")`, `Defined("X")`, and `Predicate("X")` are distinct atoms. Unlike
the prototype, the IR preserves definedness separately: a macro defined as zero
is defined but false in a value test. There are no inferred relationships among
different atoms. In particular, `N > 3` and `N <= 3` are independent opaque
predicates until a later analysis supplies integer reasoning.

Predicate text is preserved exactly, including whitespace inside string
literals. Token-aware lexical normalization belongs to a future parser, not
this IR. Macro names must be ASCII C identifiers.

## Normalization and formatting

```python
from cgull.preprocessor import (
    Variable, Defined, Predicate, conjunction, disjunction, negate,
    format_expression, expression_to_dict, expression_from_dict,
)

a = Variable("A")
condition = disjunction(a, conjunction(a, Predicate("VERSION >= 3")))
assert condition == a  # absorption
assert format_expression(conjunction(Defined("X"), negate(Variable("X")))) == (
    "defined(X) && !X"
)
assert expression_from_dict(expression_to_dict(condition)) == condition
```

`normalize` (also exposed as `simplify`) recursively folds constants and double
negation, flattens associative operators, removes duplicates, detects direct
complements, applies absorption, and sorts commutative operands using a typed
structural key. `negate`, `conjunction`, and `disjunction` normalize their results.
Raw dataclass constructors preserve tree structure; compare normalized nodes
when operand ordering should not matter. Normalization is not a complete Boolean
equivalence or satisfiability check; it does not distribute operators or build a
BDD.

`format_expression` normalizes before rendering C-style operators. Parentheses
preserve operator precedence and isolate opaque predicates when embedded. The
display string is not an identity or serialization format: distinct atom types
can have the same display text.

## Enumeration and serialization

- `expression_atoms` returns a set of typed atoms in the original tree, even if
  normalization would remove them. `ordered_atoms` returns these unique atoms
  in deterministic structural order, suitable for a future BDD variable order.
- `expression_predicates` returns a set of opaque texts without extracting
  identifiers from them.
- `expression_to_dict` normalizes and emits JSON-compatible tagged objects.
  `expression_from_dict` validates exact fields and types, rejects unknown kinds
  with `ValueError`, and returns a normalized expression.

The tags are `constant` (`value`), `variable`/`defined` (`name`), `predicate`
(`text`), `not` (`operand`), and `and`/`or` (`operands`, an array). Every object
contains `kind`. For example:

```json
{"kind": "not", "operand": {"kind": "defined", "name": "FEATURE"}}
```

Formatting, normalized structure, ordered atoms, and serialized output are
stable across operand permutations and Python hash seeds. Python's numeric
`hash()` values themselves are process-dependent and must not be persisted.

## Conditional-directive tree

Issue #421 adds `parse_conditional_directives(source)` to the same package:

```python
from cgull.preprocessor import parse_conditional_directives

tree = parse_conditional_directives('#if FEATURE\nint x;\n#else\nint y;\n#endif\n')
block = tree.blocks[0]
assert block.branches[0].body_range.text(tree.source) == 'int x;\n'
assert block.branches[1].directive.kind == 'else'
assert not tree.diagnostics
```

The parser supports `if`, `ifdef`, `ifndef`, `elif`, `elifdef`, `elifndef`,
`else`, and `endif`. It retains every recognized conditional directive in
`tree.directives`, even misplaced directives, in source order. `tree.blocks`
contains top-level blocks; each block owns ordered `branches` and an optional
`endif`. A branch points back to its `block`, owns nested `children`, and each
nested block points to its containing branch through `parent`. Construction is
iterative, so conditional nesting does not depend on Python's recursion limit.
The mutable structural containers use identity equality to avoid recursive
comparison through parent links; directive and location records are frozen and
compare by value.

`tree.source` retains the input exactly. All ranges are half-open Python string
(character, not byte) offsets with one-based original line/column coordinates;
a tab occupies one character column. Call `range.text(tree.source)` to recover
text without reparsing. Directive ranges include the complete physical logical
line, including indentation, continuations, comments and its final newline.
Body ranges extend from the end of the opening/branch directive to the beginning
of the next sibling or closing directive, and include nested blocks. Block
ranges include their opening and closing directives. Unterminated ranges extend
to EOF. LF and CRLF line endings are retained.

Each directive carries condition tokens with original ranges, so even a token
split by a backslash continuation maps back to its original physical lines.
`condition_text` is the exact source slice between the first and last condition
tokens (including intervening comments/continuations); `logical_condition` is
the spliced, comment-masked expression with outer whitespace removed.
`condition_range` is absent when there are no condition tokens. The original
full directive range always retains leading/trailing comments and whitespace.
Comments and quoted literals, including C++ raw strings, cannot create spurious
directives. Other preprocessing directives are left in the source/body ranges.

`condition` recognizes macro truth, `defined`, integer constants, parentheses,
and Boolean `!`, `&&`, and `||` using C precedence. More complex value-bearing
subexpressions remain opaque `Predicate` atoms; ternary/comma expressions are
not incorrectly decomposed into Boolean clauses. Excessively deep expression
syntax also remains opaque. Expression nodes preserve operand order; consumers
can explicitly normalize them with the expression API. This is not a full C
expression syntax checker or macro expander, and opaque predicates carry no
inferred integer semantics.

Recoverable `StructureDiagnostic` records provide `code`, `message`, and an
original `source_range`. Codes cover `misplaced_directive`, `duplicate_else`,
`branch_after_else`, `unterminated_block`, `missing_condition`, `invalid_macro`,
and `unexpected_tokens`. Diagnostics are ordered by source position. Branches
after an `else` are retained with errors; unmatched closing/branch directives
remain in the flat directive list. Invalid macro conditions have no symbolic
expression. Lexical errors outside conditional structure and general C
expression validity are outside this API's diagnostic contract.

The parser does not choose active branches, rewrite source, diagnose redundant
conditions, or participate in the scanner's concrete preprocessing path.
