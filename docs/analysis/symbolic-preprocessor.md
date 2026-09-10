# Symbolic preprocessor expression API

`cgull.preprocessor` provides the expression IR introduced in issue #420. It is
independent of `cgull.ast_analyzer.preprocessor`: it does not replace
`eval_preprocessor_expr`, resolve active branches, parse directives, or emit
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
