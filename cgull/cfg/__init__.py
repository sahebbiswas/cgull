"""Control-flow graph public API, retained at its historic import path."""

from .model import *
from .dataflow import *
from .construction import *
from .fixed_point import *
from .summaries import *
from .ownership import *
from .call_graph import *
from .size_facts import *
from .construction import _deref_vars, _deref_vars_with_lines
from ..ast_analyzer import _PRELUDE_LINE_COUNT

# Star-imported implementation modules historically left their own helper
# imports in this package namespace.  Keep the established CFG symbols while
# preventing dataclasses/typing/abc machinery from becoming part of the public
# ``cgull.cfg`` API.
_IMPLEMENTATION_EXPORTS = {
    "ABC",
    "abstractmethod",
    "dataclass",
    "field",
    "Enum",
    "Generic",
    "TypeVar",
    "Dict",
    "FrozenSet",
    "Iterable",
    "List",
    "Mapping",
    "Optional",
    "Sequence",
    "Set",
    "Tuple",
    "Union",
    "logging",
    "json",
    "re",
    "c_ast",
    "_IMPLEMENTATION_EXPORTS",
}

__all__ = [
    name
    for name in globals()
    if not name.startswith("__") and name not in _IMPLEMENTATION_EXPORTS
]
