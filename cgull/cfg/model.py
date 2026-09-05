"""CFG state model types."""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


logger = logging.getLogger(__name__)



class Nullness(Enum):
    NULL = "NULL"
    NON_NULL = "NON_NULL"
    MAYBE_NULL = "MAYBE_NULL"
    UNKNOWN = "UNKNOWN"


class Initialization(Enum):
    UNINITIALIZED = "UNINITIALIZED"
    INITIALIZED = "INITIALIZED"
    MAYBE_INITIALIZED = "MAYBE_INITIALIZED"


class Allocation(Enum):
    NOT_ALLOCATED = "NOT_ALLOCATED"
    ALLOCATED = "ALLOCATED"
    MAYBE_ALLOCATED = "MAYBE_ALLOCATED"
    FREED = "FREED"
    MAYBE_FREED = "MAYBE_FREED"


@dataclass(frozen=True)
class CFGSourceLocation:
    """Original source location for a CFG event or nested call."""

    file_path: Optional[str]
    line_number: int
    column_number: int = 0


@dataclass(frozen=True)
class CFGCall:
    """Structured call metadata attached to the containing CFG event.

    ``direct_callee`` is populated only for syntactically direct calls.  For
    function pointers and other indirect call expressions, ``callee_expression``
    retains the source spelling and ``is_indirect`` is true so later call-graph
    construction can record an unresolved edge instead of dropping the call.
    """

    direct_callee: Optional[str]
    callee_expression: str
    actual_arguments: Tuple[str, ...] = ()
    result_target: Optional[str] = None
    source_location: Optional[CFGSourceLocation] = None
    is_indirect: bool = False


@dataclass
class FunctionSummary:
    freed_params: Set[int] = field(default_factory=set)
    # Parameter positions whose incoming argument value can be dereferenced
    # before the callee establishes it is non-NULL.  This follows the
    # parameter's initial location, not a variable of the same name after an
    # assignment in the callee.
    unsafe_deref_params: Set[int] = field(default_factory=set)
    return_nullness: Nullness = Nullness.UNKNOWN
    returns_allocation: bool = False
    is_unknown: bool = False
    # Pointer parameters whose referenced caller-owned object is initialized
    # on every reachable exit vs on at least one reachable path. Appended to
    # preserve the positional constructor contract of the older fields.
    must_initialize_params: Set[int] = field(default_factory=set)
    may_initialize_params: Set[int] = field(default_factory=set)


@dataclass
class VariableFacts:
    nullness: Nullness = Nullness.UNKNOWN
    initialization: Initialization = Initialization.UNINITIALIZED
    allocation: Allocation = Allocation.NOT_ALLOCATED


@dataclass
class BasicBlock:
    block_id: int
    nodes: List["CFGEvent"] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)  # list of block_ids
    successors: List[int] = field(default_factory=list)    # list of block_ids
    edge_facts: Dict[int, Tuple[Set[str], Set[str]]] = field(default_factory=dict)  # succ block_id -> (add, remove)

    # In and Out facts at block entry and block exit
    nullness_in: Dict[str, Nullness] = field(default_factory=dict)
    nullness_out: Dict[str, Nullness] = field(default_factory=dict)

    init_in: Dict[str, Initialization] = field(default_factory=dict)
    init_out: Dict[str, Initialization] = field(default_factory=dict)

    alloc_in: Dict[str, Allocation] = field(default_factory=dict)
    alloc_out: Dict[str, Allocation] = field(default_factory=dict)

    # Alias and location lifecycle tracking facts
    loc_state_in: Dict[str, Allocation] = field(default_factory=dict)
    loc_state_out: Dict[str, Allocation] = field(default_factory=dict)
    loc_map_in: Dict[str, Set[str]] = field(default_factory=dict)
    loc_map_out: Dict[str, Set[str]] = field(default_factory=dict)


@dataclass
class CFGEvent:
    node_id: int
    kind: str
    line_number: int
    source_location: Optional[CFGSourceLocation] = None
    expr_str: str = ""
    reads: Set[str] = field(default_factory=set)
    writes: Set[str] = field(default_factory=set)
    null_writes: Set[str] = field(default_factory=set)
    maybe_null_writes: Set[str] = field(default_factory=set)
    freed: Set[str] = field(default_factory=set)
    allocated: Set[str] = field(default_factory=set)
    derefs: Set[str] = field(default_factory=set)
    deref_lines: Dict[str, int] = field(default_factory=dict)
    asserted: Set[str] = field(default_factory=set)
    alias_writes: Dict[str, str] = field(default_factory=dict)
    realloc_inputs: Set[str] = field(default_factory=set)
    realloc_bindings: Dict[str, str] = field(default_factory=dict)
    calls: Tuple[CFGCall, ...] = ()
    successors: List[int] = field(default_factory=list)

    @property
    def primary_call(self) -> Optional[CFGCall]:
        """The value-producing call, or the first call for a call statement."""
        for call in self.calls:
            if call.result_target is not None:
                return call
        return self.calls[0] if self.calls else None

    @property
    def direct_callee(self) -> Optional[str]:
        call = self.primary_call
        return call.direct_callee if call else None

    @property
    def actual_arguments(self) -> Tuple[str, ...]:
        call = self.primary_call
        return call.actual_arguments if call else ()

    @property
    def result_target(self) -> Optional[str]:
        call = self.primary_call
        return call.result_target if call else None

    def get_deref_line(self, var_name: str) -> int:
        return self.deref_lines.get(var_name, self.line_number)


