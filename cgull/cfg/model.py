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


@dataclass
class FunctionSummary:
    freed_params: Set[int] = field(default_factory=set)
    # Parameter positions which can be dereferenced before the callee has
    # established that the argument is non-NULL.  This is deliberately a
    # requirement on the caller rather than a blanket "all parameters are
    # nullable" fact: rules can combine it with an allocation result at a
    # direct call site.
    unsafe_deref_params: Set[int] = field(default_factory=set)
    return_nullness: Nullness = Nullness.UNKNOWN
    returns_allocation: bool = False
    is_unknown: bool = False


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
    successors: List[int] = field(default_factory=list)

    def get_deref_line(self, var_name: str) -> int:
        return self.deref_lines.get(var_name, self.line_number)


