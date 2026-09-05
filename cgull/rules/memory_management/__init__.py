"""
Memory management rules for C-GULL Static Analyzer.
"""

from .helpers import (
    _brace_depths,
    _source_snippet,
    _ast_cfg_for_function,
    _find_unsafe_allocation_use,
    _find_unsafe_param_deref,
    _find_uaf_uses,
    _find_memory_leak_exits,
)
from .unchecked_dynamic_allocations import UncheckedDynamicAllocationsRule
from .missing_null_check_params import MissingNullCheckOnFunctionParametersRule
from .uninitialized_pointers import UninitializedPointersRule
from .double_free import DoubleFreeRule
from .use_after_free import UseAfterFreeRule
from .uninitialized_memory_use import UninitializedMemoryUseRule
from .unsafe_sensitive_memory_clearing import UnsafeSensitiveMemoryClearingRule
from .realloc_overwrite import ReallocOverwriteRule
from .memory_leak import MemoryLeakRule
from .return_stack_variable import ReturnStackVariableRule
from .interprocedural_memcpy_bounds_precise import MemcpyStructMemberOverflowRule

__all__ = [
    "_brace_depths",
    "_source_snippet",
    "_ast_cfg_for_function",
    "_find_unsafe_allocation_use",
    "_find_unsafe_param_deref",
    "_find_uaf_uses",
    "_find_memory_leak_exits",
    "UncheckedDynamicAllocationsRule",
    "MissingNullCheckOnFunctionParametersRule",
    "UninitializedPointersRule",
    "DoubleFreeRule",
    "UseAfterFreeRule",
    "UninitializedMemoryUseRule",
    "UnsafeSensitiveMemoryClearingRule",
    "ReallocOverwriteRule",
    "MemoryLeakRule",
    "ReturnStackVariableRule",
    "MemcpyStructMemberOverflowRule",
]
