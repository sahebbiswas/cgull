"""
Rule registry for C-GULL Static Analyzer.
"""

from typing import List, Dict, Type
from .base import BaseRule
from .banned_functions import (
    BannedFunctionsRule,
    FormatStringRule,
    UnsafeIntegerConversionsRule,
    UncheckedSnprintfReturnRule,
)
from .memory_management import (
    UncheckedDynamicAllocationsRule,
    MissingNullCheckOnFunctionParametersRule,
    UninitializedPointersRule,
    UseAfterFreeRule,
    UninitializedMemoryUseRule,
    UnsafeSensitiveMemoryClearingRule,
)
from .crypto_and_safety import (
    NonConstantTimeMemoryComparisonRule,
    StrippingVolatileQualifiersRule,
    IllegalFunctionPointerConversionsRule,
    SinglePointOfFailureControlFlowRule,
    InsecureDataStorageRule,
)
from .types_and_arrays import (
    VariableLengthArraysRule,
    ArrayIndexOutOfBoundsRule,
    ArithmeticIntegerOverflowRule,
    BitwiseOperationsOnSignedIntegersRule,
    UseOfMagicNumbersRule,
)
from .misra_and_style import (
    NakedControlFlowStatementsRule,
    MissingDefaultCaseInSwitchStatementsRule,
    UseOfGotoStatementsRule,
    ParameterVoidRule,
    UnusedArgumentsRule,
    MissingAssertionsRule,
)

ALL_RULES: List[Type[BaseRule]] = [
    # High Impact
    BannedFunctionsRule,
    FormatStringRule,
    UncheckedSnprintfReturnRule,
    UncheckedDynamicAllocationsRule,
    MissingNullCheckOnFunctionParametersRule,
    NonConstantTimeMemoryComparisonRule,
    ArithmeticIntegerOverflowRule,
    ArrayIndexOutOfBoundsRule,
    UnsafeSensitiveMemoryClearingRule,
    StrippingVolatileQualifiersRule,
    VariableLengthArraysRule,
    IllegalFunctionPointerConversionsRule,
    UninitializedPointersRule,
    UseAfterFreeRule,
    UninitializedMemoryUseRule,
    # Medium Impact
    UnsafeIntegerConversionsRule,
    NakedControlFlowStatementsRule,
    UseOfMagicNumbersRule,
    BitwiseOperationsOnSignedIntegersRule,
    SinglePointOfFailureControlFlowRule,
    InsecureDataStorageRule,
    # Low Impact
    MissingDefaultCaseInSwitchStatementsRule,
    UseOfGotoStatementsRule,
    ParameterVoidRule,
    UnusedArgumentsRule,
    MissingAssertionsRule,
]

RULE_REGISTRY: Dict[str, Type[BaseRule]] = {
    rule_cls.rule_id: rule_cls for rule_cls in ALL_RULES
}


def get_all_rules() -> List[BaseRule]:
    """Instantiates and returns all active rules."""
    return [rule_cls() for rule_cls in ALL_RULES]


def get_rule_by_id(rule_id: str) -> BaseRule:
    """Returns rule instance by rule_id (e.g. CGULL-001)."""
    if rule_id in RULE_REGISTRY:
        return RULE_REGISTRY[rule_id]()
    raise KeyError(f"Rule ID '{rule_id}' not found.")
