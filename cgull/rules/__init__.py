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
    CommandInjectionRule,
)
from .memory_management import (
    UncheckedDynamicAllocationsRule,
    MissingNullCheckOnFunctionParametersRule,
    UninitializedPointersRule,
    UseAfterFreeRule,
    DoubleFreeRule,
    UninitializedMemoryUseRule,
    UnsafeSensitiveMemoryClearingRule,
    ReallocOverwriteRule,
)
from .crypto_and_safety import (
    NonConstantTimeMemoryComparisonRule,
    StrippingVolatileQualifiersRule,
    IllegalFunctionPointerConversionsRule,
    NoInsecureRandRule,
    SinglePointOfFailureControlFlowRule,
    InsecureDataStorageRule,
    WeakCryptoPrimitivesRule,
)
from .types_and_arrays import (
    VariableLengthArraysRule,
    ArrayIndexOutOfBoundsRule,
    ArithmeticIntegerOverflowRule,
    DivisionByZeroRule,
    BitwiseOperationsOnSignedIntegersRule,
    UseOfMagicNumbersRule,
    SizeofOnPointerRule,
    SignedUnsignedComparisonRule,
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
    DivisionByZeroRule,
    ArrayIndexOutOfBoundsRule,
    SizeofOnPointerRule,
    UnsafeSensitiveMemoryClearingRule,
    StrippingVolatileQualifiersRule,
    VariableLengthArraysRule,
    IllegalFunctionPointerConversionsRule,
    UninitializedPointersRule,
    UseAfterFreeRule,
    DoubleFreeRule,
    UninitializedMemoryUseRule,
    NoInsecureRandRule,
    CommandInjectionRule,
    WeakCryptoPrimitivesRule,
    ReallocOverwriteRule,
    # Medium Impact
    UnsafeIntegerConversionsRule,
    NakedControlFlowStatementsRule,
    UseOfMagicNumbersRule,
    BitwiseOperationsOnSignedIntegersRule,
    SinglePointOfFailureControlFlowRule,
    InsecureDataStorageRule,
    SignedUnsignedComparisonRule,
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


def register_rule(rule_cls: Type[BaseRule]) -> None:
    """Registers a rule class in RULE_REGISTRY and ALL_RULES."""
    RULE_REGISTRY[rule_cls.rule_id] = rule_cls
    if rule_cls not in ALL_RULES:
        ALL_RULES.append(rule_cls)
