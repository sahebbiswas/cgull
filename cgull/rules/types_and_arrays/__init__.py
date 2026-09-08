"""
Types and arrays rules for C-GULL Static Analyzer.
"""

from .variable_length_arrays import VariableLengthArraysRule
from .incorrect_pointer_scaling import IncorrectPointerScalingRule
from .sizeof_on_pointer import SizeofOnPointerRule
from .array_index_constant_bounds import ArrayIndexOutOfBoundsRule
from .arithmetic_integer_overflow import ArithmeticIntegerOverflowRule
from .bitwise_operations_on_signed_integers import BitwiseOperationsOnSignedIntegersRule
from .use_of_magic_numbers import UseOfMagicNumbersRule
from .signed_unsigned_comparison import SignedUnsignedComparisonRule
from .division_by_zero import DivisionByZeroRule
from .pointer_subtraction_size import PointerSubtractionSizeRule
from .integer_narrowing_cast import IntegerNarrowingCastRule
from .pointer_range_bounds import PointerRangeBoundsRule
from .validated_pointer_range import ValidatedPointerRangeRule

from .pointer_endpoint_wraparound import PointerEndpointWraparoundRule

__all__ = [
    "PointerEndpointWraparoundRule",
    "VariableLengthArraysRule",
    "IncorrectPointerScalingRule",
    "SizeofOnPointerRule",
    "ArrayIndexOutOfBoundsRule",
    "ArithmeticIntegerOverflowRule",
    "BitwiseOperationsOnSignedIntegersRule",
    "UseOfMagicNumbersRule",
    "SignedUnsignedComparisonRule",
    "DivisionByZeroRule",
    "PointerSubtractionSizeRule",
    "IntegerNarrowingCastRule",
    "PointerRangeBoundsRule",
    "ValidatedPointerRangeRule",
]
