"""Shared integer type and expression-typing helpers for conversion analysis."""

import re
from typing import Any, Optional

from .types import CASTContext, get_type_byte_size, resolve_typedef_shape


_INTEGER_TYPE_RE = re.compile(
    r"^(?:(?:signed|unsigned)(?:\s+(?:char|short(?:\s+int)?|int|long(?:\s+int)?|long\s+long(?:\s+int)?))?|"
    r"char|short(?:\s+int)?|int|long(?:\s+int)?|long\s+long(?:\s+int)?|"
    r"u?int(?:8|16|32|64)_t|size_t|ssize_t|intptr_t|uintptr_t|ptrdiff_t|time_t)$",
    re.IGNORECASE,
)


def _resolved_scalar_type(type_str: str, ast_ctx: Optional[CASTContext] = None) -> Optional[str]:
    if not type_str:
        return None
    type_name = type_str.strip()
    if "*" in type_name or "[" in type_name or "]" in type_name:
        return None
    if ast_ctx and ast_ctx.typedef_shapes:
        clean_name = re.sub(r"\b(?:const|volatile)\b", "", type_name).strip()
        if clean_name in ast_ctx.typedef_shapes:
            shape = resolve_typedef_shape(clean_name, ast_ctx.typedef_shapes)
            if shape.is_pointer or shape.is_array:
                return None
            type_name = shape.target
    type_name = re.sub(r"\b(?:const|volatile)\b", "", type_name).strip()
    return re.sub(r"\s+", " ", type_name)


def get_integer_type_byte_size(type_str: str, ast_ctx: Optional[CASTContext] = None) -> Optional[int]:
    """Return a known integer width, excluding non-integers and unresolved types."""
    resolved = _resolved_scalar_type(type_str, ast_ctx)
    if not resolved or not _INTEGER_TYPE_RE.fullmatch(resolved):
        return None
    return get_type_byte_size(resolved, ast_ctx)


def is_integer_narrowing_conversion(
    source_type: str,
    destination_type: str,
    ast_ctx: Optional[CASTContext] = None,
) -> Optional[bool]:
    """Compare known integer widths; return None when either side is unresolved."""
    source_width = get_integer_type_byte_size(source_type, ast_ctx)
    destination_width = get_integer_type_byte_size(destination_type, ast_ctx)
    if source_width is None or destination_width is None:
        return None
    return destination_width < source_width


def _integer_rank(type_name: str, ast_ctx: CASTContext) -> Optional[int]:
    resolved = _resolved_scalar_type(type_name, ast_ctx)
    if not resolved or get_integer_type_byte_size(resolved, ast_ctx) is None:
        return None
    normalized = resolved.lower()
    normalized = normalized.replace("signed ", "").replace("unsigned ", "")
    aliases = {
        "char": 1,
        "int8_t": 1,
        "uint8_t": 1,
        "short": 2,
        "short int": 2,
        "int16_t": 2,
        "uint16_t": 2,
        "int": 3,
        "signed": 3,
        "unsigned": 3,
        "int32_t": 3,
        "uint32_t": 3,
        "long": 4,
        "long int": 4,
        "size_t": 4,
        "ssize_t": 4,
        "intptr_t": 4,
        "uintptr_t": 4,
        "ptrdiff_t": 4,
        "time_t": 4,
        "long long": 5,
        "long long int": 5,
        "int64_t": 5,
        "uint64_t": 5,
    }
    rank = aliases.get(normalized)
    if rank is not None:
        return rank
    width = get_integer_type_byte_size(type_name, ast_ctx)
    return {1: 1, 2: 2, 4: 3, 8: 4}.get(width)


def _is_unsigned_integer(type_name: str, ast_ctx: CASTContext) -> Optional[bool]:
    resolved = _resolved_scalar_type(type_name, ast_ctx)
    if not resolved or get_integer_type_byte_size(resolved, ast_ctx) is None:
        return None
    normalized = resolved.lower()
    if normalized == "char":
        return None
    if normalized.startswith("unsigned") or normalized.startswith("uint"):
        return True
    if normalized in {"size_t", "uintptr_t"}:
        return True
    return False


def _unsigned_counterpart(type_name: str, ast_ctx: CASTContext) -> Optional[str]:
    resolved = _resolved_scalar_type(type_name, ast_ctx)
    if not resolved:
        return None
    aliases = {
        "char": "unsigned char",
        "signed char": "unsigned char",
        "short": "unsigned short",
        "short int": "unsigned short",
        "signed short": "unsigned short",
        "signed short int": "unsigned short",
        "int": "unsigned int",
        "signed": "unsigned int",
        "signed int": "unsigned int",
        "long": "unsigned long",
        "long int": "unsigned long",
        "signed long": "unsigned long",
        "signed long int": "unsigned long",
        "long long": "unsigned long long",
        "long long int": "unsigned long long",
        "signed long long": "unsigned long long",
        "signed long long int": "unsigned long long",
        "int8_t": "uint8_t",
        "int16_t": "uint16_t",
        "int32_t": "uint32_t",
        "int64_t": "uint64_t",
        "ssize_t": "size_t",
        "intptr_t": "uintptr_t",
    }
    return aliases.get(resolved.lower())


def integer_promotion(type_name: str, ast_ctx: CASTContext) -> Optional[str]:
    """Apply C integer promotions to a known scalar integer type."""
    width = get_integer_type_byte_size(type_name, ast_ctx)
    int_width = get_integer_type_byte_size("int", ast_ctx)
    rank = _integer_rank(type_name, ast_ctx)
    int_rank = _integer_rank("int", ast_ctx)
    if width is None or int_width is None or rank is None or int_rank is None:
        return None
    if rank >= int_rank:
        return type_name
    unsigned = _is_unsigned_integer(type_name, ast_ctx)
    if unsigned is None:
        # Plain char signedness is implementation-defined, but either form fits
        # in int on the supported targets when char is narrower than int.
        return "int" if width < int_width else None
    if not unsigned or width < int_width:
        return "int"
    return "unsigned int"


def usual_arithmetic_type(
    left_type: str,
    right_type: str,
    ast_ctx: CASTContext,
) -> Optional[str]:
    """Return the integer result type after promotions/usual arithmetic conversions."""
    left = integer_promotion(left_type, ast_ctx)
    right = integer_promotion(right_type, ast_ctx)
    if left is None or right is None:
        return None
    left_rank = _integer_rank(left, ast_ctx)
    right_rank = _integer_rank(right, ast_ctx)
    left_unsigned = _is_unsigned_integer(left, ast_ctx)
    right_unsigned = _is_unsigned_integer(right, ast_ctx)
    if None in (left_rank, right_rank, left_unsigned, right_unsigned):
        return None
    if left_unsigned == right_unsigned:
        return left if left_rank >= right_rank else right

    unsigned_type, unsigned_rank = (left, left_rank) if left_unsigned else (right, right_rank)
    signed_type, signed_rank = (right, right_rank) if left_unsigned else (left, left_rank)
    if unsigned_rank >= signed_rank:
        return unsigned_type

    unsigned_width = get_integer_type_byte_size(unsigned_type, ast_ctx)
    signed_width = get_integer_type_byte_size(signed_type, ast_ctx)
    if unsigned_width is None or signed_width is None:
        return None
    if signed_width > unsigned_width:
        return signed_type
    return _unsigned_counterpart(signed_type, ast_ctx)


def infer_integer_expression_type(
    ast_ctx: CASTContext,
    node: Any,
    fn: Any = None,
) -> Optional[str]:
    """Infer the C integer type of an expression using promotions and conversions.

    Unsupported or non-integer expressions return ``None`` rather than guessing.
    This deliberately models only type semantics; value/range safety remains the
    responsibility of CFG-backed range analysis.
    """
    if node is None:
        return None

    kind = type(node).__name__
    if kind == "Cast":
        from .types import _format_pycparser_expr

        target = _format_pycparser_expr(node.to_type)
        return target if get_integer_type_byte_size(target, ast_ctx) is not None else None

    if kind == "Constant":
        if node.type == "char":
            return "int"
        return node.type if get_integer_type_byte_size(node.type, ast_ctx) is not None else None

    if kind == "UnaryOp" and node.op in {"+", "-", "~"}:
        operand = infer_integer_expression_type(ast_ctx, node.expr, fn)
        return integer_promotion(operand, ast_ctx) if operand else None

    if kind == "BinaryOp":
        if node.op in {"&&", "||", "==", "!=", "<", "<=", ">", ">="}:
            return "int"
        left = infer_integer_expression_type(ast_ctx, node.left, fn)
        right = infer_integer_expression_type(ast_ctx, node.right, fn)
        if not left or not right:
            return None
        if node.op in {"<<", ">>"}:
            return integer_promotion(left, ast_ctx)
        if node.op in {"+", "-", "*", "/", "%", "&", "^", "|"}:
            return usual_arithmetic_type(left, right, ast_ctx)
        return None

    if kind == "TernaryOp":
        left = infer_integer_expression_type(ast_ctx, node.iftrue, fn)
        right = infer_integer_expression_type(ast_ctx, node.iffalse, fn)
        if not left or not right:
            return None
        return usual_arithmetic_type(left, right, ast_ctx)

    inferred = ast_ctx.infer_expr_type(node, fn)
    if inferred and get_integer_type_byte_size(inferred, ast_ctx) is not None:
        return inferred
    return None
