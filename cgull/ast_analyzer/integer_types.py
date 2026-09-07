"""Shared integer type-width helpers for conversion analysis."""

import re
from typing import Optional

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
    type_name = re.sub(r"\[[^\]]*\]", "", type_str).strip()
    if "*" in type_name:
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
