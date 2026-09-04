"""Banned-function rules.

CGULL-001 is implemented by :mod:`banned_functions_policy`; the remaining
legacy rules are re-exported unchanged from :mod:`banned_functions_legacy`.
"""

from ..utils import mask_string_and_char_literals
from . import banned_functions_legacy as _legacy
from .banned_functions_legacy import *  # noqa: F401,F403
from .banned_functions_policy import (
    BannedFunctionPolicy,
    BannedFunctionPolicyEntry,
    BannedFunctionsRule,
)


def _compat_mask_string_and_char_literals(line: str) -> str:
    """Preserve the historic public monkey-patch point for the legacy rule."""
    return mask_string_and_char_literals(line)


# Keep one implementation of FormatStringRule._get_function_ranges in the
# legacy module. Its mask dependency forwards through this compatibility
# module so callers patching cgull.rules.banned_functions continue to work.
_legacy.mask_string_and_char_literals = _compat_mask_string_and_char_literals
