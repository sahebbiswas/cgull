"""Banned-function rules.

CGULL-001 is implemented by :mod:`banned_functions_policy`; the remaining
legacy rules are re-exported unchanged from :mod:`banned_functions_legacy`.
"""

from .banned_functions_legacy import *  # noqa: F401,F403
from .banned_functions_policy import (
    BannedFunctionPolicy,
    BannedFunctionPolicyEntry,
    BannedFunctionsRule,
)
