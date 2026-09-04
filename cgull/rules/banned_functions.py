"""Banned-function rules.

CGULL-001 is implemented by :mod:`banned_functions_policy`; the remaining
legacy rules are re-exported unchanged from :mod:`banned_functions_legacy`.
"""

import re

from ..utils import mask_string_and_char_literals
from .banned_functions_legacy import *  # noqa: F401,F403
from .banned_functions_legacy import FormatStringRule as _LegacyFormatStringRule
from .banned_functions_policy import (
    BannedFunctionPolicy,
    BannedFunctionPolicyEntry,
    BannedFunctionsRule,
)


class FormatStringRule(_LegacyFormatStringRule):
    """Compatibility wrapper preserving the historic module patch point."""

    def _get_function_ranges(self, file_path, full_code, source_lines):
        cache_key = (file_path, full_code)
        if self._function_range_cache_key == cache_key:
            return self._function_ranges

        # Resolve this helper through the public banned_functions module so
        # existing callers/tests patching that symbol retain the same behavior
        # after the legacy implementation was split into a compatibility file.
        masked_source = "\n".join(
            mask_string_and_char_literals(line) for line in source_lines
        )
        ranges = []
        header_pattern = re.compile(
            r'\b([A-Za-z_]\w*)\s*\([^{};]*\)\s*\{', re.DOTALL
        )

        for match in header_pattern.finditer(masked_source):
            if match.group(1) in {"if", "for", "while", "switch"}:
                continue

            open_brace = match.end() - 1
            depth = 0
            end_brace = None
            for index in range(open_brace, len(masked_source)):
                token = masked_source[index]
                if token == '{':
                    depth += 1
                elif token == '}':
                    depth -= 1
                    if depth == 0:
                        end_brace = index
                        break

            if end_brace is not None:
                ranges.append((
                    masked_source.count("\n", 0, open_brace) + 1,
                    masked_source.count("\n", 0, end_brace) + 1,
                ))

        self._function_range_cache_key = cache_key
        self._function_ranges = ranges
        return ranges
