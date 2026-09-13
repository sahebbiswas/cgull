"""Installed parsing models, separate from user-owned include roots.

These declarations supply syntax and names, not target ABI layouts. Resource
lookup works in source trees and ordinary wheel/sdist installations and is
cached independently in each worker process.
"""

import os
from functools import lru_cache
from importlib.resources import files
from typing import Tuple


@lru_cache(maxsize=1)
def analysis_header_roots() -> Tuple[str, ...]:
    """Return Linux overlay then generic libc, using package resource lookup."""
    return tuple(
        os.path.realpath(os.fspath(files(package)))
        for package in (__name__, "pycparser_fake_libc")
    )


def is_analysis_header(path: str) -> bool:
    """Recognize infrastructure even when explicitly targeted or symlinked."""
    candidate = os.path.realpath(path)
    for root in analysis_header_roots():
        try:
            if os.path.commonpath((candidate, root)) == root:
                return True
        except ValueError:  # Different Windows drives.
            continue
    return False
