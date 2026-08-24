"""
Include path resolution for C-GULL Static Analyzer.
Handles #include "..." (quote form) and #include <...> (angle form) target resolution
against local source directories, -I include roots, and .cgullincludes configuration.
"""

import os
from typing import List, Optional


class IncludeResolver:
    """
    Resolves C header target paths to absolute file paths based on include roots
    and quote vs angle include mechanics.
    """

    def __init__(
        self,
        include_roots: Optional[List[str]] = None,
        base_dir: Optional[str] = None,
        load_cgullincludes: bool = True,
    ):
        self.base_dir = os.path.abspath(base_dir) if base_dir else os.getcwd()
        self.include_roots: List[str] = []

        if include_roots:
            for root in include_roots:
                self.add_include_root(root)

        if load_cgullincludes:
            cgullinc_path = os.path.join(self.base_dir, ".cgullincludes")
            if os.path.isfile(cgullinc_path):
                self.load_from_file(cgullinc_path)

    def add_include_root(self, root: str, relative_to: Optional[str] = None) -> None:
        """Adds an include root directory."""
        raw = root.strip()
        if not raw:
            return

        if os.path.isabs(raw):
            abs_root = os.path.abspath(raw)
        else:
            rel_base = relative_to if relative_to else self.base_dir
            abs_root = os.path.abspath(os.path.join(rel_base, raw))

        if abs_root not in self.include_roots:
            self.include_roots.append(abs_root)

    def load_from_file(self, file_path: str) -> None:
        """Loads include root paths from a .cgullincludes file."""
        if not os.path.isfile(file_path):
            return
        file_dir = os.path.dirname(os.path.abspath(file_path))
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                self.add_include_root(raw, relative_to=file_dir)

    def load_from_text(self, text: str, base_dir: Optional[str] = None) -> None:
        """Parses include root paths from raw string content."""
        rel_base = base_dir if base_dir else self.base_dir
        for line in text.splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            self.add_include_root(raw, relative_to=rel_base)

    def resolve(
        self,
        header_path: str,
        source_dir: str,
        is_quote: Optional[bool] = None,
        is_angle: Optional[bool] = None,
    ) -> Optional[str]:
        """
        Resolves a header target path to an absolute path.

        - Quote form (#include "..."): searches source_dir first, then include_roots in order.
        - Angle form (#include <...>): searches include_roots only in order.
        - Returns absolute path if found and is a file, or None if unresolved (system headers, missing headers).
        """
        raw_header = header_path.strip()
        if not raw_header:
            return None

        # Determine quote vs angle form
        if is_quote is None and is_angle is None:
            if raw_header.startswith("<") and raw_header.endswith(">"):
                is_quote = False
            else:
                is_quote = True
        elif is_quote is None:
            is_quote = not bool(is_angle)

        clean_header = raw_header.lstrip('"<').rstrip('">').strip()
        if not clean_header:
            return None

        # Handle file vs directory input for source_dir
        abs_source = os.path.abspath(source_dir)
        if os.path.isfile(abs_source) or os.path.splitext(abs_source)[1].lower() in {
            ".c",
            ".h",
            ".hpp",
            ".cpp",
            ".cc",
            ".cxx",
        }:
            abs_source_dir = os.path.dirname(abs_source)
        else:
            abs_source_dir = abs_source

        # Handle absolute header path
        if os.path.isabs(clean_header):
            return os.path.abspath(clean_header) if os.path.isfile(clean_header) else None

        # 1. Quote form: search local source directory first
        if is_quote:
            candidate = os.path.abspath(os.path.join(abs_source_dir, clean_header))
            if os.path.isfile(candidate):
                return candidate

        # 2. Search include roots in order
        for root in self.include_roots:
            candidate = os.path.abspath(os.path.join(root, clean_header))
            if os.path.isfile(candidate):
                return candidate

        # 3. Unresolved (system header or missing header)
        return None
