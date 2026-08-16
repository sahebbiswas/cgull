"""
.cgullignore file handler for C-GULL Static Analyzer.
Implements gitignore-compatible path matching for recursive scanning.
"""

import os
import re
import fnmatch
from pathlib import Path
from typing import List, Tuple, Optional


class CGullIgnoreFilter:
    """
    Parses and evaluates .cgullignore patterns to exclude files and directories
    from security scanning.
    """

    def __init__(self, base_dir: Optional[str] = None, custom_patterns: Optional[List[str]] = None):
        self.base_dir = os.path.abspath(base_dir) if base_dir else os.getcwd()
        self.rules: List[Tuple[bool, str, bool, bool]] = []  # (is_negation, regex_pattern, directory_only, anchored_to_root)
        self.raw_patterns: List[str] = []

        # Default standard ignore patterns
        default_ignores = [
            ".git/",
            ".svn/",
            ".hg/",
            "node_modules/",
            "build/",
            "dist/",
            ".cache/",
            "*.o",
            "*.obj",
            "*.so",
            "*.dylib",
            "*.dll",
            "*.a",
            "*.exe",
            "*.pyc",
            "__pycache__/",
        ]
        for pat in default_ignores:
            self._add_pattern(pat)

        if custom_patterns:
            for pat in custom_patterns:
                self._add_pattern(pat)

        # Look for .cgullignore in base_dir
        ignore_file_path = os.path.join(self.base_dir, ".cgullignore")
        if os.path.isfile(ignore_file_path):
            self.load_from_file(ignore_file_path)

    def load_from_file(self, file_path: str) -> None:
        """Reads patterns from a .cgullignore file."""
        if not os.path.exists(file_path):
            return
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                self._add_pattern(line)

    def load_from_text(self, text: str) -> None:
        """Parses patterns from raw string content (e.g. from UI)."""
        for line in text.splitlines():
            self._add_pattern(line)

    def _add_pattern(self, pattern: str) -> None:
        raw = pattern.strip()
        if not raw or raw.startswith("#"):
            return

        self.raw_patterns.append(raw)
        is_negation = False
        if raw.startswith("!"):
            is_negation = True
            raw = raw[1:].strip()

        directory_only = raw.endswith("/")
        if directory_only:
            raw = raw[:-1]

        anchored_to_root = raw.startswith("/") or "/" in raw.rstrip("/")
        # Convert glob to regex
        regex = self._glob_to_regex(raw, anchored_to_root=anchored_to_root)
        self.rules.append((is_negation, regex, directory_only, anchored_to_root))

    def _glob_to_regex(self, glob_pat: str, anchored_to_root: bool = False) -> str:
        """Converts glob pattern to regex string."""
        # Handle leading slash (relative to root)
        if glob_pat.startswith("/"):
            anchored_to_root = True
            glob_pat = glob_pat[1:]

        # Escape special regex characters except * and ?
        parts = []
        i = 0
        n = len(glob_pat)
        while i < n:
            c = glob_pat[i]
            if c == "*":
                if i + 1 < n and glob_pat[i + 1] == "*":
                    # Double star **
                    if i + 2 < n and glob_pat[i + 2] == "/":
                        parts.append("(?:.+/)?")
                        i += 3
                        continue
                    else:
                        parts.append(".*")
                        i += 2
                        continue
                else:
                    parts.append("[^/]*")
                    i += 1
                    continue
            elif c == "?":
                parts.append("[^/]")
                i += 1
                continue
            elif c in ".^$[]()+{}|\\":
                parts.append("\\" + c)
                i += 1
            else:
                parts.append(c)
                i += 1

        pattern = "".join(parts)

        if anchored_to_root:
            return f"^{pattern}(?:/.*)?$"
        else:
            return f"(?:^|/){pattern}(?:/.*)?$"

    def should_ignore(self, path: str, is_dir: bool = False) -> bool:
        """
        Determines whether the given file or directory path should be ignored.
        """
        # Normalize relative path from base_dir
        abs_path = os.path.abspath(path)
        try:
            rel_path = os.path.relpath(abs_path, self.base_dir).replace("\\", "/")
        except ValueError:
            rel_path = abs_path.replace("\\", "/")

        if rel_path == "." or rel_path == "":
            return False

        ignored = False
        for is_negation, regex, dir_only, anchored in self.rules:
            if dir_only and not is_dir:
                # Directory-only rule (e.g. "build/") must not match a
                # plain file entry unless it's a descendant of a matched
                # directory -- the regex itself (`(?:/.*)?$`) already
                # allows matching files *underneath* a matched directory,
                # so we only need to skip the case where the rule would
                # otherwise match the file/dir name itself.
                base_regex = regex[:-len("(?:/.*)?$")] + "$" if regex.endswith("(?:/.*)?$") else regex
                if re.search(base_regex, rel_path) or re.search(base_regex, os.path.basename(rel_path)):
                    continue
            # Patterns containing a "/" (anchored to base_dir, per standard
            # .gitignore semantics) must only be checked against the full
            # relative path -- NOT against the bare basename, or a rule
            # like "/config.c" (root only) would incorrectly also match
            # "src/config.c" via its basename "config.c" alone.
            if re.search(regex, rel_path) or (not anchored and re.search(regex, os.path.basename(rel_path))):
                ignored = not is_negation

        return ignored

    def filter_paths(self, paths: List[str]) -> List[str]:
        """Returns only paths that are NOT ignored."""
        return [p for p in paths if not self.should_ignore(p, os.path.isdir(p))]
