"""
Include path resolution and Translation Unit (TU) expansion for C-GULL Static Analyzer.
Handles #include "..." (quote form) and #include <...> (angle form) target resolution
against local source directories, -I include roots, and .cgullincludes configuration,
as well as recursive depth-first include expansion with guard/cycle detection.
"""

import os
import re
import logging
from typing import List, Optional, Set, Dict

logger = logging.getLogger(__name__)


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


def _has_pragma_once(content: str) -> bool:
    """Returns True if the content contains a #pragma once directive."""
    return bool(re.search(r'^[ \t]*#[ \t]*pragma[ \t]+once\b', content, re.MULTILINE | re.IGNORECASE))


def _detect_header_guard(content: str) -> Optional[str]:
    """
    Detects classic header guard pattern (#ifndef GUARD ... #define GUARD)
    and returns the guard macro symbol if found.
    """
    from .utils import strip_comments_keep_lines
    _, clean_code = strip_comments_keep_lines(content)
    directives = []
    for line in clean_code.splitlines():
        s = line.strip()
        if s.startswith('#'):
            directives.append(s)
            if len(directives) >= 10:
                break
    for idx, d1 in enumerate(directives[:3]):
        m1 = re.match(r'^#[ \t]*(?:ifndef[ \t]+([a-zA-Z_]\w*)|if[ \t]+!defined\s*\(\s*([a-zA-Z_]\w*)\s*\))', d1)
        if m1:
            sym1 = m1.group(1) or m1.group(2)
            for d in directives[idx + 1:]:
                m2 = re.match(r'^#[ \t]*define[ \t]+([a-zA-Z_]\w*)', d)
                if m2 and m2.group(1) == sym1:
                    return sym1
    return None


class TUIncludeExpander:
    """
    Recursively expands #include directives depth-first to build a single combined
    Translation Unit (TU) source string.
    """

    def __init__(
        self,
        resolver: Optional[IncludeResolver] = None,
        max_depth: int = 50,
        max_total_bytes: int = 10_000_000,
    ):
        self.resolver = resolver or IncludeResolver()
        self.max_depth = max_depth
        self.max_total_bytes = max_total_bytes

    def expand(
        self,
        source_code: str,
        source_path: str = "source.c",
    ) -> str:
        abs_source_path = os.path.abspath(source_path) if source_path and source_path != "source.c" else source_path

        seen_guards: Set[str] = set()
        guarded_files: Set[str] = set()
        active_stack: List[str] = [abs_source_path]
        state = {"total_bytes": len(source_code)}

        if _has_pragma_once(source_code):
            guarded_files.add(abs_source_path)
        guard_sym = _detect_header_guard(source_code)
        if guard_sym:
            seen_guards.add(guard_sym)
            guarded_files.add(abs_source_path)

        return self._expand_text(
            source_code,
            abs_source_path,
            active_stack,
            seen_guards,
            guarded_files,
            state,
        )

    def _expand_text(
        self,
        code: str,
        current_file_path: str,
        active_stack: List[str],
        seen_guards: Set[str],
        guarded_files: Set[str],
        state: Dict[str, int],
    ) -> str:
        current_dir = os.path.dirname(current_file_path) if os.path.isabs(current_file_path) else os.getcwd()
        lines = code.splitlines()
        output_lines: List[str] = []

        include_regex = re.compile(r'^[ \t]*#[ \t]*include[ \t]+(?:"([^"]+)"|<([^>]+)>|([^\r\n]+))')

        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]

            if line.rstrip().endswith('\\') and re.match(r'^[ \t]*#[ \t]*include\b', line):
                dir_parts = []
                curr_i = i
                while curr_i < n:
                    curr_line = lines[curr_i]
                    curr_rstrip = curr_line.rstrip()
                    if curr_rstrip.endswith('\\'):
                        dir_parts.append(curr_rstrip[:-1])
                        curr_i += 1
                    else:
                        dir_parts.append(curr_rstrip)
                        break
                full_line = " ".join(dir_parts)
                i = curr_i + 1
            else:
                full_line = line
                i += 1

            m = include_regex.match(full_line)
            if not m:
                output_lines.append(line if full_line == line else full_line)
                continue

            quote_target = m.group(1)
            angle_target = m.group(2)
            raw_target = m.group(3)

            if quote_target:
                header_path = quote_target
                is_quote = True
            elif angle_target:
                header_path = angle_target
                is_quote = False
            elif raw_target:
                raw_clean = raw_target.strip()
                if raw_clean.startswith('"'):
                    is_quote = True
                elif raw_clean.startswith('<'):
                    is_quote = False
                else:
                    is_quote = True
                header_path = raw_clean.lstrip('"<').rstrip('">').strip()
            else:
                output_lines.append(full_line)
                continue

            resolved = self.resolver.resolve(header_path, current_dir, is_quote=is_quote)
            if not resolved or not os.path.isfile(resolved):
                output_lines.append(full_line)
                continue

            abs_resolved = os.path.abspath(resolved)

            # 1. Circular include check
            if abs_resolved in active_stack:
                stack_str = " -> ".join(active_stack)
                logger.warning(
                    "Circular include detected: %s -> %s. Breaking cycle.",
                    stack_str,
                    abs_resolved,
                )
                output_lines.append("")
                continue

            # 2. Guard / #pragma once check
            if abs_resolved in guarded_files:
                output_lines.append("")
                continue

            # Read file content
            try:
                with open(abs_resolved, "r", encoding="utf-8", errors="replace") as f:
                    child_content = f.read()
            except Exception as e:
                logger.warning("Failed to read included file '%s': %s", abs_resolved, e)
                output_lines.append(full_line)
                continue

            has_p_once = _has_pragma_once(child_content)
            h_guard = _detect_header_guard(child_content)

            if has_p_once:
                guarded_files.add(abs_resolved)

            if h_guard:
                if h_guard in seen_guards:
                    guarded_files.add(abs_resolved)
                    output_lines.append("")
                    continue
                else:
                    seen_guards.add(h_guard)
                    guarded_files.add(abs_resolved)

            # 3. Depth check
            if len(active_stack) >= self.max_depth:
                logger.warning(
                    "Max include depth (%d) exceeded at %s. Stopping expansion.",
                    self.max_depth,
                    abs_resolved,
                )
                output_lines.append(full_line)
                continue

            # 4. Total bytes check
            if state["total_bytes"] + len(child_content) > self.max_total_bytes:
                logger.warning(
                    "Max total expanded include size (%d bytes) exceeded. Stopping expansion.",
                    self.max_total_bytes,
                )
                output_lines.append(full_line)
                continue

            state["total_bytes"] += len(child_content)

            active_stack.append(abs_resolved)
            child_expanded = self._expand_text(
                child_content,
                abs_resolved,
                active_stack,
                seen_guards,
                guarded_files,
                state,
            )
            active_stack.pop()

            output_lines.append(child_expanded)

        res = "\n".join(output_lines)
        if code.endswith("\n") and not res.endswith("\n"):
            res += "\n"
        return res


def expand_includes(
    source_code: str,
    source_path: str = "source.c",
    include_roots: Optional[List[str]] = None,
    resolver: Optional[IncludeResolver] = None,
    max_depth: int = 50,
    max_total_bytes: int = 10_000_000,
) -> str:
    """
    Convenience function to expand #include directives in C source code.
    """
    if resolver is None:
        resolver = IncludeResolver(include_roots=include_roots)
    expander = TUIncludeExpander(resolver=resolver, max_depth=max_depth, max_total_bytes=max_total_bytes)
    return expander.expand(source_code, source_path=source_path)
