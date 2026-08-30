"""
Include path resolution and Translation Unit (TU) expansion for C-GULL Static Analyzer.
Handles #include "..." (quote form) and #include <...> (angle form) target resolution
against local source directories, -I include roots, and .cgullincludes configuration,
as well as recursive depth-first include expansion with guard/cycle detection,
provenance line mapping, preprocessor conditional tracking, and scan boundary containment.
"""

import os
import re
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict, Tuple, Any, Union

logger = logging.getLogger(__name__)


@dataclass
class CachedHeaderExpansion:
    """
    Cached expanded representation of a C header file for reuse across translation units.
    """
    output_tuples: List[Tuple[str, "SourceLocation"]]
    included_files: Set[str]
    has_pragma_once: bool
    header_guard: Optional[str]
    byte_size: int


class HeaderCache:
    """
    In-process cache for expanded headers and parsed representations in TU mode.
    Keyed on resolved file path, SHA256 content hash, preprocessor macros, and resolver context.
    Invalidates automatically on content change (hash mismatch).
    """

    def __init__(self):
        self._expansion_cache: Dict[Tuple[str, str, Tuple[Tuple[str, int], ...], Tuple[Any, ...]], CachedHeaderExpansion] = {}
        self._ast_cache: Dict[Tuple[str, str], Any] = {}

    def clear(self) -> None:
        self._expansion_cache.clear()
        self._ast_cache.clear()

    def get_expansion(
        self,
        file_path: str,
        content_hash: str,
        macros_key: Tuple[Tuple[str, int], ...],
        resolver_key: Tuple[Any, ...] = (),
    ) -> Optional[CachedHeaderExpansion]:
        return self._expansion_cache.get((file_path, content_hash, macros_key, resolver_key))

    def set_expansion(
        self,
        file_path: str,
        content_hash: str,
        macros_key: Tuple[Tuple[str, int], ...],
        cached: CachedHeaderExpansion,
        resolver_key: Tuple[Any, ...] = (),
    ) -> None:
        self._expansion_cache[(file_path, content_hash, macros_key, resolver_key)] = cached

    def get_ast(self, file_path: str, content_hash: str) -> Optional[Any]:
        return self._ast_cache.get((file_path, content_hash))

    def set_ast(self, file_path: str, content_hash: str, value: Any) -> None:
        self._ast_cache[(file_path, content_hash)] = value


HEADER_CACHE = HeaderCache()


@dataclass
class SourceLocation:
    """
    Tracks original file path, original 1-based line number, and original line text for a line in an expanded TU.
    """
    file_path: str
    line_number: int
    line_content: str


class ExpandedTU(str):
    """
    Result of Translation Unit (TU) expansion containing expanded source text,
    a line-by-line provenance mapping back to original source locations,
    and a set of all included file paths expanded into the TU.
    Subclasses str so it can be passed directly as a string or inspected for line_map/expanded_text/included_files.
    """
    line_map: Dict[int, SourceLocation]
    included_files: Set[str]

    def __new__(cls, expanded_text: str, line_map: Optional[Dict[int, SourceLocation]] = None, included_files: Optional[Set[str]] = None):
        obj = super().__new__(cls, expanded_text)
        obj.line_map = line_map or {}
        obj.included_files = included_files or set()
        return obj

    @property
    def expanded_text(self) -> str:
        return str(self)


def _is_path_contained(candidate_path: str, trusted_roots: List[str]) -> bool:
    """
    Checks if realpath(candidate_path) is contained within at least one realpath trusted root.
    Prevents path traversal, symlink escapes, and un-trusted absolute path accesses.
    """
    try:
        real_cand = os.path.realpath(candidate_path)
        for root in trusted_roots:
            real_root = os.path.realpath(root)
            if os.path.commonpath([real_root, real_cand]) == real_root:
                return True
    except Exception:
        pass
    return False


class IncludeResolver:
    """
    Resolves C header target paths to absolute file paths based on include roots
    and quote vs angle include mechanics, with boundary containment checks.
    """

    def __init__(
        self,
        include_roots: Optional[List[str]] = None,
        base_dir: Optional[str] = None,
        load_cgullincludes: bool = True,
        allow_external_includes: bool = False,
    ):
        self.base_dir = os.path.realpath(base_dir) if base_dir else os.path.realpath(os.getcwd())
        self.include_roots: List[str] = []
        self.allow_external_includes = allow_external_includes

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
            abs_root = os.path.realpath(raw)
        else:
            rel_base = relative_to if relative_to else self.base_dir
            abs_root = os.path.realpath(os.path.join(rel_base, raw))

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

    def get_trusted_roots(self, source_dir: Optional[str] = None) -> List[str]:
        """
        Returns all trusted roots (base_dir, source_dir, and include_roots).
        """
        roots = [self.base_dir]
        if source_dir:
            abs_source = os.path.realpath(source_dir)
            if os.path.isfile(abs_source):
                abs_source = os.path.dirname(abs_source)
            if abs_source not in roots:
                roots.append(abs_source)
        for r in self.include_roots:
            if r not in roots:
                roots.append(r)
        return roots

    def get_resolution_key(self) -> Tuple[Tuple[str, ...], str, bool]:
        """Returns a hashable tuple identifying the include resolution context."""
        return (tuple(self.include_roots), self.base_dir, self.allow_external_includes)

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
        - Enforces containment within trusted roots unless allow_external_includes is True.
        - Returns real absolute path if found and is a file, or None if unresolved/rejected.
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
        abs_source = os.path.realpath(source_dir)
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

        trusted_roots = self.get_trusted_roots(source_dir=abs_source_dir)

        # Handle absolute header path
        if os.path.isabs(clean_header):
            cand = os.path.realpath(clean_header)
            if os.path.isfile(cand):
                if self.allow_external_includes or _is_path_contained(cand, trusted_roots):
                    return cand
            return None

        # 1. Quote form: search local source directory first
        if is_quote:
            candidate = os.path.realpath(os.path.join(abs_source_dir, clean_header))
            if os.path.isfile(candidate):
                if self.allow_external_includes or _is_path_contained(candidate, trusted_roots):
                    return candidate

        # 2. Search include roots in order
        for root in self.include_roots:
            candidate = os.path.realpath(os.path.join(root, clean_header))
            if os.path.isfile(candidate):
                if self.allow_external_includes or _is_path_contained(candidate, trusted_roots):
                    return candidate

        # 3. Unresolved (system header, missing header, or rejected outside boundary)
        return None


def _has_pragma_once(content: str) -> bool:
    """Returns True if the content contains a #pragma once directive."""
    return bool(re.search(r'^[ \t]*#[ \t]*pragma[ \t]+once\b', content, re.MULTILINE | re.IGNORECASE))


def _detect_header_guard(content: str) -> Optional[str]:
    """
    Detects classic whole-file header guard pattern (#ifndef GUARD ... #define GUARD ... #endif)
    and returns the guard macro symbol if found. Returns None if the guard is partial or
    does not wrap the entire file.
    """
    from .utils import strip_comments_keep_lines
    _, clean_code = strip_comments_keep_lines(content)
    lines = [ln.strip() for ln in clean_code.splitlines() if ln.strip()]
    if len(lines) < 3:
        return None

    # First non-comment directive must be #ifndef GUARD or #if !defined(GUARD)
    first = lines[0]
    m1 = re.match(r'^#[ \t]*(?:ifndef[ \t]+([a-zA-Z_]\w*)|if[ \t]+!defined\s*(?:\(\s*([a-zA-Z_]\w*)\s*\)|[ \t]+([a-zA-Z_]\w*)))', first)
    if not m1:
        return None
    guard_sym = m1.group(1) or m1.group(2) or m1.group(3)
    if not guard_sym:
        return None

    # Second non-comment directive must be #define GUARD
    second = lines[1]
    m2 = re.match(r'^#[ \t]*define[ \t]+([a-zA-Z_]\w*)(?:\s|$)', second)
    if not m2 or m2.group(1) != guard_sym:
        return None

    # Last non-comment directive must be #endif
    last = lines[-1]
    if not re.match(r'^#[ \t]*endif\b', last):
        return None

    # Verify that the guard wraps the whole file (conditional depth >= 1 for all lines between first and last)
    depth = 0
    for idx, line in enumerate(lines):
        if line.startswith('#'):
            body = line.lstrip('#').strip()
            if re.match(r'^(?:if|ifdef|ifndef)\b', body):
                depth += 1
            elif re.match(r'^(?:elif|else)\b', body):
                if depth == 1:
                    return None
            elif re.match(r'^endif\b', body):
                depth -= 1
                if depth == 0 and idx != len(lines) - 1:
                    # Outer guard closed prematurely before end of file
                    return None
        elif depth == 0:
            # Code found outside the guard
            return None

    if depth == 0:
        return guard_sym
    return None


@dataclass
class _CondFrame:
    has_taken: bool
    is_taken: bool
    parent_active: bool


class TUIncludeExpander:
    """
    Recursively expands #include directives depth-first to build a single combined
    Translation Unit (TU) source string with exact line-by-line provenance mapping,
    preprocessor conditional tracking, whole-file guard detection, and size budget enforcement.
    """

    def __init__(
        self,
        resolver: Optional[IncludeResolver] = None,
        max_depth: int = 50,
        max_total_bytes: int = 10_000_000,
        defined_syms: Optional[Any] = None,
    ):
        self.resolver = resolver or IncludeResolver()
        self.max_depth = max_depth
        self.max_total_bytes = max_total_bytes
        self.defined_syms = defined_syms
        self.rejected_paths: Set[str] = set()

    def expand(
        self,
        source_code: str,
        source_path: str = "source.c",
    ) -> ExpandedTU:
        abs_source_path = os.path.realpath(source_path) if source_path and (os.path.isabs(source_path) or os.path.isfile(source_path)) else source_path

        seen_guards: Set[str] = set()
        guarded_files: Set[str] = set()
        active_stack: List[str] = [abs_source_path]
        state = {"total_bytes": len(source_code.encode("utf-8", errors="replace"))}

        if _has_pragma_once(source_code):
            guarded_files.add(abs_source_path)
        guard_sym = _detect_header_guard(source_code)
        if guard_sym:
            seen_guards.add(guard_sym)
            guarded_files.add(abs_source_path)

        output_tuples: List[Tuple[str, SourceLocation]] = []
        included_files: Set[str] = set()
        from .ast_analyzer import _normalize_macro_dict
        macros = _normalize_macro_dict(self.defined_syms)

        self._expand_text(
            source_code,
            abs_source_path,
            active_stack,
            seen_guards,
            guarded_files,
            state,
            output_tuples,
            macros,
            included_files,
        )

        expanded_text_lines = [t[0] for t in output_tuples]
        expanded_text = "\n".join(expanded_text_lines)
        if source_code.endswith("\n") and not expanded_text.endswith("\n"):
            expanded_text += "\n"

        line_map: Dict[int, SourceLocation] = {}
        for idx, (_, src_loc) in enumerate(output_tuples, 1):
            line_map[idx] = src_loc

        return ExpandedTU(expanded_text=expanded_text, line_map=line_map, included_files=included_files)

    def _expand_text(
        self,
        code: str,
        current_file_path: str,
        active_stack: List[str],
        seen_guards: Set[str],
        guarded_files: Set[str],
        state: Dict[str, int],
        output_tuples: List[Tuple[str, SourceLocation]],
        macros: Dict[str, int],
        included_files: Set[str],
    ) -> None:
        from .ast_analyzer import eval_preprocessor_expr

        current_dir = os.path.dirname(current_file_path) if os.path.isabs(current_file_path) else os.getcwd()
        lines = code.splitlines()

        include_regex = re.compile(r'^[ \t]*#[ \t]*include[ \t]+(?:"([^"]+)"|<([^>]+)>|([^\r\n]+))')
        cond_stack: List[_CondFrame] = []

        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            orig_line_no = i + 1
            src_loc = SourceLocation(file_path=current_file_path, line_number=orig_line_no, line_content=line)

            line_lstrip = line.lstrip()

            # Handle multi-line directive continuations
            if line.rstrip().endswith('\\') and line_lstrip.startswith('#'):
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

            parent_act = True if not cond_stack else (cond_stack[-1].parent_active and cond_stack[-1].is_taken)

            # Preprocessor conditional directives tracking
            if line_lstrip.startswith('#'):
                dir_body = full_line.lstrip('#').strip()
                m_ifdef = re.match(r'^ifdef\s+([a-zA-Z_]\w*)', dir_body)
                m_ifndef = re.match(r'^ifndef\s+([a-zA-Z_]\w*)', dir_body)
                m_if = re.match(r'^if\b\s*(.*)', dir_body)
                m_elif = re.match(r'^elif\b\s*(.*)', dir_body)
                m_else = re.match(r'^else\b', dir_body)
                m_endif = re.match(r'^endif\b', dir_body)

                if m_ifdef:
                    sym_name = m_ifdef.group(1)
                    val = eval_preprocessor_expr(f"defined({sym_name})", macros) if parent_act else False
                    cond_stack.append(_CondFrame(has_taken=val, is_taken=val, parent_active=parent_act))
                    output_tuples.append((full_line, src_loc))
                    continue
                elif m_ifndef:
                    sym_name = m_ifndef.group(1)
                    val = eval_preprocessor_expr(f"!defined({sym_name})", macros) if parent_act else False
                    cond_stack.append(_CondFrame(has_taken=val, is_taken=val, parent_active=parent_act))
                    output_tuples.append((full_line, src_loc))
                    continue
                elif m_if:
                    expr_str = m_if.group(1)
                    val = eval_preprocessor_expr(expr_str, macros) if parent_act else False
                    cond_stack.append(_CondFrame(has_taken=val, is_taken=val, parent_active=parent_act))
                    output_tuples.append((full_line, src_loc))
                    continue
                elif m_elif:
                    expr_str = m_elif.group(1)
                    if cond_stack:
                        top = cond_stack[-1]
                        if top.has_taken:
                            top.is_taken = False
                        else:
                            val = eval_preprocessor_expr(expr_str, macros) if top.parent_active else False
                            top.is_taken = val
                            if val:
                                top.has_taken = True
                    output_tuples.append((full_line, src_loc))
                    continue
                elif m_else:
                    if cond_stack:
                        top = cond_stack[-1]
                        if top.has_taken:
                            top.is_taken = False
                        else:
                            top.is_taken = top.parent_active
                            top.has_taken = True
                    output_tuples.append((full_line, src_loc))
                    continue
                elif m_endif:
                    if cond_stack:
                        cond_stack.pop()
                    output_tuples.append((full_line, src_loc))
                    continue

            # If inside an inactive branch, do NOT process include directives or mutate state!
            if not parent_act:
                output_tuples.append((full_line, src_loc))
                continue

            m = include_regex.match(full_line)
            if not m:
                output_tuples.append((full_line, src_loc))
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
                output_tuples.append((full_line, src_loc))
                continue

            resolved = self.resolver.resolve(header_path, current_dir, is_quote=is_quote)
            if not resolved or not os.path.isfile(resolved):
                output_tuples.append((full_line, src_loc))
                continue

            abs_resolved = os.path.realpath(resolved)
            included_files.add(abs_resolved)

            if abs_resolved in self.rejected_paths:
                output_tuples.append((full_line, src_loc))
                continue

            # 1. Circular include check
            if abs_resolved in active_stack:
                stack_str = " -> ".join(active_stack)
                logger.warning(
                    "Circular include detected: %s -> %s. Breaking cycle.",
                    stack_str,
                    abs_resolved,
                )
                output_tuples.append(("", src_loc))
                continue

            # 2. Guard / #pragma once check
            if abs_resolved in guarded_files:
                output_tuples.append(("", src_loc))
                continue

            # Bounded size check before reading
            remaining_budget = self.max_total_bytes - state["total_bytes"]
            if remaining_budget <= 0:
                logger.warning("Max total expanded include size (%d bytes) exceeded. Skipping %s.", self.max_total_bytes, abs_resolved)
                self.rejected_paths.add(abs_resolved)
                output_tuples.append((full_line, src_loc))
                continue

            try:
                file_sz = os.path.getsize(abs_resolved)
                if file_sz > remaining_budget:
                    logger.warning("File %s (%d bytes) exceeds remaining expansion budget (%d bytes). Skipping.", abs_resolved, file_sz, remaining_budget)
                    self.rejected_paths.add(abs_resolved)
                    output_tuples.append((full_line, src_loc))
                    continue
            except Exception:
                pass

            # Bounded streamed read
            try:
                with open(abs_resolved, "r", encoding="utf-8", errors="replace") as f:
                    child_content = f.read(remaining_budget + 1)
                if len(child_content.encode("utf-8", errors="replace")) > remaining_budget:
                    logger.warning("File %s exceeded remaining byte budget when read. Skipping.", abs_resolved)
                    self.rejected_paths.add(abs_resolved)
                    output_tuples.append((full_line, src_loc))
                    continue
            except Exception as e:
                logger.warning("Failed to read included file '%s': %s", abs_resolved, e)
                output_tuples.append((full_line, src_loc))
                continue

            content_bytes = child_content.encode("utf-8", errors="replace")
            content_hash = hashlib.sha256(content_bytes).hexdigest()
            macros_key = tuple(sorted(macros.items())) if macros else ()
            resolver_key = (
                self.resolver.get_resolution_key()
                if hasattr(self.resolver, "get_resolution_key")
                else (tuple(self.resolver.include_roots), self.resolver.base_dir, self.resolver.allow_external_includes)
            )

            cached = HEADER_CACHE.get_expansion(abs_resolved, content_hash, macros_key, resolver_key)
            if cached is not None:
                if cached.has_pragma_once:
                    if abs_resolved in guarded_files:
                        output_tuples.append(("", src_loc))
                        continue

                if cached.header_guard:
                    if cached.header_guard in seen_guards:
                        guarded_files.add(abs_resolved)
                        output_tuples.append(("", src_loc))
                        continue
                    else:
                        seen_guards.add(cached.header_guard)
                        guarded_files.add(abs_resolved)

                if cached.has_pragma_once:
                    guarded_files.add(abs_resolved)

                # Depth check
                if len(active_stack) >= self.max_depth:
                    logger.warning(
                        "Max include depth (%d) exceeded at %s. Stopping expansion.",
                        self.max_depth,
                        abs_resolved,
                    )
                    output_tuples.append((full_line, src_loc))
                    continue

                # Byte budget check & accounting
                remaining_budget = self.max_total_bytes - state["total_bytes"]
                if cached.byte_size > remaining_budget:
                    logger.warning(
                        "File %s (%d bytes) exceeds remaining expansion budget (%d bytes). Skipping.",
                        abs_resolved,
                        cached.byte_size,
                        remaining_budget,
                    )
                    self.rejected_paths.add(abs_resolved)
                    output_tuples.append((full_line, src_loc))
                    continue

                state["total_bytes"] += cached.byte_size
                included_files.update(cached.included_files)
                output_tuples.extend(cached.output_tuples)
                continue

            has_p_once = _has_pragma_once(child_content)
            h_guard = _detect_header_guard(child_content)

            if has_p_once:
                if abs_resolved in guarded_files:
                    output_tuples.append(("", src_loc))
                    continue

            if h_guard:
                if h_guard in seen_guards:
                    guarded_files.add(abs_resolved)
                    output_tuples.append(("", src_loc))
                    continue
                else:
                    seen_guards.add(h_guard)
                    guarded_files.add(abs_resolved)

            if has_p_once:
                guarded_files.add(abs_resolved)

            # 3. Depth check
            if len(active_stack) >= self.max_depth:
                logger.warning(
                    "Max include depth (%d) exceeded at %s. Stopping expansion.",
                    self.max_depth,
                    abs_resolved,
                )
                output_tuples.append((full_line, src_loc))
                continue

            state["total_bytes"] += len(child_content.encode("utf-8", errors="replace"))

            active_stack.append(abs_resolved)
            child_output_tuples: List[Tuple[str, SourceLocation]] = []
            child_included_files: Set[str] = {abs_resolved}

            self._expand_text(
                child_content,
                abs_resolved,
                active_stack,
                seen_guards,
                guarded_files,
                state,
                child_output_tuples,
                macros,
                child_included_files,
            )
            active_stack.pop()

            if child_included_files == {abs_resolved}:
                cached_entry = CachedHeaderExpansion(
                    output_tuples=child_output_tuples,
                    included_files=set(child_included_files),
                    has_pragma_once=has_p_once,
                    header_guard=h_guard,
                    byte_size=len(content_bytes),
                )
                HEADER_CACHE.set_expansion(abs_resolved, content_hash, macros_key, cached_entry, resolver_key)

            included_files.update(child_included_files)
            output_tuples.extend(child_output_tuples)


def expand_includes(
    source_code: str,
    source_path: str = "source.c",
    include_roots: Optional[List[str]] = None,
    resolver: Optional[IncludeResolver] = None,
    max_depth: int = 50,
    max_total_bytes: int = 10_000_000,
    defined_syms: Optional[Any] = None,
) -> ExpandedTU:
    """
    Convenience function to expand #include directives in C source code into an ExpandedTU.
    """
    if resolver is None:
        resolver = IncludeResolver(include_roots=include_roots)
    expander = TUIncludeExpander(
        resolver=resolver,
        max_depth=max_depth,
        max_total_bytes=max_total_bytes,
        defined_syms=defined_syms,
    )
    return expander.expand(source_code, source_path=source_path)
