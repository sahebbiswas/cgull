"""
AST and Lexical Semantic Analyzer for C code in C-GULL.
Provides both pycparser integration (if installed) and a built-in
lightweight C Abstract Syntax Tree & Semantic Flow Parser.

Design note: pycparser cannot parse raw, unpreprocessed C (it chokes on
#include, macros, and standard-library typedefs like size_t/uint32_t that
it never sees a definition for). Rather than silently degrading to
"pycparser_ast = None" for almost every real-world file -- which is what
happened before, since nothing ever consumed pycparser_ast anyway -- this
module now (a) strips preprocessor directives, (b) injects a small prelude
of the typedefs real C code relies on constantly, and (c) actually walks
the resulting AST with a NodeVisitor to extract precise function/variable
information that the regex-based extractor structurally cannot get right,
most notably multi-declarator lines like `int a, b, c;`. Where pycparser
succeeds, its findings are merged into (and take precedence over) the
regex-derived CFunction/CVariable data; where it fails (which will still
happen on complex real headers/macros), we transparently fall back to the
regex-only extraction exactly as before.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple, Union, Mapping

from ..models import ParserStatus, ParseTier, ConfigProfile
from ..utils import strip_comments_keep_lines, mask_string_and_char_literals
from .preprocessor import _eval_c_prep_tokens, _normalize_macro_dict, _parse_c_int_literal, _tokenize_c_prep_expr

logger = logging.getLogger(__name__)


@dataclass
class CollectedFlags:
    """
    Represents preprocessor macros tested in conditional directives.

    Attributes:
        presence_flags: Set of macro names tested via simple presence checks (#ifdef, #ifndef, defined(X)).
        value_flags: Set of macro names tested via value comparisons (#if X > 2, #elif X == 1).
        presence_locations: Dict mapping macro name to (file_path, line_number) of first presence check.
        value_locations: Dict mapping macro name to (file_path, line_number) of first value check.
    """
    presence_flags: Set[str] = field(default_factory=set)
    value_flags: Set[str] = field(default_factory=set)
    presence_locations: Dict[str, Tuple[str, int]] = field(default_factory=dict)
    value_locations: Dict[str, Tuple[str, int]] = field(default_factory=dict)

    @property
    def all_flags(self) -> Set[str]:
        return self.presence_flags | self.value_flags

    def to_dict(self) -> Dict[str, Any]:
        return {
            "presence_flags": sorted(self.presence_flags),
            "value_flags": sorted(self.value_flags),
            "all_flags": sorted(self.all_flags),
        }

    def generate_config_profiles(
        self,
        baseline_name: str = "baseline",
        strategy: str = "one-at-a-time",
        exhaustive_threshold: int = 10,
        base_flags: Optional[Dict[str, Any]] = None,
    ) -> List[ConfigProfile]:
        """
        Generates ConfigProfile objects according to the requested configuration expansion strategy.
        """
        return generate_config_profiles(
            self,
            baseline_name=baseline_name,
            strategy=strategy,
            exhaustive_threshold=exhaustive_threshold,
            base_flags=base_flags,
        )


class ConditionalFlagCollector:
    """
    Walks clean C source code (comment-stripped view) to discover preprocessor flags
    tested across #if, #ifdef, #ifndef, #elif, and defined(...) forms.
    """

    _DEFINED_RE = re.compile(r'\bdefined\s*\(\s*([a-zA-Z_]\w*)\s*\)|\bdefined\s+([a-zA-Z_]\w*)')
    _HAS_FEATURE_RE = re.compile(r'\b__(?:has_include|has_builtin|has_feature|has_extension|has_attribute|has_cpp_attribute)\b\s*\([^)]*\)')
    _IDENT_RE = re.compile(r'\b[a-zA-Z_]\w*\b')
    _VALUE_OP_RE = re.compile(r'==|!=|<=|>=|<|>|\+|\-|\*|/|%|<<|>>|\^|~|&(?!&)|\|(?!\|)')
    _BUILTINS = {
        'true', 'false', 'defined',
        '__has_include', '__has_builtin', '__has_feature',
        '__has_extension', '__has_attribute', '__has_cpp_attribute'
    }

    @classmethod
    def collect(cls, clean_code: str, file_path: str = "") -> CollectedFlags:
        presence_raw: Set[str] = set()
        value_raw: Set[str] = set()
        presence_locs: Dict[str, Tuple[str, int]] = {}
        value_locs: Dict[str, Tuple[str, int]] = {}

        lines = clean_code.splitlines()
        i = 0
        n = len(lines)

        while i < n:
            line = lines[i]
            line_lstrip = line.lstrip()
            line_no = i + 1

            if line_lstrip.startswith('#'):
                directive_parts = []
                curr_i = i
                while curr_i < n:
                    curr_line = lines[curr_i]
                    curr_rstrip = curr_line.rstrip()
                    if curr_rstrip.endswith('\\'):
                        directive_parts.append(curr_rstrip[:-1])
                        curr_i += 1
                    else:
                        directive_parts.append(curr_rstrip)
                        break

                full_directive_str = " ".join(directive_parts).strip()
                i = curr_i + 1

                dir_body = full_directive_str.lstrip('#').strip()

                m_ifdef = re.match(r'^ifdef\s+([a-zA-Z_]\w*)', dir_body)
                m_ifndef = re.match(r'^ifndef\s+([a-zA-Z_]\w*)', dir_body)
                m_if_elif = re.match(r'^(?:if|elif)\b\s*(.*)', dir_body)

                if m_ifdef:
                    sym = m_ifdef.group(1)
                    presence_raw.add(sym)
                    if sym not in presence_locs:
                        presence_locs[sym] = (file_path, line_no)
                elif m_ifndef:
                    sym = m_ifndef.group(1)
                    presence_raw.add(sym)
                    if sym not in presence_locs:
                        presence_locs[sym] = (file_path, line_no)
                elif m_if_elif:
                    expr = m_if_elif.group(1).strip()

                    # Strip string and character literals
                    expr = re.sub(r'"([^"\\]|\\.)*"|\'([^\'\\]|\\.)*\'', ' ', expr)

                    # Replace feature-test macros like __has_include("...") or __has_include(<...>)
                    expr = cls._HAS_FEATURE_RE.sub(" 1 ", expr)

                    # Extract defined(X) or defined X presence checks
                    for m_def in cls._DEFINED_RE.finditer(expr):
                        sym = m_def.group(1) or m_def.group(2)
                        if sym and sym not in cls._BUILTINS:
                            presence_raw.add(sym)
                            if sym not in presence_locs:
                                presence_locs[sym] = (file_path, line_no)

                    # Replace defined(...) expressions with placeholder constant ' 1 '
                    expr_no_defined = cls._DEFINED_RE.sub(" 1 ", expr)

                    # Split expression into clauses around logical operators (&&, ||)
                    clauses = re.split(r'&&|\|\|', expr_no_defined)
                    for clause in clauses:
                        has_value_op = bool(cls._VALUE_OP_RE.search(clause))
                        for m_ident in cls._IDENT_RE.finditer(clause):
                            ident = m_ident.group(0)
                            if ident not in cls._BUILTINS:
                                if has_value_op:
                                    value_raw.add(ident)
                                    if ident not in value_locs:
                                        value_locs[ident] = (file_path, line_no)
                                else:
                                    presence_raw.add(ident)
                                    if ident not in presence_locs:
                                        presence_locs[ident] = (file_path, line_no)
            else:
                i += 1

        value_flags = set(value_raw)
        presence_flags = set(presence_raw) - value_flags

        if value_flags:
            logger.info(
                "Discovered value-comparison preprocessor macro(s) (out of scope for boolean flag toggling): %s",
                ", ".join(sorted(value_flags))
            )

        return CollectedFlags(
            presence_flags=presence_flags,
            value_flags=value_flags,
            presence_locations=presence_locs,
            value_locations=value_locs,
        )

    @classmethod
    def generate_variant_configs(
        cls,
        clean_code: str,
        baseline_name: str = "baseline",
        strategy: str = "one-at-a-time",
        exhaustive_threshold: int = 10,
        base_flags: Optional[Dict[str, Any]] = None,
    ) -> List[ConfigProfile]:
        """
        Discovers preprocessor flags in clean C source code and generates ConfigProfile objects
        according to the requested configuration expansion strategy.
        """
        collected = cls.collect(clean_code)
        return collected.generate_config_profiles(
            baseline_name=baseline_name,
            strategy=strategy,
            exhaustive_threshold=exhaustive_threshold,
            base_flags=base_flags,
        )


def merge_profile_flags(profiles: List[ConfigProfile]) -> Dict[str, Optional[Union[str, int, bool]]]:
    """
    Merges macro flags across multiple ConfigProfiles in a deterministic, coverage-preserving manner.
    - Presence macros (None): if defined in any profile, kept as defined (None).
    - Undef (False): if undef in one profile and presence in another, presence wins (None) with a warning.
    - Value macros: if values conflict across profiles (e.g. RETRY_COUNT=5 vs RETRY_COUNT=10),
      the macro is dropped from the merged dict with a warning so preprocessor conditionals do not
      assume a single conflicting value.
    """
    if not profiles:
        return {}
    if len(profiles) == 1:
        return dict(profiles[0].flags)

    merged: Dict[str, Optional[Union[str, int, bool]]] = {}
    conflicts: Set[str] = set()

    for p in profiles:
        for k, v in p.flags.items():
            if k in conflicts:
                continue
            if k not in merged:
                merged[k] = v
            else:
                existing_v = merged[k]
                if existing_v == v:
                    continue
                # If one is presence (None) and the other is False (undef), presence wins
                if (existing_v is None and v is False) or (existing_v is False and v is None):
                    merged[k] = None
                    logger.warning(f"Macro presence conflict for '{k}' across profiles; keeping as defined (None).")
                else:
                    conflicts.add(k)
                    del merged[k]
                    logger.warning(
                        f"Conflicting values for macro '{k}' across profiles ({existing_v} vs {v}). "
                        f"Dropping macro '{k}' from merged seed flags."
                    )

    return merged


def parse_json_config_seed(filepath: str) -> List[ConfigProfile]:
    """
    Parses a JSON configuration seed file (.json) containing multiple named profiles:
    {"profile_name": {"MACRO": value_or_true, ...}, ...}
    into a list of ConfigProfiles.
    """
    import json
    from pathlib import Path

    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Config seed path '{filepath}' does not exist.")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(
            f"Invalid JSON config seed structure in '{filepath}': top-level JSON must be an object mapping profile names to flag objects."
        )

    profiles: List[ConfigProfile] = []
    for profile_name, flag_map in data.items():
        if not isinstance(flag_map, dict):
            raise ValueError(
                f"Invalid profile '{profile_name}' in '{filepath}': profile value must be an object mapping macro names to values."
            )

        flags: Dict[str, Optional[Union[str, int, bool]]] = {}
        for k, v in flag_map.items():
            macro_name = str(k)
            if not re.fullmatch(r"[a-zA-Z_]\w*", macro_name):
                raise ValueError(
                    f"Invalid preprocessor identifier '{macro_name}' in profile '{profile_name}' in '{filepath}'."
                )

            if v is True or v is None:
                flags[macro_name] = None
            elif v is False:
                flags[macro_name] = False
            elif isinstance(v, bool):
                pass
            elif isinstance(v, int):
                flags[macro_name] = v
            elif isinstance(v, str):
                flags[macro_name] = v
            else:
                raise ValueError(
                    f"Unsupported flag value type '{type(v).__name__}' for macro '{macro_name}' in profile '{profile_name}' in '{filepath}'. "
                    f"Flag values must be boolean, null, int, or string."
                )

        profiles.append(ConfigProfile(name=str(profile_name), flags=flags))

    return profiles


def parse_config_seed(filepath: str, name_override: Optional[str] = None) -> ConfigProfile:
    """
    Parses a header file (.h) containing #define and #undef directives into a ConfigProfile.

    Config profile name defaults to the filename stem (e.g. "config_debug.h" -> "config_debug"),
    or can be overridden via "// cgull-config-name: custom_name" on the first line or via `name_override`.

    Function-like macros (#define FOO(x) ...) are skipped with a warning logged.
    """
    from pathlib import Path

    path = Path(filepath)
    if path.suffix.lower() == ".json":
        raise ValueError(
            f"parse_config_seed() does not accept JSON seed files directly as JSON seeds can contain multiple profiles. "
            f"Use parse_json_config_seed() or parse_config_seeds() for JSON config seed files."
        )

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    config_name = name_override
    first_line = content.splitlines()[0] if content.splitlines() else ""
    m_name = re.match(r'^[ \t]*//[ \t]*cgull-config-name:[ \t]*([a-zA-Z0-9_\-]+)', first_line, re.IGNORECASE)
    if m_name and not name_override:
        config_name = m_name.group(1).strip()
    if not config_name:
        config_name = path.stem

    clean_lines, clean_code = strip_comments_keep_lines(content)

    flags: Dict[str, Optional[Union[str, int, bool]]] = {}

    lines = clean_code.splitlines()
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        line_lstrip = line.lstrip()

        if line_lstrip.startswith('#'):
            directive_parts = []
            curr_i = i
            while curr_i < n:
                curr_line = lines[curr_i]
                curr_rstrip = curr_line.rstrip()
                if curr_rstrip.endswith('\\'):
                    directive_parts.append(curr_rstrip[:-1])
                    curr_i += 1
                else:
                    directive_parts.append(curr_rstrip)
                    break

            full_directive_str = " ".join(directive_parts).strip()
            i = curr_i + 1

            dir_body = full_directive_str.lstrip('#').strip()

            m_fn_macro = re.match(r'^define\s+([a-zA-Z_]\w*)\(', dir_body)
            if m_fn_macro:
                macro_name = m_fn_macro.group(1)
                logger.warning(f"Skipping function-like macro '{macro_name}' in seed file {filepath}")
                continue

            m_define = re.match(r'^define\s+([a-zA-Z_]\w*)(?:\([^)]*\))?(?:\s+(.*))?$', dir_body)
            m_undef = re.match(r'^undef\s+([a-zA-Z_]\w*)', dir_body)

            if m_define:
                m_name_str = m_define.group(1)
                m_val_raw = (m_define.group(2) or "").strip()

                if not m_val_raw:
                    flags[m_name_str] = None
                else:
                    val_clean = re.sub(r'/\*.*?\*/|//.*', '', m_val_raw).strip()
                    if not val_clean:
                        flags[m_name_str] = None
                    else:
                        m_num = re.match(r'^-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*$', val_clean)
                        if m_num:
                            parsed_int = _parse_c_int_literal(val_clean)
                            if parsed_int is not None:
                                flags[m_name_str] = parsed_int
                            else:
                                flags[m_name_str] = val_clean
                        else:
                            curr_macros = _normalize_macro_dict(flags)
                            tokens = _tokenize_c_prep_expr(val_clean, curr_macros)
                            if tokens:
                                flags[m_name_str] = _eval_c_prep_tokens(tokens)
                            else:
                                flags[m_name_str] = val_clean

            elif m_undef:
                m_name_str = m_undef.group(1)
                flags[m_name_str] = False
        else:
            i += 1

    return ConfigProfile(name=config_name, flags=flags)


def find_compile_commands(target_path: str, config_dir: Optional[str] = None) -> Optional[str]:
    """
    Auto-discovers compile_commands.json by searching upward starting from target_path
    up to project boundary markers (.git, .cgull.toml, pyproject.toml, config_dir, or drive root).
    Returns path to compile_commands.json if found, else None.
    """
    import os
    if not target_path:
        return None

    abs_target = os.path.abspath(target_path)
    curr_dir = abs_target if os.path.isdir(abs_target) else os.path.dirname(abs_target)

    stop_dirs = set()
    if config_dir:
        stop_dirs.add(os.path.abspath(config_dir))

    while True:
        cc_file = os.path.join(curr_dir, "compile_commands.json")
        if os.path.isfile(cc_file):
            return cc_file

        if (
            curr_dir in stop_dirs
            or os.path.isdir(os.path.join(curr_dir, ".git"))
            or os.path.isfile(os.path.join(curr_dir, ".cgull.toml"))
            or os.path.isfile(os.path.join(curr_dir, "pyproject.toml"))
        ):
            break

        parent = os.path.dirname(curr_dir)
        if parent == curr_dir:
            break
        curr_dir = parent

    return None


def _format_profile_name_from_flags(flags: Dict[str, Optional[Union[str, int, bool]]]) -> str:
    """
    Formats a profile name from a dictionary of macro flags.
    """
    if not flags:
        return "default"
    parts = []
    for k in sorted(flags.keys()):
        v = flags[k]
        if v is None:
            parts.append(k)
        elif v is False:
            parts.append(f"-U{k}")
        else:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _parse_macro_flag_spec(
    spec: str,
    is_undef: bool = False
) -> Tuple[Optional[str], Optional[Union[str, int, bool]]]:
    """
    Parses a macro specification string (e.g. "FOO", "RETRY_COUNT=5", "VERSION=\"1.0.0\"").
    Returns (macro_name, value).
    """
    spec = spec.strip()
    if not spec:
        return None, None

    if is_undef:
        macro_name = spec.split()[0]
        if re.fullmatch(r"[a-zA-Z_]\w*", macro_name):
            return macro_name, False
        return None, None

    if "=" in spec:
        macro_name, raw_val = spec.split("=", 1)
        macro_name = macro_name.strip()
        raw_val = raw_val.strip()

        if not re.fullmatch(r"[a-zA-Z_]\w*", macro_name):
            return None, None

        # Strip surrounding quotes if present
        if (raw_val.startswith('"') and raw_val.endswith('"')) or (raw_val.startswith("'") and raw_val.endswith("'")):
            raw_val = raw_val[1:-1]

        m_num = re.match(r'^-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*$', raw_val)
        if m_num:
            parsed_int = _parse_c_int_literal(raw_val)
            if parsed_int is not None:
                parsed_val: Union[str, int] = parsed_int
            else:
                parsed_val = raw_val
        else:
            parsed_val = raw_val

        return macro_name, parsed_val
    else:
        macro_name = spec.strip()
        if re.fullmatch(r"[a-zA-Z_]\w*", macro_name):
            return macro_name, None
        return None, None


def parse_compile_commands(filepath_or_data: Union[str, List[Any]]) -> List[ConfigProfile]:
    """
    Parses a JSON Compilation Database (compile_commands.json) file or loaded JSON list
    into a list of ConfigProfiles.
    Groups entries that share an identical set of -D and -U preprocessor flags into a single ConfigProfile,
    named from the shared flags rather than any single file.
    """
    import json
    import shlex
    from pathlib import Path

    if isinstance(filepath_or_data, (str, Path)):
        filepath = str(filepath_or_data)
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Compile commands file '{filepath}' does not exist.")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    elif isinstance(filepath_or_data, list):
        data = filepath_or_data
        filepath = "<json_data>"
    else:
        raise ValueError("filepath_or_data must be a filepath string or a loaded JSON list.")

    if not isinstance(data, list):
        raise ValueError(
            f"Invalid compile_commands.json structure in '{filepath}': top-level JSON must be an array of entry objects."
        )

    valid_entries = [
        entry for entry in data
        if isinstance(entry, dict) and ("command" in entry or "arguments" in entry)
    ]
    if not valid_entries:
        raise ValueError(
            f"Invalid compile_commands.json structure in '{filepath}': array contains no valid compile command entries (expected objects with 'command' or 'arguments')."
        )

    grouped_flags: Dict[frozenset, Dict[str, Optional[Union[str, int, bool]]]] = {}

    for entry in valid_entries:
        args: List[str] = []
        if "arguments" in entry and isinstance(entry["arguments"], list):
            args = [str(a) for a in entry["arguments"]]
        elif "command" in entry and isinstance(entry["command"], str):
            try:
                args = shlex.split(entry["command"], posix=True)
            except Exception:
                args = entry["command"].split()
        else:
            continue

        entry_flags: Dict[str, Optional[Union[str, int, bool]]] = {}
        idx = 0
        num_args = len(args)

        while idx < num_args:
            arg = args[idx]
            if arg == "-D":
                if idx + 1 < num_args:
                    idx += 1
                    macro, val = _parse_macro_flag_spec(args[idx])
                    if macro:
                        entry_flags[macro] = val
            elif arg.startswith("-D"):
                macro, val = _parse_macro_flag_spec(arg[2:])
                if macro:
                    entry_flags[macro] = val
            elif arg == "-U":
                if idx + 1 < num_args:
                    idx += 1
                    macro, val = _parse_macro_flag_spec(args[idx], is_undef=True)
                    if macro:
                        entry_flags[macro] = val
            elif arg.startswith("-U"):
                macro, val = _parse_macro_flag_spec(arg[2:], is_undef=True)
                if macro:
                    entry_flags[macro] = val

            idx += 1

        flag_key = frozenset(entry_flags.items())
        if flag_key not in grouped_flags:
            grouped_flags[flag_key] = entry_flags

    profiles: List[ConfigProfile] = []
    for entry_flags in grouped_flags.values():
        p_name = _format_profile_name_from_flags(entry_flags)
        profiles.append(ConfigProfile(name=p_name, flags=entry_flags))

    return profiles


def parse_config_seeds(path_or_dir: str) -> List[ConfigProfile]:
    """
    Parses configuration seed header files or JSON seed files from a file or directory into a list of ConfigProfiles.

    If path_or_dir is a JSON file (.json), parses and returns all ConfigProfiles defined in it.
    If path_or_dir is a header file (.h/.hpp), parses and returns a single-item list containing its ConfigProfile.
    If path_or_dir is a directory:
        - Discovers all .h and .hpp files directly in that directory.
        - If an optional .cgullconfigs manifest file exists in the directory, parses it to filter
          and order the headers.
        - Parses each selected header using parse_config_seed.
    """
    import os
    import fnmatch
    import json
    from pathlib import Path

    p = Path(path_or_dir)
    if not p.exists():
        raise FileNotFoundError(f"Config seed path '{path_or_dir}' does not exist.")

    if p.is_file():
        if p.suffix.lower() == ".json":
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            if isinstance(data, list):
                is_cc = any(
                    isinstance(entry, dict) and ("command" in entry or "arguments" in entry)
                    for entry in data
                )
                if is_cc:
                    return parse_compile_commands(data)
                raise ValueError(
                    f"Invalid JSON seed file '{path_or_dir}': top-level list must contain compilation database entries with 'command' or 'arguments'."
                )
            elif isinstance(data, dict):
                return parse_json_config_seed(str(p))
            else:
                raise ValueError(
                    f"Invalid JSON config seed structure in '{path_or_dir}': top-level JSON must be an object or compilation database list."
                )
        return [parse_config_seed(str(p))]

    if not p.is_dir():
        raise ValueError(f"Config seed path '{path_or_dir}' is neither a file nor a directory.")

    dir_path = p
    manifest_path = dir_path / ".cgullconfigs"

    direct_headers = [
        f.name for f in dir_path.iterdir()
        if f.is_file() and f.suffix.lower() in ('.h', '.hpp')
    ]
    direct_headers_sorted = sorted(direct_headers)

    selected_filenames: List[str] = []

    def _matches_pattern(filename: str, pattern: str) -> bool:
        clean_pat = pattern.lstrip("./")
        if filename == clean_pat or os.path.basename(clean_pat) == filename:
            return True
        if fnmatch.fnmatch(filename, clean_pat) or fnmatch.fnmatch(filename, os.path.basename(clean_pat)):
            return True
        return False

    base_dir_resolved = dir_path.resolve()

    if manifest_path.is_file():
        with open(manifest_path, "r", encoding="utf-8", errors="replace") as mf:
            raw_lines = [line.strip() for line in mf]
            lines = [line for line in raw_lines if line and not line.startswith("#")]

        inclusions = [line for line in lines if not line.startswith("!")]
        exclusions = [line[1:].strip() for line in lines if line.startswith("!")]

        if inclusions:
            for inc in inclusions:
                clean_inc = inc.lstrip("./")
                if ".." in inc or "/" in clean_inc or "\\" in clean_inc:
                    raise ValueError(f"Invalid manifest entry '{inc}': path separators and path traversal are not allowed.")

                if not Path(clean_inc).suffix.lower() in ('.h', '.hpp'):
                    raise ValueError(f"Invalid manifest entry '{inc}': file must have a .h or .hpp extension.")

                candidate = (dir_path / clean_inc).resolve()
                try:
                    is_rel = candidate.is_relative_to(base_dir_resolved)
                except AttributeError:
                    is_rel = (os.path.commonpath([str(base_dir_resolved), str(candidate)]) == str(base_dir_resolved))

                if not is_rel:
                    raise ValueError(f"Invalid manifest entry '{inc}': resolves outside seed directory.")

                matched = [h for h in direct_headers_sorted if _matches_pattern(h, inc)]
                if not matched and candidate.is_file():
                    matched.append(clean_inc)

                for m_file in matched:
                    if m_file not in selected_filenames:
                        selected_filenames.append(m_file)
        else:
            selected_filenames = list(direct_headers_sorted)

        if exclusions:
            filtered = []
            for fname in selected_filenames:
                excluded = False
                for exc in exclusions:
                    if _matches_pattern(fname, exc):
                        excluded = True
                        break
                if not excluded:
                    filtered.append(fname)
            selected_filenames = filtered

    else:
        selected_filenames = direct_headers_sorted

    profiles: List[ConfigProfile] = []
    for fname in selected_filenames:
        header_file = dir_path / fname
        if header_file.is_file():
            profiles.append(parse_config_seed(str(header_file)))

    return profiles


def _generate_pairwise_covering_array(presence_flags: List[str]) -> List[Set[str]]:
    """
    Generates a 2-way covering array for a list of boolean presence flags using IPOG.
    Returns a list of sets, where each set contains the flag names defined (set to None) in that profile.
    """
    n = len(presence_flags)
    if n == 0:
        return [set()]
    if n == 1:
        return [set(), {presence_flags[0]}]
    if n == 2:
        return [
            set(),
            {presence_flags[0]},
            {presence_flags[1]},
            {presence_flags[0], presence_flags[1]},
        ]

    # Initialize T with all 4 combinations of first 2 variables
    T: List[Dict[int, int]] = [
        {0: 0, 1: 0},
        {0: 0, 1: 1},
        {0: 1, 1: 0},
        {0: 1, 1: 1},
    ]

    for i in range(2, n):
        # Uncovered tuples for variable i with any j < i
        C: Set[Tuple[int, int, int]] = set()
        for j in range(i):
            for vj in (0, 1):
                for vi in (0, 1):
                    C.add((j, vj, vi))

        # Phase 1: Horizontal extension of existing rows in T
        for r in T:
            best_vi = 0
            best_cover_count = -1
            best_covered_tuples: Set[Tuple[int, int, int]] = set()

            for vi in (0, 1):
                covered_now = set()
                for j in range(i):
                    vj = r[j]
                    tup = (j, vj, vi)
                    if tup in C:
                        covered_now.add(tup)
                if len(covered_now) > best_cover_count:
                    best_cover_count = len(covered_now)
                    best_vi = vi
                    best_covered_tuples = covered_now

            r[i] = best_vi
            C.difference_update(best_covered_tuples)

        # Phase 2: Vertical extension for remaining uncovered tuples in C
        while C:
            target_tup = sorted(C)[0]
            j_target, vj_target, vi_target = target_tup

            new_r: Dict[int, int] = {}
            new_r[j_target] = vj_target
            new_r[i] = vi_target

            for k in range(i):
                if k == j_target:
                    continue
                best_vk = 0
                best_k_count = -1
                for vk in (0, 1):
                    cnt = 1 if (k, vk, vi_target) in C else 0
                    if cnt > best_k_count:
                        best_k_count = cnt
                        best_vk = vk
                new_r[k] = best_vk

            covered_by_new = set()
            for k in range(i):
                vk = new_r[k]
                tup = (k, vk, vi_target)
                if tup in C:
                    covered_by_new.add(tup)
            C.difference_update(covered_by_new)
            T.append(new_r)

    result = []
    for r in T:
        active = {presence_flags[idx] for idx, val in r.items() if val == 1}
        result.append(active)

    unique_results = []
    seen = set()
    for active_set in result:
        fs = frozenset(active_set)
        if fs not in seen:
            seen.add(fs)
            unique_results.append(active_set)

    return unique_results


def generate_config_profiles(
    flags: Union[CollectedFlags, Set[str], List[str], Tuple[str, ...]],
    baseline_name: str = "baseline",
    strategy: str = "one-at-a-time",
    exhaustive_threshold: int = 10,
    base_flags: Optional[Dict[str, Any]] = None,
) -> List[ConfigProfile]:
    """
    Generates ConfigProfile objects according to the requested configuration expansion strategy.

    Strategies:
      - "baseline": generates a single baseline profile ("nothing extra defined").
      - "one-at-a-time": generates (1) baseline profile and (2) single-flag-flipped variants (O(N)).
      - "pairwise": generates a 2-way covering array over all flag pairs using IPOG algorithm.
      - "exhaustive": generates all 2^N combinations of presence flags. Permitted only when N <= exhaustive_threshold;
        otherwise raises ValueError suggesting pairwise.

    Args:
        flags: A CollectedFlags object or a set/list/tuple of presence flag names.
        baseline_name: Profile name for the baseline configuration (default: "baseline").
        strategy: Expansion strategy ("baseline", "one-at-a-time", "pairwise", "exhaustive").
        exhaustive_threshold: Max flag count allowed for "exhaustive" strategy (default: 10).
        base_flags: Optional dictionary of base macro flags to include in all generated profiles.

    Returns:
        List of ConfigProfile objects.
    """
    if isinstance(flags, CollectedFlags):
        presence_set = flags.presence_flags
    elif isinstance(flags, (set, list, tuple)):
        presence_set = set(flags)
    else:
        raise TypeError(f"Expected CollectedFlags, set, list, or tuple, got {type(flags).__name__}")

    valid_strategies = {"baseline", "one-at-a-time", "pairwise", "exhaustive"}
    strat_clean = str(strategy).strip().lower()
    if strat_clean not in valid_strategies:
        raise ValueError(
            f"Invalid config strategy '{strategy}'. Expected one of: {', '.join(sorted(valid_strategies))}."
        )

    presence_flags = sorted(presence_set)
    base_dict = dict(base_flags) if base_flags else {}

    if strat_clean == "baseline":
        return [ConfigProfile(name=baseline_name, flags=base_dict)]

    if strat_clean == "one-at-a-time":
        profiles: List[ConfigProfile] = [ConfigProfile(name=baseline_name, flags=base_dict)]
        for flag in presence_flags:
            f_map = dict(base_dict)
            f_map[flag] = None
            profiles.append(ConfigProfile(name=flag, flags=f_map))
        return profiles

    if strat_clean == "exhaustive":
        flag_count = len(presence_flags)
        if flag_count > exhaustive_threshold:
            raise ValueError(
                f"Discovered flag count ({flag_count}) exceeds max exhaustive threshold ({exhaustive_threshold}). "
                f"Use pairwise or one-at-a-time strategy."
            )
        import itertools
        profiles = []
        for k in range(0, flag_count + 1):
            for combo in itertools.combinations(presence_flags, k):
                f_map = dict(base_dict)
                for flag in combo:
                    f_map[flag] = None
                if not combo:
                    p_name = baseline_name
                else:
                    p_name = _format_profile_name_from_flags({f: None for f in combo})
                profiles.append(ConfigProfile(name=p_name, flags=f_map))
        return profiles

    if strat_clean == "pairwise":
        flag_sets = _generate_pairwise_covering_array(presence_flags)
        profiles = []
        for active_set in flag_sets:
            f_map = dict(base_dict)
            for flag in active_set:
                f_map[flag] = None
            if not active_set:
                p_name = baseline_name
            else:
                p_name = _format_profile_name_from_flags({f: None for f in sorted(active_set)})
            profiles.append(ConfigProfile(name=p_name, flags=f_map))
        return profiles

    return [ConfigProfile(name=baseline_name, flags=base_dict)]

STANDARD_UNSIGNED_TYPES = {
    "size_t", "size_type", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "uintptr_t", "uintmax_t", "u_int8_t", "u_int16_t", "u_int32_t", "u_int64_t",
    "u_char", "u_int", "u_long", "u_short", "char16_t", "char32_t"
}


def is_unsigned_type(type_name: str, custom_typedefs: Optional[Set[str]] = None) -> bool:
    """
    Returns True if type_name represents an unsigned integer or pointer-size type.
    Resolves standard C unsigned typedefs (e.g. size_t, uint8_t, uintptr_t)
    as well as any custom unsigned typedefs provided.
    """
    if not type_name:
        return False
    tn = type_name.lower()
    if "unsigned" in tn:
        return True
    for u_type in STANDARD_UNSIGNED_TYPES:
        if re.search(r'\b' + re.escape(u_type) + r'\b', tn):
            return True
    if custom_typedefs:
        for u_type in custom_typedefs:
            if re.search(r'\b' + re.escape(u_type.lower()) + r'\b', tn):
                return True
    return False


# Common standard-library typedefs that pycparser needs a definition for
# since it never sees <stdint.h>/<stddef.h>/etc. Injected as a prelude
# before parsing; stripped back out via line-count offset afterwards.
_PYCPARSER_PRELUDE = """
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned char uint8_t;
typedef signed char int8_t;
typedef unsigned short uint16_t;
typedef signed short int16_t;
typedef unsigned int uint32_t;
typedef signed int int32_t;
typedef unsigned long uint64_t;
typedef signed long int64_t;
typedef int wchar_t;
typedef int bool;
typedef unsigned long uintptr_t;
typedef long intptr_t;
typedef unsigned long size_type;
"""
_PRELUDE_LINE_COUNT = _PYCPARSER_PRELUDE.count("\n")

# Keywords that must never be treated as a "type" by the declaration-regex
# matcher. Without this guard, a bare statement like `return c;` or
# `break;` parses as if it were declaring a variable named after whatever
# identifier follows the keyword (`return` looks like a type, `c` looks
# like the declared name), producing spurious "uninitialized variable"
# findings on ordinary control-flow statements.
_STATEMENT_KEYWORDS = {
    'return', 'break', 'continue', 'goto', 'case', 'default', 'if', 'else', 'for', 'while',
    'switch', 'sizeof', 'typeof', 'do',
}

# Strips #include/#define/#pragma/#if.../conditional compilation directives
# (and line-continuations) so pycparser sees plain C. This is a best-effort
# substitute for a real preprocessor pass -- it will not expand macros, so
# code that structurally depends on macro expansion still won't parse, but
# it unblocks the large fraction of files that only use directives for
# includes/include-guards/simple constants.
_PREPROCESSOR_LINE_RE = re.compile(r'^[ \t]*#')


