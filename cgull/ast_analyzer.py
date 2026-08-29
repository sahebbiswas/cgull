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

from .models import ParserStatus, ParseTier, ConfigProfile
from .utils import strip_comments_keep_lines, mask_string_and_char_literals

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


@dataclass
class _CondFrame:
    has_taken: bool
    is_taken: bool
    parent_active: bool


def _parse_c_int_literal(literal_str: str) -> Optional[int]:
    """
    Parses a C integer literal string into an int.
    Supports hexadecimal (0x/0X), binary (0b/0B), legacy octal (leading 0 followed by octal digits),
    decimal numbers, leading signs (+/-), and C integer suffixes (U, L, UL, ULL, etc.).
    Returns None if parsing fails.
    """
    if not literal_str:
        return None
    s = literal_str.strip()
    sign = 1
    if s.startswith('-'):
        sign = -1
        s = s[1:].strip()
    elif s.startswith('+'):
        s = s[1:].strip()

    s = re.sub(r'[uUlL]+$', '', s)
    if not s:
        return None

    try:
        if s.startswith(('0x', '0X')):
            return sign * int(s[2:], 16)
        elif s.startswith(('0b', '0B')):
            return sign * int(s[2:], 2)
        elif s.startswith('0') and len(s) > 1 and s.isdigit():
            return sign * int(s, 8)
        else:
            return sign * int(s, 10)
    except ValueError:
        return None


_C_PREP_TOKEN_RE = re.compile(
    r'(?P<WHITESPACE>[ \t\r\n]+)|'
    r'(?P<NUMBER>(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*)|'
    r'(?P<IDENT>[a-zA-Z_]\w*)|'
    r'(?P<LOGICAL_OR>\|\|)|'
    r'(?P<LOGICAL_AND>&&)|'
    r'(?P<EQUAL>==)|'
    r'(?P<NOT_EQUAL>!=)|'
    r'(?P<LESS_EQUAL><=)|'
    r'(?P<GREATER_EQUAL>>=)|'
    r'(?P<LSHIFT><<)|'
    r'(?P<RSHIFT>>>)|'
    r'(?P<LPAREN>\()|'
    r'(?P<RPAREN>\))|'
    r'(?P<LOGICAL_NOT>!)|'
    r'(?P<BITWISE_NOT>~)|'
    r'(?P<ADD>\+)|'
    r'(?P<SUB>-)|'
    r'(?P<MUL>\*)|'
    r'(?P<DIV>/)|'
    r'(?P<MOD>%)|'
    r'(?P<LESS><)|'
    r'(?P<GREATER>>)|'
    r'(?P<BITWISE_AND>&)|'
    r'(?P<BITWISE_XOR>\^)|'
    r'(?P<BITWISE_OR>\|)'
)


def _tokenize_c_prep_expr(expr_str: str, macros: Dict[str, int]) -> Optional[List[Tuple[str, Any]]]:
    s = expr_str.strip()

    # Pre-resolve defined(SYM) and defined SYM
    def replace_defined(m):
        sym = m.group(1) or m.group(2)
        return " 1 " if sym in macros else " 0 "

    s = re.sub(
        r'\bdefined\s*\(\s*([a-zA-Z_]\w*)\s*\)|\bdefined\s+([a-zA-Z_]\w*)',
        replace_defined,
        s
    )

    tokens: List[Tuple[str, Any]] = []
    pos = 0
    n = len(s)

    while pos < n:
        m = _C_PREP_TOKEN_RE.match(s, pos)
        if not m:
            return None  # Unrecognized character
        pos = m.end()

        kind = m.lastgroup
        if kind == 'WHITESPACE':
            continue

        raw_text = m.group(kind)

        if kind == 'NUMBER':
            val = _parse_c_int_literal(raw_text)
            if val is not None:
                tokens.append(('NUMBER', val))
            else:
                return None
        elif kind == 'IDENT':
            if raw_text == 'true':
                tokens.append(('NUMBER', 1))
            elif raw_text == 'false':
                tokens.append(('NUMBER', 0))
            elif raw_text in macros:
                val = macros[raw_text]
                try:
                    num_val = int(val) if val is not None else 1
                except (TypeError, ValueError):
                    num_val = 1
                tokens.append(('NUMBER', num_val))
            else:
                tokens.append(('NUMBER', 0))
        else:
            tokens.append((kind, None))

    if len(tokens) > 500:
        return None  # DoS guard

    return tokens


_INFIX_BP = {
    'LOGICAL_OR':    (1, 2),
    'LOGICAL_AND':   (3, 4),
    'BITWISE_OR':    (5, 6),
    'BITWISE_XOR':   (7, 8),
    'BITWISE_AND':   (9, 10),
    'EQUAL':         (11, 12),
    'NOT_EQUAL':     (11, 12),
    'LESS':          (13, 14),
    'LESS_EQUAL':    (13, 14),
    'GREATER':       (13, 14),
    'GREATER_EQUAL': (13, 14),
    'LSHIFT':        (15, 16),
    'RSHIFT':        (15, 16),
    'ADD':           (17, 18),
    'SUB':           (17, 18),
    'MUL':           (19, 20),
    'DIV':           (19, 20),
    'MOD':           (19, 20),
}


def _eval_c_prep_tokens(tokens: List[Tuple[str, Any]]) -> int:
    pos = 0
    n = len(tokens)

    def parse_expr(min_bp: int = 0) -> int:
        nonlocal pos
        if pos >= n:
            return 0

        tok_type, tok_val = tokens[pos]
        pos += 1

        if tok_type == 'NUMBER':
            left = tok_val
        elif tok_type == 'LPAREN':
            left = parse_expr(0)
            if pos < n and tokens[pos][0] == 'RPAREN':
                pos += 1
        elif tok_type == 'LOGICAL_NOT':
            right = parse_expr(21)
            left = 1 if (right == 0) else 0
        elif tok_type == 'BITWISE_NOT':
            right = parse_expr(21)
            left = ~right
        elif tok_type == 'ADD':
            left = parse_expr(21)
        elif tok_type == 'SUB':
            left = -parse_expr(21)
        else:
            return 0

        while pos < n:
            op_type = tokens[pos][0]
            if op_type not in _INFIX_BP:
                break
            lbp, rbp = _INFIX_BP[op_type]
            if lbp < min_bp:
                break
            pos += 1  # consume op

            right = parse_expr(rbp)

            if op_type == 'LOGICAL_OR':
                left = 1 if (left != 0 or right != 0) else 0
            elif op_type == 'LOGICAL_AND':
                left = 1 if (left != 0 and right != 0) else 0
            elif op_type == 'BITWISE_OR':
                left = left | right
            elif op_type == 'BITWISE_XOR':
                left = left ^ right
            elif op_type == 'BITWISE_AND':
                left = left & right
            elif op_type == 'EQUAL':
                left = 1 if (left == right) else 0
            elif op_type == 'NOT_EQUAL':
                left = 1 if (left != right) else 0
            elif op_type == 'LESS':
                left = 1 if (left < right) else 0
            elif op_type == 'LESS_EQUAL':
                left = 1 if (left <= right) else 0
            elif op_type == 'GREATER':
                left = 1 if (left > right) else 0
            elif op_type == 'GREATER_EQUAL':
                left = 1 if (left >= right) else 0
            elif op_type == 'LSHIFT':
                shift_amt = max(0, min(63, right))
                left = left << shift_amt
            elif op_type == 'RSHIFT':
                shift_amt = max(0, min(63, right))
                left = left >> shift_amt
            elif op_type == 'ADD':
                left = left + right
            elif op_type == 'SUB':
                left = left - right
            elif op_type == 'MUL':
                left = left * right
            elif op_type == 'DIV':
                left = left // right if right != 0 else 0
            elif op_type == 'MOD':
                left = left % right if right != 0 else 0

        return left

    try:
        return parse_expr(0)
    except Exception:
        return 0


def _normalize_macro_dict(defined_syms: Optional[Any]) -> Dict[str, int]:
    """
    Normalizes defined_syms into a Dict[str, int] suitable for preprocessor expression evaluation.
    Handles sets/lists/tuples (mapping symbols to 1) and dicts/Mapping (converting values
    including None for presence toggles, bools, ints, and string integers to int).
    Note: Entries whose value is explicitly False (e.g. from #undef in a seed header) are omitted
    so defined(SYM) returns False and sym in macros evaluates to False.
    """
    if not defined_syms:
        return {}

    if isinstance(defined_syms, (set, list, tuple, frozenset)):
        return {str(s): 1 for s in defined_syms}

    if isinstance(defined_syms, (dict, Mapping)):
        macros: Dict[str, int] = {}
        for k, v in defined_syms.items():
            key = str(k)
            if v is False:
                continue
            elif v is None:
                macros[key] = 1
            elif isinstance(v, bool):
                macros[key] = 1 if v else 0
            elif isinstance(v, int):
                macros[key] = v
            elif isinstance(v, str):
                v_clean = v.strip()
                parsed_int = _parse_c_int_literal(v_clean)
                if parsed_int is not None:
                    macros[key] = parsed_int
                else:
                    macros[key] = 1 if v_clean else 0
            else:
                try:
                    macros[key] = int(v)
                except (TypeError, ValueError):
                    macros[key] = 1
        return macros

    return {}


def eval_preprocessor_expr(expr_str: str, defined_syms: Optional[Any] = None) -> bool:
    """
    Evaluates a C preprocessor condition expression (for #if / #elif) under
    the assumption of `defined_syms` / `macros`. Any undefined identifier evaluates to 0 (false).
    Supports C operator precedence, numeric macro expansion, integer suffixes (U, L, UL, etc.),
    and contains DoS protections against extreme shifts or division by zero.
    """
    if not expr_str or not expr_str.strip():
        return False

    macros = _normalize_macro_dict(defined_syms)

    tokens = _tokenize_c_prep_expr(expr_str, macros)
    if tokens is None or len(tokens) == 0:
        return False

    val = _eval_c_prep_tokens(tokens)
    return bool(val != 0)


def resolve_preprocessor_conditionals(code: str, defined_syms: Optional[Any] = None) -> str:
    """
    Performs a line-by-line single-pass resolution of C preprocessor directives and
    conditionals (#if, #ifdef, #ifndef, #elif, #else, #endif), evaluating branch
    conditions against `macros` (or `defined_syms`).

    Replaces directive lines and non-taken branch bodies with blank lines ("") to maintain
    exact line alignment and total line count for AST mapping.
    """
    macros: Dict[str, int] = _normalize_macro_dict(defined_syms)

    lines = code.splitlines()
    output_lines: List[str] = []

    cond_stack: List[_CondFrame] = []

    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        line_lstrip = line.lstrip()

        # Check if this line starts a preprocessor directive
        if line_lstrip.startswith('#'):
            directive_parts = []
            directive_line_indices = []

            curr_i = i
            while curr_i < n:
                curr_line = lines[curr_i]
                directive_line_indices.append(curr_i)
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
            m_if = re.match(r'^if\b\s*(.*)', dir_body)
            m_elif = re.match(r'^elif\b\s*(.*)', dir_body)
            m_else = re.match(r'^else\b', dir_body)
            m_endif = re.match(r'^endif\b', dir_body)
            m_define = re.match(r'^define\s+([a-zA-Z_]\w*)(?:\([^)]*\))?(?:\s+(.*))?$', dir_body)
            m_undef = re.match(r'^undef\s+([a-zA-Z_]\w*)', dir_body)

            parent_act = True if not cond_stack else (cond_stack[-1].parent_active and cond_stack[-1].is_taken)

            if m_ifdef:
                sym_name = m_ifdef.group(1)
                val = eval_preprocessor_expr(f"defined({sym_name})", macros) if parent_act else False
                cond_stack.append(_CondFrame(has_taken=val, is_taken=val, parent_active=parent_act))
                for _ in directive_line_indices:
                    output_lines.append("")
            elif m_ifndef:
                sym_name = m_ifndef.group(1)
                val = eval_preprocessor_expr(f"!defined({sym_name})", macros) if parent_act else False
                cond_stack.append(_CondFrame(has_taken=val, is_taken=val, parent_active=parent_act))
                for _ in directive_line_indices:
                    output_lines.append("")
            elif m_if:
                expr_str = m_if.group(1)
                val = eval_preprocessor_expr(expr_str, macros) if parent_act else False
                cond_stack.append(_CondFrame(has_taken=val, is_taken=val, parent_active=parent_act))
                for _ in directive_line_indices:
                    output_lines.append("")
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
                for _ in directive_line_indices:
                    output_lines.append("")
            elif m_else:
                if cond_stack:
                    top = cond_stack[-1]
                    if top.has_taken:
                        top.is_taken = False
                    else:
                        top.is_taken = top.parent_active
                        top.has_taken = True
                for _ in directive_line_indices:
                    output_lines.append("")
            elif m_endif:
                if cond_stack:
                    cond_stack.pop()
                for _ in directive_line_indices:
                    output_lines.append("")
            elif m_define:
                if parent_act:
                    m_name = m_define.group(1)
                    m_val_raw = (m_define.group(2) or "").strip()
                    if not m_val_raw or m_val_raw.startswith('//') or m_val_raw.startswith('/*'):
                        macros[m_name] = 1
                    else:
                        val_clean = re.sub(r'/\*.*?\*/|//.*', '', m_val_raw).strip()
                        m_num = re.match(r'^-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*$', val_clean)
                        if m_num:
                            parsed_int = _parse_c_int_literal(val_clean)
                            if parsed_int is not None:
                                macros[m_name] = parsed_int
                            else:
                                macros[m_name] = 1
                        else:
                            if eval_preprocessor_expr(val_clean, macros):
                                tokens = _tokenize_c_prep_expr(val_clean, macros)
                                if tokens:
                                    macros[m_name] = _eval_c_prep_tokens(tokens)
                                else:
                                    macros[m_name] = 1
                            else:
                                macros[m_name] = 1
                    for idx in directive_line_indices:
                        output_lines.append(lines[idx])
                else:
                    for _ in directive_line_indices:
                        output_lines.append("")
            elif m_undef:
                if parent_act:
                    macros.pop(m_undef.group(1), None)
                    for idx in directive_line_indices:
                        output_lines.append(lines[idx])
                else:
                    for _ in directive_line_indices:
                        output_lines.append("")
            else:
                if parent_act:
                    for idx in directive_line_indices:
                        output_lines.append(lines[idx])
                else:
                    for _ in directive_line_indices:
                        output_lines.append("")

        else:
            # Ordinary code line
            current_active = True if not cond_stack else (cond_stack[-1].parent_active and cond_stack[-1].is_taken)
            if current_active:
                output_lines.append(line)
            else:
                output_lines.append("")
            i += 1

    res = "\n".join(output_lines)
    if code.endswith("\n") and not res.endswith("\n"):
        res += "\n"
    return res


def _strip_attributes_and_specifiers(code: str) -> str:
    """
    Strips GNU/Clang __attribute__((...)) and MSVC __declspec(...) constructs
    from C source code while preserving character/line offsets (replacing
    stripped tokens with spaces/newlines).
    """
    result = []
    i = 0
    n = len(code)
    targets = [('__attribute__', 13), ('__declspec', 10)]
    while i < n:
        matched = False
        for kw, kw_len in targets:
            if code[i:i + kw_len] == kw:
                j = i + kw_len
                while j < n and code[j].isspace():
                    j += 1
                if j < n and code[j] == '(':
                    paren_depth = 0
                    k = j
                    while k < n:
                        if code[k] == '(':
                            paren_depth += 1
                        elif code[k] == ')':
                            paren_depth -= 1
                            if paren_depth == 0:
                                k += 1
                                break
                        k += 1
                    chunk = code[i:k]
                    spaces = ''.join('\n' if c == '\n' else ' ' for c in chunk)
                    result.append(spaces)
                    i = k
                    matched = True
                    break
        if not matched:
            result.append(code[i])
            i += 1
    return ''.join(result)


@dataclass
class CParameter:
    name: str
    type_name: str
    is_pointer: bool
    line_number: int
    is_array: bool = False


class ScopedVarDict(dict):
    """
    A custom dictionary for function variables that supports tuple keys (var_name, enclosing_block_id)
    or string keys (var_name) for lexical block-scoping while maintaining backward-compatible
    string key lookups (returning innermost binding) and de-duplicated string key iteration.
    """
    def __getitem__(self, key):
        if super().__contains__(key):
            return super().__getitem__(key)
        if isinstance(key, str):
            for dict_key, var in reversed(list(super().items())):
                if dict_key == key or (isinstance(dict_key, tuple) and dict_key[0] == key):
                    return var
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        if super().__contains__(key):
            return True
        if isinstance(key, str):
            return any(
                dict_key == key or (isinstance(dict_key, tuple) and dict_key[0] == key)
                for dict_key in super().keys()
            )
        return False

    def items(self):
        seen_names = set()
        for dict_key, var in reversed(list(super().items())):
            name = dict_key[0] if isinstance(dict_key, tuple) else dict_key
            if name not in seen_names:
                seen_names.add(name)
                yield name, var

    def keys(self):
        for name, _var in self.items():
            yield name


@dataclass
class CVariable:
    name: str
    type_name: str
    is_pointer: bool
    is_signed: bool
    is_volatile: bool
    is_vla: bool
    array_size_expr: Optional[str]
    has_initializer: bool
    declaration_line: int
    is_array: bool = False
    assigned_lines: List[int] = field(default_factory=list)
    read_lines: List[int] = field(default_factory=list)
    freed_lines: List[int] = field(default_factory=list)
    checked_null_lines: List[int] = field(default_factory=list)
    enclosing_block_id: int = 0
    address_taken: bool = False
    address_taken_lines: List[int] = field(default_factory=list)


@dataclass
class CFGNode:
    node_id: int
    kind: str  # "decl", "assignment", "call", "if_cond", "while_cond", "for_cond", "switch_cond", "return", "free", "null_check", "statement"
    line_number: int
    expr_str: str = ""
    target_var: Optional[str] = None
    read_vars: Set[str] = field(default_factory=set)
    written_vars: Set[str] = field(default_factory=set)
    freed_vars: Set[str] = field(default_factory=set)
    null_checked_vars: Set[str] = field(default_factory=set)
    next_nodes: List["CFGNode"] = field(default_factory=list)


def _map_line(exp_line: int, line_map: Optional[Dict[int, Any]]) -> int:
    if line_map and exp_line in line_map:
        src_loc = line_map[exp_line]
        if isinstance(src_loc, int):
            return src_loc
        if hasattr(src_loc, "line_number"):
            return src_loc.line_number
        if hasattr(src_loc, "line"):
            return src_loc.line
    return exp_line


@dataclass
class CFunction:
    name: str
    return_type: str
    parameters: List[CParameter]
    start_line: int
    end_line: int
    body: str
    variables: Dict[Union[str, Tuple[str, int]], CVariable] = field(default_factory=ScopedVarDict)
    has_void_param_list: bool = False
    is_empty_param_list: bool = False
    calls: List[Tuple[str, int, str]] = field(default_factory=list)  # (callee_name, line, raw_args)
    returns_boolean: bool = False
    has_assertions: bool = False
    cfg_nodes: List[CFGNode] = field(default_factory=list)
    body_start_line: int = 0
    start_line_exp: int = 0
    end_line_exp: int = 0


@dataclass
class FieldInfo:
    """
    Represents a single field inside a C struct or union definition.

    Attributes:
        name: Name of the field.
        type_name: Declared type of the field (e.g. "int", "char", "struct Inner").
        is_array: True if the field is declared as an array (e.g., char buf[100]).
        array_size: Resolved constant element count if compile-time constant or macro;
            None if scalar, flexible array member (data[] or data[0]), or unknown size.
        is_pointer: True if the field is a pointer.
        is_struct_or_union: True if the field type is a nested struct or union.
        nested_tag: Tag name or typedef name of the nested struct/union if applicable.
        is_union: True if the field itself is a union.
    """
    name: str
    type_name: str
    is_array: bool = False
    array_size: Optional[int] = None
    array_dims: List[Optional[int]] = field(default_factory=list)
    is_pointer: bool = False
    is_struct_or_union: bool = False
    nested_tag: Optional[str] = None
    is_union: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type_name": self.type_name,
            "is_array": self.is_array,
            "array_size": self.array_size,
            "array_dims": self.array_dims,
            "is_pointer": self.is_pointer,
            "is_struct_or_union": self.is_struct_or_union,
            "nested_tag": self.nested_tag,
            "is_union": self.is_union,
        }


@dataclass
class StructDef:
    """
    Represents a C struct or union definition and its field schema table.

    Attributes:
        name: Struct or union tag or primary typedef name.
        is_union: True if this definition is a union rather than a struct.
        fields: Dict mapping field names to FieldInfo objects.
    """
    name: str
    is_union: bool = False
    fields: Dict[str, FieldInfo] = field(default_factory=dict)

    def __getitem__(self, field_name: str) -> FieldInfo:
        return self.fields[field_name]

    def __contains__(self, field_name: str) -> bool:
        return field_name in self.fields

    def __iter__(self):
        return iter(self.fields)

    def __len__(self) -> int:
        return len(self.fields)

    def get(self, field_name: str, default=None):
        return self.fields.get(field_name, default)

    def keys(self):
        return self.fields.keys()

    def values(self):
        return self.fields.values()

    def items(self):
        return self.fields.items()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "is_union": self.is_union,
            "fields": {k: v.to_dict() for k, v in self.fields.items()},
        }


@dataclass
class TypedefShape:
    """
    Tracks typedef target type, pointer status, array status, and array size.
    """
    target: str
    is_pointer: bool = False
    is_array: bool = False
    array_size: Optional[int] = None


def get_type_byte_size(type_str: str, ast_ctx: Optional["CASTContext"] = None) -> Optional[int]:
    """
    Returns the byte size of a C type string if it is a primitive scalar type or pointer.
    Returns None if the type is a struct, union, or unknown layout.
    """
    if not type_str:
        return None

    tn = type_str.strip()
    tn = re.sub(r'\[[^\]]*\]', '', tn).strip()

    if '*' in tn:
        return 8

    if ast_ctx and hasattr(ast_ctx, 'typedef_shapes') and ast_ctx.typedef_shapes:
        clean_tag = re.sub(r'^(?:const|volatile|struct|union)\s+', '', tn).strip()
        if clean_tag in ast_ctx.typedef_shapes:
            shape = resolve_typedef_shape(clean_tag, ast_ctx.typedef_shapes)
            if shape.is_pointer:
                return 8
            tn = shape.target.strip()
            tn = re.sub(r'\[[^\]]*\]', '', tn).strip()
            if '*' in tn:
                return 8

    tn_lower = re.sub(r'\b(?:const|volatile)\b', '', tn).strip().lower()
    tn_lower = re.sub(r'\s+', ' ', tn_lower)

    if tn_lower in ('char', 'signed char', 'unsigned char', 'int8_t', 'uint8_t', 'void', 'bool', '_bool'):
        return 1
    if tn_lower in ('short', 'signed short', 'unsigned short', 'short int', 'signed short int', 'unsigned short int', 'int16_t', 'uint16_t', 'char16_t'):
        return 2
    if tn_lower in ('int', 'signed int', 'unsigned int', 'signed', 'unsigned', 'int32_t', 'uint32_t', 'float', 'char32_t', 'wchar_t'):
        return 4
    if tn_lower in ('long', 'signed long', 'unsigned long', 'long int', 'signed long int', 'unsigned long int', 'long long', 'signed long long', 'unsigned long long', 'long long int', 'signed long long int', 'unsigned long long int', 'int64_t', 'uint64_t', 'double', 'long double', 'size_t', 'ssize_t', 'intptr_t', 'uintptr_t', 'ptrdiff_t', 'time_t'):
        return 8

    return None


def resolve_typedef_shape(
    type_name: str,
    typedef_shapes: Dict[str, TypedefShape],
    visited: Optional[Set[str]] = None
) -> TypedefShape:
    """
    Recursively resolves typedef shape chains (pointers, arrays, target struct tags/types).
    """
    if visited is None:
        visited = set()

    clean_type = re.sub(r'^(?:const|volatile|struct|union)\s+', '', type_name.strip()).rstrip(' *').strip()
    if not clean_type or clean_type in visited or clean_type not in typedef_shapes:
        return TypedefShape(target=type_name)

    visited.add(clean_type)
    shape = typedef_shapes[clean_type]
    sub = resolve_typedef_shape(shape.target, typedef_shapes, visited)

    is_pointer = shape.is_pointer or sub.is_pointer or ('*' in type_name)
    is_array = shape.is_array or sub.is_array
    array_size = shape.array_size if shape.array_size is not None else sub.array_size

    return TypedefShape(
        target=sub.target,
        is_pointer=is_pointer,
        is_array=is_array,
        array_size=array_size,
    )


@dataclass
class CASTContext:
    functions: List[CFunction]
    global_variables: Dict[str, CVariable]
    source_lines: List[str]
    raw_source: str
    clean_source: str
    has_pycparser: bool = False
    pycparser_ast: Optional[Any] = None
    parser_status: str = ParserStatus.FALLBACK_PARSER.value
    parse_tier: str = ParseTier.REGEX_FALLBACK.value
    unsigned_typedefs: Set[str] = field(default_factory=set)
    struct_defs: Dict[str, StructDef] = field(default_factory=dict)
    typedef_shapes: Dict[str, TypedefShape] = field(default_factory=dict)
    line_map: Optional[Dict[int, Any]] = None

    def _clean_and_resolve_type_string(self, type_str: str) -> Optional[StructDef]:
        if not type_str or not isinstance(type_str, str):
            return None
        tn = type_str.strip()
        if tn in self.struct_defs:
            return self.struct_defs[tn]

        # 1. Clean out array brackets, e.g. [100], [4], []
        cleaned = re.sub(r'\[[^\]]*\]', '', tn)
        # 2. Clean out paren pointer declarators like (*parr) or (*)
        cleaned = re.sub(r'\(\s*\*\s*[a-zA-Z_]\w*\s*\)', '', cleaned)
        cleaned = re.sub(r'\(\s*\*\s*\)', '', cleaned)
        # 3. Strip CV qualifiers, storage specifiers
        cleaned = re.sub(r'\b(?:const|volatile|restrict|static|extern|inline|register)\b', '', cleaned)
        # 4. Strip pointer asterisks and trim
        cleaned = cleaned.replace('*', '').strip()
        # 5. Clean leading struct/union keyword
        tag_candidate = re.sub(r'^(?:struct|union)\s+', '', cleaned).strip()

        # Try candidates in order: if type_str explicitly specifies struct or union,
        # prioritize tag-qualified candidates over unqualified typedef names.
        is_explicit_struct = "struct " in type_str
        is_explicit_union = "union " in type_str

        if is_explicit_struct:
            candidates = [f"struct {tag_candidate}", tag_candidate, cleaned, f"union {tag_candidate}"]
        elif is_explicit_union:
            candidates = [f"union {tag_candidate}", tag_candidate, cleaned, f"struct {tag_candidate}"]
        else:
            candidates = [tag_candidate, cleaned, f"struct {tag_candidate}", f"union {tag_candidate}"]

        for cand in candidates:
            if cand in self.struct_defs:
                return self.struct_defs[cand]

        # 6. Try recursive typedef resolution via typedef_shapes if available
        if tag_candidate in self.typedef_shapes:
            shape = resolve_typedef_shape(tag_candidate, self.typedef_shapes)
            sub_clean = re.sub(r'^(?:const|volatile|struct|union)\s+', '', shape.target.strip()).replace('*', '').strip()
            for cand in [sub_clean, shape.target, f"struct {sub_clean}", f"union {sub_clean}"]:
                if cand in self.struct_defs:
                    return self.struct_defs[cand]

        return None

    def get_struct_def(self, type_name: str) -> Optional[StructDef]:
        if not type_name:
            return None
        return self._clean_and_resolve_type_string(type_name)

    def resolve_struct_def(
        self,
        fn_or_type: Union[CFunction, CVariable, CParameter, str],
        expr_or_var: Optional[str] = None
    ) -> Optional[StructDef]:
        """
        Resolves an expression or base identifier (parameter, local variable, or global)
        within a function (or a direct type string / variable object) to its underlying
        struct or union definition (StructDef by tag or primary typedef).
        """
        # If passed a CVariable or CParameter directly
        if isinstance(fn_or_type, (CVariable, CParameter)):
            return self._clean_and_resolve_type_string(fn_or_type.type_name)

        # If passed a type string or identifier string directly without function context
        if isinstance(fn_or_type, str) and expr_or_var is None:
            return self._clean_and_resolve_type_string(fn_or_type)

        # If passed a function and variable/expression name
        if isinstance(fn_or_type, CFunction):
            fn = fn_or_type
            if not expr_or_var:
                return None
            target_str = expr_or_var.strip()

            # 0. Check for leading type cast in target_str, e.g. "((struct A *)p)->array_a" or "(A_t *)p"
            m_cast = re.search(r'\(\s*\*?\s*\(\s*((?:const\s+|volatile\s+|struct\s+|union\s+)?[a-zA-Z_]\w*(?:\s*\*+)?)\s*\)', target_str)
            if not m_cast:
                m_cast = re.search(r'\(\s*((?:const\s+|volatile\s+|struct\s+|union\s+)?[a-zA-Z_]\w*(?:\s*\*+)?)\s*\)', target_str)
            if m_cast:
                cast_type = m_cast.group(1).strip()
                resolved_cast = self._clean_and_resolve_type_string(cast_type)
                if resolved_cast:
                    return resolved_cast

            # Find matching variable, parameter, or global
            target_type_name: Optional[str] = None

            # 1. Exact variable lookup in function body
            if target_str in fn.variables:
                v = fn.variables[target_str]
                target_type_name = v.type_name
            else:
                # 2. Exact parameter lookup
                for p in fn.parameters:
                    if p.name == target_str:
                        target_type_name = p.type_name
                        break

            # 3. Exact global variable lookup
            if not target_type_name and target_str in self.global_variables:
                target_type_name = self.global_variables[target_str].type_name

            # 4. If target_str is a complex expression (e.g. "a->array_a", "arr[0]", "(*parr)"),
            # extract candidate identifier tokens and search for matching local/param/global
            if not target_type_name:
                idents = re.findall(r'\b[a-zA-Z_]\w*\b', target_str)
                keywords = {'struct', 'union', 'const', 'volatile', 'sizeof', 'return', 'int', 'char', 'void'}
                for ident in idents:
                    if ident in keywords:
                        continue
                    if ident in fn.variables:
                        target_type_name = fn.variables[ident].type_name
                        break
                    for p in fn.parameters:
                        if p.name == ident:
                            target_type_name = p.type_name
                            break
                    if target_type_name:
                        break
                    if ident in self.global_variables:
                        target_type_name = self.global_variables[ident].type_name
                        break

            # 5. Fallback: if not found as variable/param/global, treat target_str as type string
            if not target_type_name:
                target_type_name = target_str

            return self._clean_and_resolve_type_string(target_type_name)

        # Fallback for direct string lookup with expr_or_var
        if isinstance(expr_or_var, str):
            return self._clean_and_resolve_type_string(expr_or_var)
        if isinstance(fn_or_type, str):
            return self._clean_and_resolve_type_string(fn_or_type)

        return None


def split_c_statements_at_outer_depth(code_block: str) -> List[str]:
    """
    Splits a C code block (e.g. struct/union body) into statements on semicolons,
    only at outer depth (brace_depth == 0, paren_depth == 0, bracket_depth == 0).
    """
    statements = []
    current = []
    brace_depth = 0
    paren_depth = 0
    bracket_depth = 0

    for ch in code_block:
        if ch == '{':
            brace_depth += 1
            current.append(ch)
        elif ch == '}':
            brace_depth = max(0, brace_depth - 1)
            current.append(ch)
        elif ch == '(':
            paren_depth += 1
            current.append(ch)
        elif ch == ')':
            paren_depth = max(0, paren_depth - 1)
            current.append(ch)
        elif ch == '[':
            bracket_depth += 1
            current.append(ch)
        elif ch == ']':
            bracket_depth = max(0, bracket_depth - 1)
            current.append(ch)
        elif ch == ';' and brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
            stmt = ''.join(current).strip()
            if stmt:
                statements.append(stmt)
            current = []
        else:
            current.append(ch)

    stmt = ''.join(current).strip()
    if stmt:
        statements.append(stmt)

    return statements


def parse_member_declarations(stmt: str, clean_code: str) -> List[FieldInfo]:
    """
    Parses a struct/union member declaration statement (e.g. "int a, b[10], *c;")
    extracting type specifiers and splitting declarators on top-level commas.
    """
    stmt = stmt.strip()
    if not stmt or stmt.startswith('#'):
        return []

    m_body_struct = re.match(r'^((?:struct|union)\b[^{}]*\{[^{}]*\}\s*\*?)\s*(.+)$', stmt, re.DOTALL)
    if m_body_struct:
        type_spec = m_body_struct.group(1).strip()
        decl_part = m_body_struct.group(2).strip()
        declarators = [decl_part]
    else:
        tokens = []
        curr = []
        paren_d = 0
        bracket_d = 0
        brace_d = 0
        for ch in stmt:
            if ch == '(': paren_d += 1
            elif ch == ')': paren_d = max(0, paren_d - 1)
            elif ch == '[': bracket_d += 1
            elif ch == ']': bracket_d = max(0, bracket_d - 1)
            elif ch == '{': brace_d += 1
            elif ch == '}': brace_d = max(0, brace_d - 1)

            if ch == ',' and paren_d == 0 and bracket_d == 0 and brace_d == 0:
                tokens.append(''.join(curr).strip())
                curr = []
            else:
                curr.append(ch)
        if curr:
            tokens.append(''.join(curr).strip())

        if not tokens:
            return []

        first_tok = tokens[0]

        # Check for function pointer declarator in first_tok: e.g. "int (*callback)(void *, int)"
        m_fn_first = re.search(r'^(.*?)\(\s*\*\s*([a-zA-Z_]\w*)\s*\)\s*\((.*?)\)$', first_tok)
        if m_fn_first:
            type_spec = m_fn_first.group(1).strip()
            declarators = tokens
        else:
            m_decl_start = re.search(r'\b([a-zA-Z_]\w*)\s*(?::\s*[^:]+)?\s*(?:\[[^\]]*\])?$', first_tok)
            if not m_decl_start:
                return []

            ident_match = m_decl_start.group(1)
            c_type_keywords = {'int', 'char', 'short', 'long', 'float', 'double', 'signed', 'unsigned', 'struct', 'union', 'enum', 'void', 'const', 'volatile', 'bool'}
            if ident_match in c_type_keywords and ':' in first_tok[m_decl_start.start():]:
                # Anonymous bit-field like "unsigned int : 2"
                return []

            decl1_start_idx = m_decl_start.start()
            before_name = first_tok[:decl1_start_idx].rstrip()
            type_spec = before_name.rstrip(' *').strip()
            if not type_spec and ident_match in c_type_keywords:
                type_spec = ident_match
            ptr_stars = before_name[len(type_spec):]

            decl_part1 = (ptr_stars + first_tok[decl1_start_idx:]).strip()
            declarators = [decl_part1] + tokens[1:]

    fields: List[FieldInfo] = []
    for decl_str in declarators:
        decl_str = decl_str.strip()
        if not decl_str:
            continue

        # Check for function pointer member: e.g. "int (*callback)(void *, int)"
        m_fn = re.search(r'^(.*?)\(\s*\*\s*([a-zA-Z_]\w*)\s*\)\s*\((.*?)\)$', decl_str)
        if m_fn:
            ret_t = m_fn.group(1).strip() or type_spec
            f_name = m_fn.group(2).strip()
            params_t = m_fn.group(3).strip()
            fn_type_name = f"{ret_t} (*)({params_t})".strip() if params_t else f"{ret_t} (*)".strip()
            fields.append(FieldInfo(
                name=f_name,
                type_name=fn_type_name,
                is_array=False,
                array_size=None,
                is_pointer=True,
                is_struct_or_union=False,
                nested_tag=None,
                is_union=False,
            ))
            continue

        m_bit = re.search(r'^(.*?)\b([a-zA-Z_]\w*)\s*:\s*([^:]+)$', decl_str)
        if m_bit:
            f_name = m_bit.group(2)
            ptr_part = m_bit.group(1)
            is_ptr = ('*' in ptr_part) or ('*' in type_spec)
            is_array = False
            array_size = None
        else:
            is_ptr = ('*' in decl_str) or ('*' in type_spec)

            m_arr = re.search(r'\b([a-zA-Z_]\w*)\s*\[\s*([^\]]*)\s*\]$', decl_str)
            m_scalar = re.search(r'\b([a-zA-Z_]\w*)$', decl_str)

            if m_arr:
                f_name = m_arr.group(1)
                dim_expr = m_arr.group(2).strip()
                is_array = True
                if dim_expr == "" or dim_expr == "0":
                    array_size = None
                else:
                    array_size = resolve_constant_expr(dim_expr, clean_code)
            elif m_scalar:
                f_name = m_scalar.group(1)
                is_array = False
                array_size = None
            else:
                continue

        is_struct_or_union = False
        nested_tag = None
        is_field_union = False
        if type_spec.startswith('struct ') or type_spec.startswith('union '):
            is_struct_or_union = True
            is_field_union = type_spec.startswith('union ')
            m_t = re.search(r'\b(?:struct|union)\s+([a-zA-Z_]\w*)', type_spec)
            nested_tag = m_t.group(1) if m_t else None

        base_t = type_spec.strip()
        if is_ptr:
            type_name = base_t if base_t.endswith('*') else f"{base_t} *"
        else:
            type_name = base_t

        fields.append(FieldInfo(
            name=f_name,
            type_name=type_name,
            is_array=is_array,
            array_size=array_size,
            is_pointer=is_ptr,
            is_struct_or_union=is_struct_or_union,
            nested_tag=nested_tag,
            is_union=is_field_union,
        ))

    return fields


def resolve_constant_expr(expr_str: str, clean_code: str, max_depth: int = 20) -> Optional[int]:
    """
    Resolves a constant expression string (digit, hex, expression-valued macro #define,
    const int variable, or enum constant) to an integer value if compile-time constant,
    else returns None. Recursively expands object-like macros with cycle protection.
    """
    if not expr_str or not expr_str.strip():
        return None

    s = expr_str.strip()

    # Direct integer literal (e.g. 100, 0x64, 0144)
    m_num = re.match(r'^-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*$', s)
    if m_num:
        parsed_int = _parse_c_int_literal(s)
        if parsed_int is not None:
            return parsed_int

    # Collect object-like macros (#define MACRO body) from clean_code
    macro_defs: Dict[str, str] = {}
    for line in clean_code.splitlines():
        line_s = line.strip()
        if line_s.startswith('#'):
            dir_body = line_s.lstrip('#').strip()
            m_def = re.match(r'^define\s+([a-zA-Z_]\w*)(?!\()\s+(.+)$', dir_body)
            if m_def:
                m_name = m_def.group(1)
                m_val = re.sub(r'/\*.*?\*/|//.*', '', m_def.group(2)).strip()
                if m_val:
                    macro_defs[m_name] = m_val

    # Collect const int variables
    for const_m in re.finditer(
        r'\bconst\s+(?:int|size_t|uint\w+_t|int\w+_t|unsigned\s+int|long|short)\s+([a-zA-Z_]\w*)\s*=\s*([^;]+);',
        clean_code
    ):
        c_name = const_m.group(1)
        c_val = const_m.group(2).strip()
        macro_defs[c_name] = c_val

    # Collect enum constants
    enum_regex = re.compile(r'\benum\b[^{}]*\{([^}]+)\}')
    for enum_m in enum_regex.finditer(clean_code):
        enum_body = enum_m.group(1)
        curr_val = 0
        for item in enum_body.split(','):
            item = item.strip()
            if not item:
                continue
            if '=' in item:
                parts = item.split('=', 1)
                e_name = parts[0].strip()
                e_val_str = parts[1].strip()
                parsed_e = _parse_c_int_literal(e_val_str)
                if parsed_e is not None:
                    curr_val = parsed_e
                else:
                    curr_val = 0
            else:
                e_name = item.strip()
            if e_name and e_name.isidentifier():
                macro_defs[e_name] = str(curr_val)
                curr_val += 1

    # Recursive macro replacement with cycle protection
    def expand_expr(target_str: str, visited: Set[str], depth: int = 0) -> str:
        if depth > max_depth:
            return target_str

        def replace_ident(m):
            ident = m.group(0)
            if ident in macro_defs and ident not in visited:
                new_visited = visited | {ident}
                body = macro_defs[ident]
                return f"({expand_expr(body, new_visited, depth + 1)})"
            return ident

        return re.sub(r'\b[a-zA-Z_]\w*\b', replace_ident, target_str)

    expanded = expand_expr(s, set())

    # Ensure all identifiers in expression are resolved before evaluating
    remaining_idents = set(re.findall(r'\b[a-zA-Z_]\w*\b', expanded)) - {"true", "false"}
    if remaining_idents:
        return None

    numeric_macros: Dict[str, int] = {}
    tokens = _tokenize_c_prep_expr(expanded, numeric_macros)
    if tokens:
        try:
            val = _eval_c_prep_tokens(tokens)
            return val
        except Exception:
            pass

    return None


def _format_pycparser_expr(node) -> str:
    """Recursively formats a pycparser expression node to a C code string."""
    if node is None:
        return ""
    type_name = type(node).__name__
    if type_name == "Constant":
        return str(node.value)
    elif type_name == "ID":
        return str(node.name)
    elif type_name == "UnaryOp":
        return f"{node.op}{_format_pycparser_expr(node.expr)}"
    elif type_name == "BinaryOp":
        return f"{_format_pycparser_expr(node.left)} {node.op} {_format_pycparser_expr(node.right)}"
    elif type_name == "Cast":
        return f"({_format_pycparser_expr(node.to_type)}){_format_pycparser_expr(node.expr)}"
    elif type_name == "ArrayRef":
        return f"{_format_pycparser_expr(node.name)}[{_format_pycparser_expr(node.subscript)}]"
    elif type_name == "StructRef":
        return f"{_format_pycparser_expr(node.name)}{node.type}{_format_pycparser_expr(node.field)}"
    elif type_name == "FuncCall":
        args_str = ""
        if node.args:
            args_str = ", ".join(_format_pycparser_expr(a) for a in getattr(node.args, "exprs", []))
        return f"{_format_pycparser_expr(node.name)}({args_str})"
    elif type_name == "ExprList":
        return ", ".join(_format_pycparser_expr(e) for e in getattr(node, "exprs", []))
    elif type_name == "Typename":
        tname, _, _, _, _, _, _, _ = _format_pycparser_type(node.type)
        return tname
    elif type_name == "Assignment":
        return f"{_format_pycparser_expr(node.lvalue)} {node.op} {_format_pycparser_expr(node.rvalue)}"
    elif type_name == "Return":
        return f"return {_format_pycparser_expr(node.expr)}".strip() if node.expr else "return"
    elif type_name == "Decl":
        init_str = f" = {_format_pycparser_expr(node.init)}" if node.init else ""
        return f"{_format_pycparser_expr(node.type)} {node.name}{init_str}"
    elif hasattr(node, "name") and node.name:
        return str(node.name)
    return ""


def _format_pycparser_type(node, custom_typedefs: Optional[Set[str]] = None) -> Tuple[str, bool, bool, bool, bool, bool, Optional[str], bool]:
    """
    Recursively formats a pycparser type node.
    Returns:
      (type_name, is_pointer, is_func_ptr, is_volatile, is_signed, is_vla, array_size_expr, is_array)
    """
    if node is None:
        return "int", False, False, False, True, False, None, False

    quals = getattr(node, "quals", []) or []
    is_volatile = "volatile" in quals
    is_signed = "unsigned" not in quals
    type_name = type(node).__name__

    if type_name == "PtrDecl":
        sub_t, sub_ptr, is_fp, sub_vol, sub_sig, sub_vla, sub_dim, is_arr = _format_pycparser_type(node.type, custom_typedefs)
        vol = is_volatile or sub_vol
        sig = is_signed and sub_sig
        if is_fp:
            return f"(*{sub_t})", True, True, vol, sig, False, None, False
        return f"{sub_t} *", True, False, vol, sig, False, None, False

    elif type_name == "ArrayDecl":
        sub_t, sub_ptr, sub_fp, sub_vol, sub_sig, _, _, _ = _format_pycparser_type(node.type, custom_typedefs)
        dim_str = None
        is_vla = False
        if node.dim:
            if type(node.dim).__name__ == "Constant":
                dim_str = str(node.dim.value)
                is_vla = False
            elif type(node.dim).__name__ == "ID":
                dim_str = str(node.dim.name)
                is_vla = True
            else:
                dim_str = _format_pycparser_expr(node.dim)
                is_vla = True
        vol = is_volatile or sub_vol
        sig = is_signed and sub_sig
        return f"{sub_t}[{dim_str or ''}]", sub_ptr, sub_fp, vol, sig, is_vla, dim_str, True

    elif type_name == "FuncDecl":
        ret_t, _, _, sub_vol, sub_sig, _, _, _ = _format_pycparser_type(node.type, custom_typedefs)
        p_list = []
        if node.args and getattr(node.args, "params", None):
            for p in node.args.params:
                p_type_name = type(p).__name__
                if p_type_name == "EllipsisParam" or not hasattr(p, "type"):
                    p_list.append("...")
                elif p_type_name == "Typename":
                    pt, _, _, _, _, _, _, _ = _format_pycparser_type(p.type, custom_typedefs)
                    p_list.append(pt)
                elif p_type_name == "Decl":
                    pt, _, _, _, _, _, _, _ = _format_pycparser_type(p.type, custom_typedefs)
                    p_list.append(f"{pt} {p.name}" if getattr(p, "name", None) else pt)
        params_str = ", ".join(p_list) if p_list else "void"
        return f"{ret_t} ({params_str})", False, True, sub_vol, sub_sig, False, None, False

    elif type_name == "TypeDecl":
        inner = node.type
        inner_type_name = type(inner).__name__
        vol = is_volatile
        sig = is_signed
        if inner_type_name == "IdentifierType":
            names = getattr(inner, "names", ["int"])
            tname = " ".join(names)
            sig = not is_unsigned_type(tname, custom_typedefs)
        elif inner_type_name == "Struct":
            tname = f"struct {inner.name}" if getattr(inner, "name", None) else "struct"
        elif inner_type_name == "Union":
            tname = f"union {inner.name}" if getattr(inner, "name", None) else "union"
        elif inner_type_name == "Enum":
            tname = f"enum {inner.name}" if getattr(inner, "name", None) else "enum"
        else:
            tname = getattr(node, "declname", "int") or "int"
            sig = not is_unsigned_type(tname, custom_typedefs)
        if "volatile" in (getattr(inner, "quals", []) or []):
            vol = True
        return tname, False, False, vol, sig, False, None, False

    elif type_name == "IdentifierType":
        names = getattr(node, "names", ["int"])
        tname = " ".join(names)
        sig = not is_unsigned_type(tname, custom_typedefs)
        return tname, False, False, False, sig, False, None, False

    elif type_name == "Typename":
        return _format_pycparser_type(node.type, custom_typedefs)

    return "int", False, False, False, True, False, None, False


def _extract_identifiers_from_ast(node, ignore_callees: bool = False) -> Set[str]:
    """Recursively extracts all identifier names from an AST node."""
    names: Set[str] = set()
    if node is None:
        return names
    kind = type(node).__name__
    if kind == "ID":
        names.add(str(node.name))
    elif ignore_callees and kind == "FuncCall":
        if node.args:
            names.update(_extract_identifiers_from_ast(node.args, ignore_callees=ignore_callees))
        return names
    for _, child in node.children():
        names.update(_extract_identifiers_from_ast(child, ignore_callees=ignore_callees))
    return names


def _extract_read_vars_from_ast(node) -> Set[str]:
    """
    Recursively extracts variable identifier names that are read in an AST node,
    properly ignoring struct/union member names in StructRef (s.field or ptr->field).
    For FuncCall nodes, recurses into node.name (to capture function pointer variable reads
    such as fp(), obj->fp(), or callbacks[i]()) as well as node.args.
    """
    names: Set[str] = set()
    if node is None:
        return names
    kind = type(node).__name__
    if kind == "ID":
        names.add(str(node.name))
    elif kind == "StructRef":
        names.update(_extract_read_vars_from_ast(node.name))
        return names
    elif kind == "FuncCall":
        if node.name:
            names.update(_extract_read_vars_from_ast(node.name))
        if node.args:
            names.update(_extract_read_vars_from_ast(node.args))
        return names

    for _, child in node.children():
        names.update(_extract_read_vars_from_ast(child))
    return names


def _get_max_ast_line(node, current_max: int, prelude_offset: int) -> int:
    """Recursively finds the maximum line coordinate in an AST node."""
    if node is None:
        return current_max
    if getattr(node, "coord", None):
        current_max = max(current_max, node.coord.line - prelude_offset)
    for _, child in node.children():
        current_max = _get_max_ast_line(child, current_max, prelude_offset)
    return current_max


class _ASTFunctionAnalyzer:
    """
    Traverses a pycparser FuncDef body to extract local variables,
    function calls, dataflow events, and CFG nodes.
    """

    def __init__(self, owning_fn: CFunction, prelude_offset: int, clean_lines: List[str], custom_typedefs: Optional[Set[str]] = None, typedef_shapes: Optional[Dict[str, TypedefShape]] = None, line_map: Optional[Dict[int, Any]] = None):
        self.owning_fn = owning_fn
        self.prelude_offset = prelude_offset
        self.clean_lines = clean_lines
        self.custom_typedefs = custom_typedefs
        self.typedef_shapes = typedef_shapes or {}
        self.line_map = line_map
        self.node_counter = 0
        self.block_counter = 0
        self.scope_stack: List[int] = [0]
        self.block_parents: Dict[int, int] = {}

    def resolve_var(self, name: str) -> Optional[CVariable]:
        for block_id in reversed(self.scope_stack):
            var_key = (name, block_id)
            if var_key in self.owning_fn.variables:
                return self.owning_fn.variables[var_key]
        if name in self.owning_fn.variables:
            return self.owning_fn.variables[name]
        return None

    def analyze(self, body_node) -> None:
        if body_node is None:
            return
        from pycparser import c_ast

        class Visitor(c_ast.NodeVisitor):
            def __init__(self, outer: "_ASTFunctionAnalyzer"):
                self.outer = outer
                self.current_target_var: Optional[str] = None

            def visit_Compound(self, node):
                parent_id = self.outer.scope_stack[-1]
                self.outer.block_counter += 1
                block_id = self.outer.block_counter
                self.outer.block_parents[block_id] = parent_id
                self.outer.scope_stack.append(block_id)
                self.generic_visit(node)
                self.outer.scope_stack.pop()

            def visit_Decl(self, node):
                prev_target = self.current_target_var
                if node.name and type(node.type).__name__ != "FuncDecl":
                    self.current_target_var = node.name
                    exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                    line_no = _map_line(exp_line, self.outer.line_map)
                    tname, is_ptr, is_fp, is_vol, is_sig, is_vla, arr_dim, is_arr = _format_pycparser_type(node.type, self.outer.custom_typedefs)
                    shape = resolve_typedef_shape(tname, self.outer.typedef_shapes) if hasattr(self.outer, "typedef_shapes") and self.outer.typedef_shapes else None
                    v_is_array = is_arr or (shape.is_array if shape else False)
                    v_is_pointer = (is_ptr or is_fp) or (shape.is_pointer if shape else False)
                    v_arr_dim = arr_dim if arr_dim is not None else (str(shape.array_size) if shape and shape.array_size is not None else None)
                    current_block_id = self.outer.scope_stack[-1]
                    c_var = CVariable(
                        name=node.name,
                        type_name=tname,
                        is_pointer=v_is_pointer,
                        is_signed=is_sig,
                        is_volatile=is_vol,
                        is_vla=is_vla,
                        array_size_expr=v_arr_dim,
                        has_initializer=(node.init is not None),
                        declaration_line=line_no,
                        is_array=v_is_array,
                        enclosing_block_id=current_block_id,
                    )
                    var_key = (node.name, current_block_id)
                    self.outer.owning_fn.variables[var_key] = c_var

                    init_ids: Set[str] = set()
                    if node.init:
                        c_var.assigned_lines.append(line_no)
                        init_ids = _extract_read_vars_from_ast(node.init)
                        for v in init_ids:
                            target_v = self.outer.resolve_var(v)
                            if target_v:
                                target_v.read_lines.append(line_no)

                    init_str = f" = {_format_pycparser_expr(node.init)}" if node.init else ""
                    alloc_fn_names = {"malloc", "calloc", "realloc", "aligned_alloc"}
                    is_alloc = False
                    if node.init:
                        init_expr_str = _format_pycparser_expr(node.init)
                        if any(fn_name in init_expr_str for fn_name in alloc_fn_names):
                            is_alloc = True

                    self.outer.node_counter += 1
                    cfg_n = CFGNode(
                        node_id=self.outer.node_counter,
                        kind="allocation" if is_alloc else "decl",
                        line_number=line_no,
                        expr_str=f"{tname} {node.name}{init_str}",
                        target_var=node.name,
                        written_vars={node.name} if node.init else set(),
                        read_vars=init_ids if node.init else set(),
                    )
                    self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)
                self.current_target_var = prev_target

            def visit_Assignment(self, node):
                prev_target = self.current_target_var
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                lval_ids = _extract_identifiers_from_ast(node.lvalue)
                rval_ids = _extract_read_vars_from_ast(node.rvalue)
                target = list(lval_ids)[0] if lval_ids else None
                if type(node.lvalue).__name__ == "ID":
                    target_v = self.outer.resolve_var(node.lvalue.name)
                    if target_v:
                        target_v.assigned_lines.append(line_no)
                        if node.op != '=':
                            target_v.read_lines.append(line_no)
                else:
                    lval_read_ids = _extract_read_vars_from_ast(node.lvalue)
                    for v in lval_read_ids:
                        target_v = self.outer.resolve_var(v)
                        if target_v:
                            target_v.read_lines.append(line_no)
                for v in rval_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

                alloc_fn_names = {"malloc", "calloc", "realloc", "aligned_alloc"}
                rval_expr_str = _format_pycparser_expr(node.rvalue)
                is_alloc = any(fn_name in rval_expr_str for fn_name in alloc_fn_names)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="allocation" if is_alloc else "assignment",
                    line_number=line_no,
                    expr_str=f"{_format_pycparser_expr(node.lvalue)} {node.op} {rval_expr_str}",
                    target_var=target,
                    written_vars=lval_ids if type(node.lvalue).__name__ == "ID" else set(),
                    read_vars=rval_ids | (lval_ids if type(node.lvalue).__name__ != "ID" else set()),
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.current_target_var = target
                self.generic_visit(node)
                self.current_target_var = prev_target

            def visit_Cast(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                read_ids = _extract_read_vars_from_ast(node.expr)
                for v in read_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)
                self.generic_visit(node)

            def visit_Return(self, node):
                prev_target = self.current_target_var
                self.current_target_var = "return"
                self.generic_visit(node)
                self.current_target_var = prev_target

            def visit_UnaryOp(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                if node.op == '&':
                    addr_ids = _extract_read_vars_from_ast(node.expr)
                    for v in addr_ids:
                        target_v = self.outer.resolve_var(v)
                        if target_v:
                            target_v.address_taken = True
                            target_v.address_taken_lines.append(line_no)
                elif node.op in ('++', 'p++', '--', 'p--'):
                    read_ids = _extract_read_vars_from_ast(node.expr)
                    for v in read_ids:
                        target_v = self.outer.resolve_var(v)
                        if target_v:
                            target_v.read_lines.append(line_no)
                            target_v.assigned_lines.append(line_no)

                self.generic_visit(node)
                if node.op == "sizeof":
                    expr_str = _format_pycparser_expr(node.expr)
                    # We do NOT include these as read_vars because unevaluated sizeof operands
                    # are not runtime reads (avoids false-positive Use-After-Free/Uninitialized errors).
                    self.outer.node_counter += 1
                    cfg_n = CFGNode(
                        node_id=self.outer.node_counter,
                        kind="sizeof",
                        line_number=line_no,
                        expr_str=f"sizeof({expr_str})",
                        read_vars=set(),
                    )
                    self.outer.owning_fn.cfg_nodes.append(cfg_n)

                    # Ensure sizeof is treated like a call in fallback as well
                    self.outer.owning_fn.calls.append(("sizeof", line_no, expr_str, self.current_target_var))

            def visit_FuncCall(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                callee = _format_pycparser_expr(node.name)
                raw_args = _format_pycparser_expr(node.args) if node.args else ""
                if callee not in ('if', 'for', 'while', 'switch', 'sizeof', 'typeof', '__attribute__'):
                    self.outer.owning_fn.calls.append((callee, line_no, raw_args, self.current_target_var))

                callee_read_ids = _extract_read_vars_from_ast(node.name)
                arg_read_ids = _extract_read_vars_from_ast(node.args) if node.args else set()
                all_read_ids = callee_read_ids | arg_read_ids
                freed_set: Set[str] = set()
                null_checked_set: Set[str] = set()

                param_names = {p.name for p in self.outer.owning_fn.parameters}
                if callee in ("free", "cfree", "vfree", "realloc"):
                    if node.args and getattr(node.args, "exprs", None):
                        freed_p = _format_pycparser_expr(node.args.exprs[0])
                        target_v = self.outer.resolve_var(freed_p)
                        if target_v:
                            target_v.freed_lines.append(line_no)
                            freed_set.add(freed_p)
                        elif freed_p in param_names:
                            freed_set.add(freed_p)

                if callee in ("assert", "ASSERT", "assert_param"):
                    self.outer.owning_fn.has_assertions = True
                    if node.args:
                        null_checked_set = _extract_read_vars_from_ast(node.args)
                        for v in null_checked_set:
                            target_v = self.outer.resolve_var(v)
                            if target_v:
                                target_v.checked_null_lines.append(line_no)

                for v in all_read_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="free" if freed_set else "call",
                    line_number=line_no,
                    expr_str=f"{callee}({raw_args})",
                    target_var=callee,
                    read_vars=all_read_ids,
                    freed_vars=freed_set,
                    null_checked_vars=null_checked_set,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

            def visit_If(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                cond_ids = _extract_read_vars_from_ast(node.cond)
                null_checked_set = set(cond_ids)
                for v in null_checked_set:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.checked_null_lines.append(line_no)
                for v in cond_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="if_cond",
                    line_number=line_no,
                    expr_str=_format_pycparser_expr(node.cond),
                    read_vars=cond_ids,
                    null_checked_vars=null_checked_set,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

            def visit_While(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                cond_ids = _extract_read_vars_from_ast(node.cond)
                null_checked_set = set(cond_ids)
                for v in null_checked_set:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.checked_null_lines.append(line_no)
                for v in cond_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="while_cond",
                    line_number=line_no,
                    expr_str=_format_pycparser_expr(node.cond),
                    read_vars=cond_ids,
                    null_checked_vars=null_checked_set,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

            def visit_For(self, node):
                parent_id = self.outer.scope_stack[-1]
                self.outer.block_counter += 1
                block_id = self.outer.block_counter
                self.outer.block_parents[block_id] = parent_id
                self.outer.scope_stack.append(block_id)

                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                cond_ids = _extract_read_vars_from_ast(node.cond) if node.cond else set()
                for v in cond_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="for_cond",
                    line_number=line_no,
                    expr_str=_format_pycparser_expr(node.cond) if node.cond else "",
                    read_vars=cond_ids,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)
                self.outer.scope_stack.pop()

            def visit_Return(self, node):
                exp_line = (node.coord.line - self.outer.prelude_offset) if node.coord else self.outer.owning_fn.start_line_exp
                line_no = _map_line(exp_line, self.outer.line_map)
                ret_expr_str = _format_pycparser_expr(node.expr)
                if ret_expr_str in ("0", "1", "true", "false"):
                    if any(term in self.outer.owning_fn.name.lower() for term in ['auth', 'verify', 'check_password', 'validate_token', 'boot_secure', 'crypto', 'admin', 'login', 'permission']):
                        self.outer.owning_fn.returns_boolean = True

                ret_ids = _extract_read_vars_from_ast(node.expr) if node.expr else set()
                for v in ret_ids:
                    target_v = self.outer.resolve_var(v)
                    if target_v:
                        target_v.read_lines.append(line_no)

                self.outer.node_counter += 1
                cfg_n = CFGNode(
                    node_id=self.outer.node_counter,
                    kind="return",
                    line_number=line_no,
                    expr_str=ret_expr_str,
                    read_vars=ret_ids,
                )
                self.outer.owning_fn.cfg_nodes.append(cfg_n)
                self.generic_visit(node)

        Visitor(self).visit(body_node)
        self.owning_fn.block_parents = dict(self.block_parents)

        # Connect sequential CFG nodes
        for i in range(len(self.owning_fn.cfg_nodes) - 1):
            self.owning_fn.cfg_nodes[i].next_nodes.append(self.owning_fn.cfg_nodes[i + 1])


class CASTParser:
    """
    Lightweight C Abstract Syntax & Semantic Flow Parser.
    Extracts functions, scopes, variables, control flow structures,
    pointer dereferences, and function calls.
    """

    def __init__(self):
        pass

    def parse(
        self,
        source_code: str,
        defined_syms: Optional[Any] = None,
        line_map: Optional[Dict[int, Any]] = None,
    ) -> CASTContext:
        lines = source_code.splitlines()
        clean_lines, clean_code = strip_comments_keep_lines(source_code)

        unsigned_typedefs: Set[str] = set()
        self._extract_unsigned_typedefs(clean_code, unsigned_typedefs)

        pycparser_res = self._try_pycparser(clean_code, defined_syms=defined_syms)
        if len(pycparser_res) == 3:
            pycparser_ast, has_pycparser, parse_tier = pycparser_res
        else:
            pycparser_ast, has_pycparser = pycparser_res
            parse_tier = ParseTier.DIRECTIVE_STRIPPED.value if has_pycparser else ParseTier.REGEX_FALLBACK.value

        clean_code = resolve_preprocessor_conditionals(clean_code, defined_syms=defined_syms)
        clean_lines = clean_code.splitlines()

        if has_pycparser and pycparser_ast is not None:
            struct_defs = self._extract_struct_defs_from_ast(pycparser_ast, clean_code)
            functions, global_vars = self._build_model_from_ast(pycparser_ast, clean_lines, clean_code, unsigned_typedefs, line_map=line_map)
            parser_status = ParserStatus.PYCPARSER_SUCCESS.value
        else:
            struct_defs = self._extract_struct_defs_from_regex(clean_code)
            functions = self._extract_functions(clean_lines, clean_code, unsigned_typedefs, line_map=line_map)
            global_vars = self._extract_global_vars(clean_lines, functions, unsigned_typedefs, line_map=line_map)
            parser_status = ParserStatus.FALLBACK_PARSER.value
            parse_tier = ParseTier.REGEX_FALLBACK.value


        typedef_shapes = getattr(self, "typedef_shapes", {})

        return CASTContext(
            functions=functions,
            global_variables=global_vars,
            source_lines=lines,
            raw_source=source_code,
            clean_source=clean_code,
            has_pycparser=has_pycparser,
            pycparser_ast=pycparser_ast,
            parser_status=parser_status,
            parse_tier=parse_tier,
            unsigned_typedefs=unsigned_typedefs,
            struct_defs=struct_defs,
            typedef_shapes=typedef_shapes,
            line_map=line_map,
        )

    def _extract_struct_defs_from_ast(self, pycparser_ast, clean_code: str) -> Dict[str, StructDef]:
        from pycparser import c_ast

        struct_defs: Dict[str, StructDef] = {}
        typedef_aliases: Dict[str, str] = {}
        typedef_shapes: Dict[str, TypedefShape] = {}

        def process_struct_or_union_node(node, name_override: Optional[str] = None):
            is_union = isinstance(node, c_ast.Union)
            struct_tag = node.name
            typedef_name = name_override
            main_name = struct_tag or typedef_name or f"anon_{id(node)}"

            fields_map: Dict[str, FieldInfo] = {}
            if getattr(node, "decls", None):
                for decl in node.decls:
                    if not getattr(decl, "name", None):
                        continue
                    f_name = decl.name
                    curr_type = decl.type

                    is_array = False
                    array_size = None
                    is_pointer = False
                    is_struct_or_union = False
                    nested_tag = None
                    is_field_union = False

                    array_dims = []
                    while isinstance(curr_type, c_ast.ArrayDecl):
                        is_array = True
                        dim_node = curr_type.dim
                        d_size = None
                        if dim_node is None:
                            d_size = None
                        elif isinstance(dim_node, c_ast.Constant):
                            try:
                                val = int(str(dim_node.value), 0)
                                d_size = val if val > 0 else None
                            except ValueError:
                                d_size = resolve_constant_expr(str(dim_node.value), clean_code)
                        elif isinstance(dim_node, c_ast.ID):
                            d_size = resolve_constant_expr(dim_node.name, clean_code)
                        else:
                            expr_str = _format_pycparser_expr(dim_node)
                            d_size = resolve_constant_expr(expr_str, clean_code)
                        array_dims.append(d_size)
                        curr_type = curr_type.type

                    if is_array:
                        array_size = array_dims[0] if array_dims else None

                    while isinstance(curr_type, c_ast.PtrDecl):
                        is_pointer = True
                        curr_type = curr_type.type

                    if isinstance(curr_type, c_ast.TypeDecl):
                        type_node = curr_type.type
                        if isinstance(type_node, c_ast.IdentifierType):
                            t_names = getattr(type_node, 'names', ['int'])
                            type_name = ' '.join(t_names)
                        elif isinstance(type_node, (c_ast.Struct, c_ast.Union)):
                            is_struct_or_union = True
                            is_field_union = isinstance(type_node, c_ast.Union)
                            nested_tag = type_node.name
                            if getattr(type_node, "decls", None):
                                nested_sd = process_struct_or_union_node(type_node)
                                nested_tag = nested_sd.name
                            type_name = f"{'union' if is_field_union else 'struct'} {nested_tag or ''}".strip()
                        else:
                            type_name = getattr(curr_type, 'declname', 'int') or 'int'
                    else:
                        type_name = _format_pycparser_expr(curr_type)

                    fields_map[f_name] = FieldInfo(
                        name=f_name,
                        type_name=type_name,
                        is_array=is_array,
                        array_size=array_size,
                        array_dims=array_dims,
                        is_pointer=is_pointer,
                        is_struct_or_union=is_struct_or_union,
                        nested_tag=nested_tag,
                        is_union=is_field_union,
                    )

            sd = StructDef(name=main_name, is_union=is_union, fields=fields_map)
            prefix = "union" if is_union else "struct"

            struct_defs[main_name] = sd
            struct_defs[f"{prefix} {main_name}"] = sd

            if struct_tag:
                struct_defs[struct_tag] = sd
                struct_defs[f"{prefix} {struct_tag}"] = sd
            if typedef_name:
                struct_defs[typedef_name] = sd
                struct_defs[f"{prefix} {typedef_name}"] = sd

            return sd

        class StructVisitor(c_ast.NodeVisitor):
            def visit_Decl(self, node):
                if isinstance(node.type, (c_ast.Struct, c_ast.Union)) and getattr(node.type, "decls", None):
                    process_struct_or_union_node(node.type)
                self.generic_visit(node)

            def visit_Typedef(self, node):
                td_name = node.name
                curr = node.type

                is_arr = False
                arr_size = None
                if isinstance(curr, c_ast.ArrayDecl):
                    is_arr = True
                    dim_node = curr.dim
                    if dim_node is None:
                        arr_size = None
                    elif isinstance(dim_node, c_ast.Constant):
                        try:
                            val = int(str(dim_node.value), 0)
                            arr_size = val if val > 0 else None
                        except ValueError:
                            arr_size = resolve_constant_expr(str(dim_node.value), clean_code)
                    elif isinstance(dim_node, c_ast.ID):
                        arr_size = resolve_constant_expr(dim_node.name, clean_code)
                    else:
                        expr_str = _format_pycparser_expr(dim_node)
                        arr_size = resolve_constant_expr(expr_str, clean_code)
                    curr = curr.type

                is_ptr = False
                while isinstance(curr, c_ast.PtrDecl):
                    is_ptr = True
                    curr = curr.type

                if isinstance(curr, c_ast.TypeDecl):
                    inner = curr.type
                    if isinstance(inner, (c_ast.Struct, c_ast.Union)):
                        underlying = inner.name or td_name
                        typedef_shapes[td_name] = TypedefShape(
                            target=underlying,
                            is_pointer=is_ptr,
                            is_array=is_arr,
                            array_size=arr_size,
                        )
                        if getattr(inner, "decls", None):
                            sd = process_struct_or_union_node(inner, name_override=td_name)
                            if sd and td_name:
                                struct_defs[td_name] = sd
                        else:
                            if inner.name:
                                typedef_aliases[td_name] = inner.name
                    elif isinstance(inner, c_ast.IdentifierType):
                        underlying = ' '.join(getattr(inner, 'names', []))
                        if underlying:
                            typedef_shapes[td_name] = TypedefShape(
                                target=underlying,
                                is_pointer=is_ptr,
                                is_array=is_arr,
                                array_size=arr_size,
                            )
                            typedef_aliases[td_name] = underlying

                self.generic_visit(node)

        StructVisitor().visit(pycparser_ast)

        self.typedef_shapes = dict(typedef_shapes)

        # Pass 2: Resolve typedef aliases and update field nested tags, pointers, and array shapes (with multi-level chain resolution)
        resolved_aliases: Set[str] = set()
        changed = True
        while changed:
            changed = False
            for alias_name, target_name in list(typedef_aliases.items()):
                if alias_name in resolved_aliases:
                    continue
                target_clean = re.sub(r'^(?:struct|union)\s+', '', target_name).strip()
                target_sd = None
                if target_name in struct_defs:
                    target_sd = struct_defs[target_name]
                elif f"struct {target_clean}" in struct_defs:
                    target_sd = struct_defs[f"struct {target_clean}"]
                elif f"union {target_clean}" in struct_defs:
                    target_sd = struct_defs[f"union {target_clean}"]
                elif target_clean in struct_defs:
                    target_sd = struct_defs[target_clean]

                if target_sd is not None:
                    struct_defs[alias_name] = target_sd
                    resolved_aliases.add(alias_name)
                    changed = True

        # Post-process fields to merge typedef pointer/array shapes and resolve nested struct/union tags
        for sd in list(struct_defs.values()):
            for field in sd.fields.values():
                raw_type = field.type_name.strip()
                clean_type = re.sub(r'^(?:const|volatile|struct|union)\s+', '', raw_type).rstrip(' *').strip()

                if clean_type in typedef_shapes:
                    shape = resolve_typedef_shape(clean_type, typedef_shapes)
                    if shape.is_pointer:
                        field.is_pointer = True
                    if shape.is_array:
                        field.is_array = True
                        if field.array_size is None:
                            field.array_size = shape.array_size

                clean_target = clean_type
                if clean_type in typedef_shapes:
                    clean_target = resolve_typedef_shape(clean_type, typedef_shapes).target
                    clean_target = re.sub(r'^(?:const|volatile|struct|union)\s+', '', clean_target).rstrip(' *').strip()

                matched_sd = None
                for candidate in (clean_target, clean_type):
                    if candidate in struct_defs:
                        matched_sd = struct_defs[candidate]
                        break
                    elif f"struct {candidate}" in struct_defs:
                        matched_sd = struct_defs[f"struct {candidate}"]
                        break
                    elif f"union {candidate}" in struct_defs:
                        matched_sd = struct_defs[f"union {candidate}"]
                        break

                if matched_sd:
                    field.is_struct_or_union = True
                    field.nested_tag = matched_sd.name
                    field.is_union = matched_sd.is_union

        return struct_defs



    def _extract_struct_defs_from_regex(self, clean_code: str) -> Dict[str, StructDef]:
        struct_defs: Dict[str, StructDef] = {}
        typedef_aliases: Dict[str, str] = {}
        typedef_shapes: Dict[str, TypedefShape] = {}

        # 1. Match typedef statements:
        # e.g. typedef struct Inner * InnerPtr_t;
        # typedef char Buffer16_t[16];
        # typedef struct A A_t;
        typedef_stmt_regex = re.compile(
            r'\btypedef\s+([^;]+);',
            re.MULTILINE
        )
        for m in typedef_stmt_regex.finditer(clean_code):
            body = m.group(1).strip()
            if '{' in body or '}' in body:
                continue
            m_arr = re.search(r'^(.*?)\b([a-zA-Z_]\w*)\s*\[\s*([^\]]*)\s*\]$', body)
            m_decl = re.search(r'^(.*?)\b([a-zA-Z_]\w*)$', body)
            if m_arr:
                base_t = m_arr.group(1).strip()
                td_name = m_arr.group(2).strip()
                dim_s = m_arr.group(3).strip()
                is_ptr = '*' in base_t
                arr_sz = resolve_constant_expr(dim_s, clean_code) if dim_s else None
                clean_target = re.sub(r'^(?:const|volatile|struct|union)\s+', '', base_t).rstrip(' *').strip()
                typedef_shapes[td_name] = TypedefShape(
                    target=clean_target,
                    is_pointer=is_ptr,
                    is_array=True,
                    array_size=arr_sz,
                )
                typedef_aliases[td_name] = clean_target
            elif m_decl:
                base_t = m_decl.group(1).strip()
                td_name = m_decl.group(2).strip()
                is_ptr = '*' in base_t or '*' in td_name
                clean_target = re.sub(r'^(?:const|volatile|struct|union)\s+', '', base_t).rstrip(' *').strip()
                typedef_shapes[td_name] = TypedefShape(
                    target=clean_target,
                    is_pointer=is_ptr,
                    is_array=False,
                    array_size=None,
                )
                typedef_aliases[td_name] = clean_target

        # 2. Find struct and union definitions with bodies: [typedef] struct/union [Tag] { body } [Aliases];
        struct_def_regex = re.compile(
            r'\b(typedef\s+)?(struct|union)\b\s*([a-zA-Z_]\w*)?\s*\{',
            re.MULTILINE
        )

        n = len(clean_code)
        for m in struct_def_regex.finditer(clean_code):
            is_typedef = bool(m.group(1))
            kw = m.group(2)
            is_union = (kw == 'union')
            tag = m.group(3)

            body_start = m.end()
            brace_count = 1
            curr_pos = body_start
            while curr_pos < n and brace_count > 0:
                ch = clean_code[curr_pos]
                if ch == '{':
                    brace_count += 1
                elif ch == '}':
                    brace_count -= 1
                curr_pos += 1

            if brace_count != 0:
                continue

            body = clean_code[body_start:curr_pos - 1]

            after_pos = curr_pos
            semicolon_pos = clean_code.find(';', after_pos)
            trailing_str = ""
            if semicolon_pos != -1 and semicolon_pos - after_pos < 100:
                trailing_str = clean_code[after_pos:semicolon_pos].strip()

            aliases = []
            if trailing_str:
                for token in trailing_str.split(','):
                    t = token.strip().lstrip('*').strip()
                    if t and t.isidentifier():
                        aliases.append(t)

            fields_map: Dict[str, FieldInfo] = {}

            member_stmts = split_c_statements_at_outer_depth(body)
            for stmt in member_stmts:
                parsed_fields = parse_member_declarations(stmt, clean_code)
                for f in parsed_fields:
                    fields_map[f.name] = f

            main_name = tag or (aliases[0] if aliases else f"anon_{m.start()}")
            sd = StructDef(name=main_name, is_union=is_union, fields=fields_map)
            prefix = "union" if is_union else "struct"

            if tag:
                struct_defs[tag] = sd
                struct_defs[f"{prefix} {tag}"] = sd

            for alias in aliases:
                struct_defs[alias] = sd
                struct_defs[f"{prefix} {alias}"] = sd

        self.typedef_shapes = dict(typedef_shapes)

        # Pass 2: Resolve simple typedef aliases (with multi-level chain resolution)
        resolved_aliases: Set[str] = set()
        changed = True
        while changed:
            changed = False
            for alias_name, target_name in list(typedef_aliases.items()):
                if alias_name in resolved_aliases:
                    continue
                target_clean = re.sub(r'^(?:struct|union)\s+', '', target_name).strip()
                target_sd = None
                if target_name in struct_defs:
                    target_sd = struct_defs[target_name]
                elif f"struct {target_clean}" in struct_defs:
                    target_sd = struct_defs[f"struct {target_clean}"]
                elif f"union {target_clean}" in struct_defs:
                    target_sd = struct_defs[f"union {target_clean}"]
                elif target_clean in struct_defs:
                    target_sd = struct_defs[target_clean]

                if target_sd is not None:
                    struct_defs[alias_name] = target_sd
                    resolved_aliases.add(alias_name)
                    changed = True

        # Post-process fields for nested structs/unions and typedef shapes
        for sd in list(struct_defs.values()):
            for field in sd.fields.values():
                raw_type = field.type_name.strip()
                clean_type = re.sub(r'^(?:const|volatile|struct|union)\s+', '', raw_type).rstrip(' *').strip()
                if field.name and clean_type.endswith(field.name):
                    clean_type = clean_type[:-len(field.name)].strip()
                clean_type = clean_type.rstrip(' *').strip()

                if clean_type in typedef_shapes:
                    shape = resolve_typedef_shape(clean_type, typedef_shapes)
                    if shape.is_pointer:
                        field.is_pointer = True
                    if shape.is_array:
                        field.is_array = True
                        if field.array_size is None:
                            field.array_size = shape.array_size

                clean_target = clean_type
                if clean_type in typedef_shapes:
                    clean_target = resolve_typedef_shape(clean_type, typedef_shapes).target
                    clean_target = re.sub(r'^(?:const|volatile|struct|union)\s+', '', clean_target).rstrip(' *').strip()

                matched_sd = None
                for candidate in (clean_target, clean_type):
                    if candidate in struct_defs:
                        matched_sd = struct_defs[candidate]
                        break
                    elif f"struct {candidate}" in struct_defs:
                        matched_sd = struct_defs[f"struct {candidate}"]
                        break
                    elif f"union {candidate}" in struct_defs:
                        matched_sd = struct_defs[f"union {candidate}"]
                        break

                if matched_sd:
                    field.is_struct_or_union = True
                    field.nested_tag = matched_sd.name
                    field.is_union = matched_sd.is_union

        return struct_defs

    def _extract_unsigned_typedefs(self, clean_code: str, target_set: Set[str]) -> None:
        """
        Extracts custom unsigned typedef names from comment-stripped source code,
        supporting single and multi-declarator typedef statements as well as pointer declarators.
        """
        typedef_stmt_regex = re.compile(r'\btypedef\s+([^;]+);', re.MULTILINE)
        for match in typedef_stmt_regex.finditer(clean_code):
            stmt_body = match.group(1).strip()
            if not stmt_body:
                continue

            # Split on top-level commas (ignoring commas inside nested parentheses/brackets)
            tokens: List[str] = []
            current = []
            paren_depth = 0
            bracket_depth = 0
            for char in stmt_body:
                if char == '(':
                    paren_depth += 1
                elif char == ')':
                    paren_depth = max(0, paren_depth - 1)
                elif char == '[':
                    bracket_depth += 1
                elif char == ']':
                    bracket_depth = max(0, bracket_depth - 1)

                if char == ',' and paren_depth == 0 and bracket_depth == 0:
                    tokens.append(''.join(current).strip())
                    current = []
                else:
                    current.append(char)
            if current:
                tokens.append(''.join(current).strip())

            if not tokens:
                continue

            # First token contains the base type and the first declarator
            first_part = tokens[0]
            # Match base type and declarator identifier
            # e.g. "unsigned int u32", "unsigned int *pu32", "uint8_t (*func_ptr)(int)"
            m_fn_ptr = re.search(r'^(.*?)\(\s*\*\s*([a-zA-Z_]\w*)\s*\)\s*\(.*?\)$', first_part)
            if m_fn_ptr:
                base_type = m_fn_ptr.group(1).strip()
                alias = m_fn_ptr.group(2).strip()
                if is_unsigned_type(base_type, target_set):
                    target_set.add(alias)
            else:
                m_decl = re.search(r'^(.*?)\b([a-zA-Z_]\w*)\s*(?:\[[^\]]*\])?$', first_part)
                if m_decl:
                    base_type = m_decl.group(1).strip()
                    first_alias = m_decl.group(2).strip()
                    if is_unsigned_type(base_type, target_set):
                        target_set.add(first_alias)

                        # Subsequent tokens in multi-declarator typedef share the same base_type
                        for sub_tok in tokens[1:]:
                            m_sub_fn = re.search(r'\(\s*\*\s*([a-zA-Z_]\w*)\s*\)', sub_tok)
                            if m_sub_fn:
                                target_set.add(m_sub_fn.group(1).strip())
                            else:
                                m_sub = re.search(r'\b([a-zA-Z_]\w*)\s*(?:\[[^\]]*\])?$', sub_tok)
                                if m_sub:
                                    target_set.add(m_sub.group(1).strip())

    @staticmethod
    def strip_only(source_code: str) -> Tuple[List[str], str]:
        """
        Cheap path used by the engine in REGEX-only mode: just returns
        comment-stripped lines/code without the (much more expensive)
        function/variable extraction or pycparser attempt.
        """
        return strip_comments_keep_lines(source_code)

    def _try_pycparser(self, clean_code: str, defined_syms: Optional[Any] = None):
        """
        Attempts a real pycparser parse of the (comment-stripped) source.

        Three-tier strategy:

        1. **pcpp + pycparser** (best): Use pcpp to expand #define macros
           and evaluate #ifdef conditionals, then parse with pycparser.
           This handles the common case of macro-dependent code.

        2. **Strip directives + pycparser** (good): If pcpp is unavailable
           or its output still fails to parse, fall back to the original
           approach of stripping preprocessor directives and injecting a
           typedef prelude.

        3. **Regex extractor** (fallback): If pycparser is not installed
           or both tiers above fail, return None and let the caller use
           the regex-based function/variable extractor.
        """
        try:
            from pycparser import c_parser
        except ImportError:
            return None, False, ParseTier.REGEX_FALLBACK.value

        # Tier 1: pcpp preprocessing (if available)
        pcpp_result = self._try_pcpp_preprocess(clean_code, defined_syms=defined_syms)
        if pcpp_result is not None:
            try:
                parser = c_parser.CParser()
                pycparser_ast = parser.parse(pcpp_result, filename='<input>')
                return pycparser_ast, True, ParseTier.PCPP_PYCPARSER.value
            except Exception:
                pass  # Fall through to tier 2

        # Tier 2: Conditional resolution + Directive stripping + typedef prelude
        resolved_code = resolve_preprocessor_conditionals(clean_code, defined_syms=defined_syms)
        directive_stripped_lines = [
            "" if line.lstrip().startswith("#") else line
            for line in resolved_code.splitlines()
        ]
        directive_stripped_code = "\n".join(directive_stripped_lines)
        if resolved_code.endswith("\n") and not directive_stripped_code.endswith("\n"):
            directive_stripped_code += "\n"
        stripped_code = _strip_attributes_and_specifiers(directive_stripped_code)
        filtered_prelude = self._filter_prelude(_PYCPARSER_PRELUDE, stripped_code)
        prepared = filtered_prelude + stripped_code

        try:
            parser = c_parser.CParser()
            pycparser_ast = parser.parse(prepared, filename='<input>')
            return pycparser_ast, True, ParseTier.DIRECTIVE_STRIPPED.value
        except Exception:
            return None, False, ParseTier.REGEX_FALLBACK.value

    def _filter_prelude(self, prelude_text: str, code_text: str) -> str:
        """Filters out typedefs from the prelude that are explicitly re-declared in code_text."""
        filtered = []
        for line in prelude_text.splitlines(keepends=True):
            line_s = line.strip()
            if line_s.startswith('typedef '):
                parts = line_s.rstrip(';\n').split()
                if len(parts) >= 3:
                    name = parts[-1]
                    if re.search(r'\btypedef\s+[^;]*\b' + re.escape(name) + r'\b\s*;', code_text):
                        filtered.append('\n' if line.endswith('\n') else '')
                        continue
            filtered.append(line)
        return ''.join(filtered)

    def _try_pcpp_preprocess(self, clean_code: str, defined_syms: Optional[Any] = None) -> "Optional[str]":
        """
        Uses pcpp (pure-Python C preprocessor) to expand macros and
        evaluate conditional compilation directives, producing output
        that pycparser can parse.

        Returns the preprocessed source with the typedef prelude
        prepended, or None if pcpp is not installed or preprocessing
        fails.

        Line-number preservation: pcpp emits ``#line N`` directives.
        We convert those back into the appropriate number of blank
        lines so that pycparser's reported line numbers (minus the
        prelude offset) still map to original source lines.
        """
        try:
            import pcpp
        except ImportError:
            return None

        import io
        import re

        class _SilentPreprocessor(pcpp.Preprocessor):
            """Suppresses errors, passes through unresolvable #includes, and syncs #line directives on drift."""
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.line_directive = '#line'

            def on_error(self, file, line, msg):
                pass

            def on_include_not_found(self, is_malformed, is_system_include,
                                     curdir, includepath):
                raise pcpp.OutputDirective(pcpp.Action.IgnoreAndPassThrough)

            def write(self, oh=None):
                """Custom write loop based on pcpp.Preprocessor.write (pcpp v1.30) that forces

                emitting a #line directive whenever lineno drifts (e.g. multi-line macro calls).
                """
                if oh is None:
                    import sys
                    oh = sys.stdout
                lastlineno = 0
                lastsource = None
                done = False
                blanklines = 0
                while not done:
                    emitlinedirective = False
                    toks = []
                    all_ws = True
                    while not done:
                        tok = self.token()
                        if not tok:
                            done = True
                            break
                        toks.append(tok)
                        if tok.value and tok.value[0] == '\n':
                            break
                        if tok.type not in self.t_WS:
                            all_ws = False
                    if not toks:
                        break
                    if all_ws:
                        if len(toks) > 1:
                            tok = toks[-1]
                            toks = [tok]
                        blanklines += toks[0].value.count('\n')
                        continue
                    for n in range(len(toks) - 1, -1, -1):
                        if self.t_LINECONT is not None and toks[n].type == self.t_LINECONT:
                            if n > 0 and n < len(toks) - 2 and toks[n - 1].type in self.t_WS and toks[n + 1].type in self.t_WS:
                                if self.t_LINECONT is None or toks[n - 1].type != self.t_LINECONT:
                                    toks[n - 1].value = toks[n - 1].value[0]
                                    del toks[n:n + 2]
                            else:
                                del toks[n]
                    emitlinedirective = (blanklines > 6) and self.line_directive is not None
                    if hasattr(toks[0], 'source'):
                        if lastsource is None:
                            if toks[0].source is not None:
                                emitlinedirective = True
                            lastsource = toks[0].source
                        elif lastsource != toks[0].source:
                            emitlinedirective = True
                            lastsource = toks[0].source
                    first_ws = None
                    for n in range(len(toks) - 1, -1, -1):
                        tok = toks[n]
                        if first_ws is None:
                            if (self.t_SPACE is not None and tok.type == self.t_SPACE) or len(tok.value) == 0:
                                first_ws = n
                        else:
                            if (self.t_SPACE is None or tok.type != self.t_SPACE) and len(tok.value) > 0:
                                m = n + 1
                                while m != first_ws:
                                    del toks[m]
                                    first_ws -= 1
                                first_ws = None
                                if self.compress > 0:
                                    if toks[m].value and toks[m].value[0] == ' ':
                                        toks[m].value = ' '
                    if toks[0].lineno != lastlineno + 1:
                        emitlinedirective = True
                    lastlineno = toks[0].lineno
                    if emitlinedirective and self.line_directive is not None:
                        oh.write(self.line_directive + ' ' + str(lastlineno) + ('' if lastsource is None else (' "' + lastsource + '"')) + '\n')
                    for tok in toks:
                        if tok.type == self.t_COMMENT1:
                            lastlineno += tok.value.count('\n')
                    blanklines = 0
                    for tok in toks:
                        oh.write(tok.value)

        try:
            preprocessor = _SilentPreprocessor()
            if defined_syms:
                if isinstance(defined_syms, (set, list, tuple, frozenset)):
                    for s in defined_syms:
                        item = str(s).strip()
                        if " " in item:
                            preprocessor.define(item)
                        else:
                            preprocessor.define(f"{item} 1")
                elif isinstance(defined_syms, (dict, Mapping)):
                    for k, v in defined_syms.items():
                        key = str(k)
                        if v is False:
                            preprocessor.undef(key)
                    norm_macros = _normalize_macro_dict(defined_syms)
                    for k, v in norm_macros.items():
                        preprocessor.define(f"{k} {v}")
                else:
                    norm_macros = _normalize_macro_dict(defined_syms)
                    for k, v in norm_macros.items():
                        preprocessor.define(f"{k} {v}")

            # Feed the typedef prelude + source as a single unit so that
            # macros defined in the source are expanded while the prelude
            # typedefs are preserved for pycparser.
            filtered_prelude = self._filter_prelude(_PYCPARSER_PRELUDE, clean_code)
            combined = filtered_prelude + clean_code
            preprocessor.parse(combined, '<input>')
            out = io.StringIO()
            preprocessor.write(out)
            raw = out.getvalue()

            # Reconstruct line-preserving output: convert #line N
            # directives into blank-line padding so that line numbers
            # in the output correspond to line numbers in `combined`.
            line_dir_re = re.compile(r'^#line\s+(\d+)')
            output_lines: list = []
            current_line = 1
            for line in raw.splitlines():
                m = line_dir_re.match(line)
                if m:
                    target_line = int(m.group(1))
                    while current_line < target_line:
                        output_lines.append('')
                        current_line += 1
                else:
                    output_lines.append(line)
                    current_line += 1

            result = '\n'.join(output_lines)

            # Strip any remaining #include lines that pcpp passed through
            # (unresolvable includes) -- pycparser can't handle them.
            result = '\n'.join(
                '' if _PREPROCESSOR_LINE_RE.match(ln) else ln
                for ln in result.splitlines()
            )
            result = _strip_attributes_and_specifiers(result)

            return result
        except Exception:
            return None

    def _build_model_from_ast(
        self, pycparser_ast, clean_lines: List[str], clean_code: str, custom_typedefs: Optional[Set[str]] = None, line_map: Optional[Dict[int, Any]] = None
    ) -> Tuple[List[CFunction], Dict[str, CVariable]]:
        """
        Builds the authoritative structural representation (functions, parameters,
        local/global variables, symbols, types, scopes, CFG, and dataflow)
        directly from a pycparser AST.
        """
        from pycparser import c_ast

        functions: List[CFunction] = []
        global_vars: Dict[str, CVariable] = {}

        for ext in pycparser_ast.ext:
            if isinstance(ext, c_ast.Typedef) and custom_typedefs is not None:
                tname, _, _, _, is_sig, _, _, _ = _format_pycparser_type(ext.type, custom_typedefs)
                if not is_sig and ext.name:
                    custom_typedefs.add(ext.name)
            elif isinstance(ext, c_ast.Decl) and type(ext.type).__name__ != "FuncDecl" and type(ext).__name__ != "Typedef":
                exp_line = (ext.coord.line - _PRELUDE_LINE_COUNT) if ext.coord else 1
                line_no = _map_line(exp_line, line_map)
                tname, is_ptr, is_fp, is_vol, is_sig, is_vla, arr_dim, is_arr = _format_pycparser_type(ext.type, custom_typedefs)
                shape = resolve_typedef_shape(tname, self.typedef_shapes) if hasattr(self, "typedef_shapes") and self.typedef_shapes else None
                v_is_array = is_arr or (shape.is_array if shape else False)
                v_is_pointer = (is_ptr or is_fp) or (shape.is_pointer if shape else False)
                v_arr_dim = arr_dim if arr_dim is not None else (str(shape.array_size) if shape and shape.array_size is not None else None)
                if ext.name and ext.name not in ('typedef', '#include', '#define', '#ifdef', '#ifndef'):
                    global_vars[ext.name] = CVariable(
                        name=ext.name,
                        type_name=tname,
                        is_pointer=v_is_pointer,
                        is_signed=is_sig,
                        is_volatile=is_vol,
                        is_vla=is_vla,
                        array_size_expr=v_arr_dim,
                        has_initializer=(ext.init is not None),
                        declaration_line=line_no,
                        is_array=v_is_array,
                    )

            elif isinstance(ext, c_ast.FuncDef):
                fname = ext.decl.name
                fn_start_exp = (ext.decl.coord.line - _PRELUDE_LINE_COUNT) if ext.decl.coord else 1
                fn_start = _map_line(fn_start_exp, line_map)

                ret_t, _, _, _, _, _, _, _ = _format_pycparser_type(ext.decl.type.type, custom_typedefs)

                params: List[CParameter] = []
                has_void_param = False
                is_empty_params = False
                func_args = ext.decl.type.args

                if func_args is None or not getattr(func_args, "params", None):
                    is_empty_params = True
                else:
                    if len(func_args.params) == 1:
                        p0 = func_args.params[0]
                        if hasattr(p0, "type"):
                            p0_type, _, _, _, _, _, _, _ = _format_pycparser_type(p0.type, custom_typedefs)
                            if p0_type == "void" and (not getattr(p0, "name", None) or p0.name == "void"):
                                has_void_param = True

                    if not has_void_param:
                        for param in func_args.params:
                            if type(param).__name__ == "EllipsisParam" or not hasattr(param, "type"):
                                continue
                            p_name = getattr(param, "name", None) or ""
                            p_type, p_is_ptr, p_is_fp, _, _, _, _, p_is_arr = _format_pycparser_type(param.type, custom_typedefs)
                            p_line_exp = (param.coord.line - _PRELUDE_LINE_COUNT) if param.coord else fn_start_exp
                            p_line = _map_line(p_line_exp, line_map)
                            p_shape = resolve_typedef_shape(p_type, self.typedef_shapes) if hasattr(self, "typedef_shapes") and self.typedef_shapes else None
                            p_is_array = p_is_arr or (p_shape.is_array if p_shape else False)
                            p_is_pointer = p_is_ptr or p_is_fp or (p_shape.is_pointer if p_shape else False)
                            params.append(CParameter(
                                name=p_name,
                                type_name=p_type,
                                is_pointer=p_is_pointer,
                                line_number=p_line,
                                is_array=p_is_array,
                            ))

                fn_end_exp = _get_max_ast_line(ext.body, fn_start_exp, _PRELUDE_LINE_COUNT)
                brace_count = 0
                for l in range(fn_start_exp, len(clean_lines) + 1):
                    line_str = clean_lines[l - 1]
                    brace_count += line_str.count("{") - line_str.count("}")
                    if l >= fn_end_exp and brace_count <= 0:
                        fn_end_exp = l
                        break

                fn_end = _map_line(fn_end_exp, line_map)
                fn_body = "\n".join(clean_lines[fn_start_exp: max(fn_start_exp, fn_end_exp - 1)]) if fn_start_exp < fn_end_exp else ""
                body_start_line = _map_line(fn_start_exp + 1 if fn_start_exp < fn_end_exp else fn_start_exp, line_map)

                fn = CFunction(
                    name=fname,
                    return_type=ret_t,
                    parameters=params,
                    start_line=fn_start,
                    end_line=fn_end,
                    body=fn_body,
                    has_void_param_list=has_void_param,
                    is_empty_param_list=is_empty_params,
                    body_start_line=body_start_line,
                    start_line_exp=fn_start_exp,
                    end_line_exp=fn_end_exp,
                )

                if ext.body:
                    _ASTFunctionAnalyzer(fn, _PRELUDE_LINE_COUNT, clean_lines, custom_typedefs, typedef_shapes=self.typedef_shapes, line_map=line_map).analyze(ext.body)

                functions.append(fn)

        return functions, global_vars

    def _extract_functions(self, lines: List[str], full_code: str, custom_typedefs: Optional[Set[str]] = None, line_map: Optional[Dict[int, Any]] = None) -> List[CFunction]:
        functions: List[CFunction] = []
        # Pattern to match C function header: return_type func_name(params) {
        # e.g., int auth_user(char *user, const char *pass)
        func_header_regex = re.compile(
            r'^[ \t]*((?:(?:static|inline|extern|const|unsigned|signed|struct\s+\w+|\w+)\s+)+)(\*?\s*[\w_]+)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )

        for match in func_header_regex.finditer(full_code):
            start_pos = match.start()
            start_line_exp = full_code[:start_pos].count('\n') + 1
            start_line = _map_line(start_line_exp, line_map)

            ret_type = match.group(1).strip()
            raw_name = match.group(2).strip()
            params_str = match.group(3).strip()

            if raw_name.startswith('*'):
                ret_type += ' *'
                func_name = raw_name[1:].strip()
            else:
                func_name = raw_name

            # Skip control structures masquerading as functions if any (e.g. if/while)
            if func_name in ('if', 'for', 'while', 'switch', 'catch'):
                continue

            # Find matching closing brace
            brace_count = 1
            body_start_pos = match.end()
            curr_pos = body_start_pos
            n = len(full_code)

            while curr_pos < n and brace_count > 0:
                ch = full_code[curr_pos]
                if ch == '{':
                    brace_count += 1
                elif ch == '}':
                    brace_count -= 1
                curr_pos += 1

            end_line_exp = full_code[:curr_pos].count('\n') + 1
            end_line = _map_line(end_line_exp, line_map)
            body = full_code[body_start_pos:curr_pos - 1]
            body_start_line_exp = full_code[:body_start_pos].count('\n') + 1
            body_start_line = _map_line(body_start_line_exp, line_map)

            # Parse parameters
            params: List[CParameter] = []
            is_empty_params = (params_str == "")
            has_void_param = (params_str == "void")

            if params_str and params_str != "void":
                for param_token in params_str.split(','):
                    param_token = param_token.strip()
                    if not param_token:
                        continue
                    is_ptr = '*' in param_token
                    p_parts = param_token.replace('*', ' * ').split()
                    if len(p_parts) >= 2:
                        p_name = p_parts[-1]
                        p_type = " ".join(p_parts[:-1])
                    elif len(p_parts) == 1:
                        p_name = p_parts[0]
                        p_type = "int"
                    else:
                        continue

                    p_is_arr = False
                    m_p_arr = re.match(r'^([a-zA-Z_]\w*)\s*(\[[^\]]*\])$', p_name)
                    if m_p_arr:
                        p_name = m_p_arr.group(1)
                        p_type = f"{p_type}{m_p_arr.group(2)}"
                        p_is_arr = True

                    if '[' in p_type:
                        p_is_arr = True

                    params.append(CParameter(name=p_name, type_name=p_type, is_pointer=is_ptr, line_number=start_line, is_array=p_is_arr))

            fn = CFunction(
                name=func_name,
                return_type=ret_type,
                parameters=params,
                start_line=start_line,
                end_line=end_line,
                body=body,
                has_void_param_list=has_void_param,
                is_empty_param_list=is_empty_params,
                body_start_line=body_start_line,
                start_line_exp=start_line_exp,
                end_line_exp=end_line_exp,
            )

            # Analyze function body variables & calls
            self._analyze_function_body(fn, lines, custom_typedefs, line_map=line_map)
            functions.append(fn)

        return functions

    def _analyze_function_body(self, fn: CFunction, all_lines: List[str], custom_typedefs: Optional[Set[str]] = None, line_map: Optional[Dict[int, Any]] = None) -> None:
        body_lines = fn.body.splitlines()
        fn_start_exp = fn.start_line_exp or fn.start_line

        # Detect assertions
        if "assert(" in fn.body or "ASSERT(" in fn.body or "assert_param(" in fn.body:
            fn.has_assertions = True

        # Detect boolean return in security context
        if re.search(r'\breturn\s+(?:0|1|true|false)\s*;', fn.body):
            if any(term in fn.name.lower() for term in ['auth', 'verify', 'check_password', 'validate_token', 'boot_secure', 'crypto', 'admin', 'login', 'permission']):
                fn.returns_boolean = True

        # Extract function calls inside body
        # We parse the full body string to handle multiline arguments and nested parentheses
        call_regex = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')
        for m in call_regex.finditer(fn.body):
            callee = m.group(1)
            if callee not in ('if', 'for', 'while', 'switch', 'sizeof', 'typeof', '__attribute__'):
                # Match balanced parens to get args
                args_start = m.end() - 1
                paren_depth = 0
                in_string = False
                in_char = False
                escape = False
                j = args_start
                n = len(fn.body)
                while j < n:
                    c = fn.body[j]
                    if escape:
                        escape = False
                    elif c == '\\':
                        escape = True
                    elif c == '"' and not in_char:
                        in_string = not in_string
                    elif c == "'" and not in_string:
                        in_char = not in_char
                    elif not in_string and not in_char:
                        if c == '(':
                            paren_depth += 1
                        elif c == ')':
                            paren_depth -= 1
                            if paren_depth == 0:
                                break
                    j += 1

                if j < n:
                    args = fn.body[args_start + 1 : j]
                    # Calc line number
                    prefix = fn.body[:m.start()]
                    exp_line = fn_start_exp + prefix.count('\n')
                    line_no = _map_line(exp_line, line_map)

                    target_var = None
                    stmt_prefix_match = re.search(r'(?:^|[;{}])\s*([^;{}]+)\s*=\s*[^;{}]*$', prefix)
                    if stmt_prefix_match:
                        m_var = re.search(r'\b([a-zA-Z_]\w*)\s*(?:\[[^\]]*\])?$', stmt_prefix_match.group(1))
                        if m_var:
                            target_var = m_var.group(1)

                    fn.calls.append((callee, line_no, args, target_var))

        C_KEYWORDS = {
            'return', 'break', 'continue', 'goto', 'case', 'default', 'if', 'else', 'for', 'while',
            'switch', 'sizeof', 'typeof', 'typedef', 'struct', 'union', 'enum', 'extern', 'static',
            'const', 'volatile', 'register', 'inline', 'restrict', '0', '1', 'NULL'
        }

        # Track local variable declarations and block scope hierarchy
        var_decl_regex = re.compile(
            r'^[ \t]*((?:volatile\s+|static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*|\w|\s)*?)\s*([a-zA-Z_]\w*)(?:\[([^\]]*)\])?(?:\s*=\s*([^;]+))?;'
        )
        ptr_arr_decl_regex = re.compile(
            r'^[ \t]*((?:volatile\s+|static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+)\(\s*\*\s*([a-zA-Z_]\w*)\s*\)(?:\[([^\]]*)\])?(?:\s*=\s*([^;]+))?;'
        )
        block_counter = 0
        scope_stack = [0]
        block_parents = {}

        for i, line in enumerate(body_lines):
            exp_line = fn_start_exp + i
            line_no = _map_line(exp_line, line_map)
            masked_line = mask_string_and_char_literals(line)
            m = var_decl_regex.match(line)
            m_parr = ptr_arr_decl_regex.match(line) if not m else None
            m_target = m or m_parr
            decl_start = m_target.start() if m_target else len(line)

            for pos, char in enumerate(masked_line):
                if pos == decl_start and m_target:
                    type_prefix = m_target.group(1).strip()
                    v_name = m_target.group(2).strip()
                    array_dim = m_target.group(3)
                    init_val = m_target.group(4)

                    if v_name not in C_KEYWORDS and v_name.isidentifier():
                        type_tokens = type_prefix.split()
                        if not (type_tokens and type_tokens[-1] in _STATEMENT_KEYWORDS):
                            is_ptr = '*' in type_prefix or '*' in v_name or (m_parr is not None)
                            is_signed = not is_unsigned_type(type_prefix, custom_typedefs)
                            is_volatile = 'volatile' in type_prefix
                            is_vla = False
                            if array_dim is not None:
                                dim_clean = array_dim.strip()
                                if dim_clean and not dim_clean.isdigit() and not dim_clean.isupper() and not dim_clean.startswith('0x'):
                                    is_vla = True

                            curr_block = scope_stack[-1]
                            shape = resolve_typedef_shape(type_prefix, self.typedef_shapes) if hasattr(self, "typedef_shapes") and self.typedef_shapes else None
                            v_is_array = (array_dim is not None) or (shape.is_array if shape else False)
                            v_is_pointer = is_ptr or (shape.is_pointer if shape else False)
                            v_arr_dim = array_dim if array_dim is not None else (str(shape.array_size) if shape and shape.array_size is not None else None)
                            c_var = CVariable(
                                name=v_name,
                                type_name=type_prefix,
                                is_pointer=v_is_pointer,
                                is_signed=is_signed,
                                is_volatile=is_volatile,
                                is_vla=is_vla,
                                array_size_expr=v_arr_dim,
                                has_initializer=(init_val is not None),
                                declaration_line=line_no,
                                is_array=v_is_array,
                                enclosing_block_id=curr_block,
                            )
                            if init_val:
                                c_var.assigned_lines.append(line_no)
                            fn.variables[(v_name, curr_block)] = c_var

                if char == '{':
                    block_counter += 1
                    parent_id = scope_stack[-1]
                    block_parents[block_counter] = parent_id
                    scope_stack.append(block_counter)
                elif char == '}':
                    if len(scope_stack) > 1:
                        scope_stack.pop()

        fn.block_parents = block_parents

        # Track variable life cycles (free, null-checks, reads, assignments, address-taking)
        assign_regex = re.compile(r'^\s*([a-zA-Z_]\w*)\s*(?:\[[^\]]*\]|\.\w+|->\w+)*\s*=(?!=)')
        for i, line in enumerate(body_lines):
            exp_line = fn_start_exp + i
            line_no = _map_line(exp_line, line_map)
            m_assign = assign_regex.match(line)
            if m_assign:
                v_name = m_assign.group(1)
                if v_name in fn.variables:
                    if line_no not in fn.variables[v_name].assigned_lines:
                        fn.variables[v_name].assigned_lines.append(line_no)

            # free(x)
            free_match = re.search(r'\bfree\s*\(\s*(\w+)\s*\)', line)
            if free_match:
                v_name = free_match.group(1)
                if v_name in fn.variables:
                    fn.variables[v_name].freed_lines.append(line_no)

            # if (x == NULL) or if (!x) or if (x != NULL)
            for v_name in list(fn.variables.keys()) + [p.name for p in fn.parameters]:
                if re.search(rf'\bif\s*\([^)]*?\b{re.escape(v_name)}\s*(?:==\s*NULL|!=\s*NULL|==\s*0|!=\s*0)\b', line) or \
                   re.search(rf'\bif\s*\(\s*!{re.escape(v_name)}\b', line) or \
                   re.search(rf'\bif\s*\(\s*{re.escape(v_name)}\s*\)', line):
                    if v_name in fn.variables:
                        fn.variables[v_name].checked_null_lines.append(line_no)

            # Check address-taking & reads for local variables in fallback mode
            for v_name, c_var in fn.variables.items():
                if not v_name or v_name in C_KEYWORDS:
                    continue

                # Address-taken check: &v_name
                if re.search(rf'&\s*\b{re.escape(v_name)}\b', line):
                    c_var.address_taken = True
                    if line_no not in c_var.address_taken_lines:
                        c_var.address_taken_lines.append(line_no)

                # Read check:
                if re.search(rf'\b{re.escape(v_name)}\b', line):
                    is_read = False
                    # 1. Declaration line: read if v_name appears in initializer / RHS or multiple times on decl line
                    if line_no == c_var.declaration_line:
                        if '=' in line:
                            rhs = line.split('=', 1)[1]
                            if re.search(rf'\b{re.escape(v_name)}\b', rhs):
                                is_read = True
                        # Check if v_name appears > 1 times on declaration line
                        if len(re.findall(rf'\b{re.escape(v_name)}\b', line)) > 1:
                            is_read = True
                    else:
                        # 2. Compound assignment / inc / dec on v_name
                        if re.search(rf'\b{re.escape(v_name)}\s*(?:\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=)', line) or \
                           re.search(rf'(?:\+\+|--)\s*\b{re.escape(v_name)}\b', line):
                            is_read = True
                        else:
                            # 3. Pure LHS assignment v_name = ...
                            m_pure_assign = re.match(rf'^\s*{re.escape(v_name)}\s*=(?!=)\s*(.*)$', line)
                            if m_pure_assign:
                                rhs = m_pure_assign.group(1)
                                if re.search(rf'\b{re.escape(v_name)}\b', rhs):
                                    is_read = True
                            else:
                                is_read = True

                    if is_read and line_no not in c_var.read_lines:
                        c_var.read_lines.append(line_no)

    def _extract_global_vars(self, lines: List[str], functions: List[CFunction], custom_typedefs: Optional[Set[str]] = None, line_map: Optional[Dict[int, Any]] = None) -> Dict[str, CVariable]:
        global_vars: Dict[str, CVariable] = {}
        func_line_ranges = set()
        for fn in functions:
            start_exp = fn.start_line_exp or fn.start_line
            end_exp = fn.end_line_exp or fn.end_line
            for l in range(start_exp, end_exp + 1):
                func_line_ranges.add(l)

        var_decl_regex = re.compile(
            r'^[ \t]*((?:volatile\s+|static\s+|const\s+|unsigned\s+|signed\s+|struct\s+\w+|\w+)\s+(?:\*|\w|\s)*?)\s*(\w+)(?:\[([^\]]*)\])?(?:\s*=\s*([^;]+))?;'
        )

        for line_no_exp, line in enumerate(lines, 1):
            if line_no_exp in func_line_ranges:
                continue
            line_no = _map_line(line_no_exp, line_map)
            m = var_decl_regex.match(line)
            if m:
                type_prefix = m.group(1).strip()
                v_name = m.group(2).strip()
                type_tokens = type_prefix.split()
                if type_tokens and type_tokens[-1] in _STATEMENT_KEYWORDS:
                    continue
                if v_name not in ('typedef', '#include', '#define', '#ifdef', '#ifndef'):
                    shape = resolve_typedef_shape(type_prefix, self.typedef_shapes) if hasattr(self, "typedef_shapes") and self.typedef_shapes else None
                    v_is_array = (m.group(3) is not None) or (shape.is_array if shape else False)
                    v_is_pointer = ('*' in type_prefix) or (shape.is_pointer if shape else False)
                    v_arr_dim = m.group(3) if m.group(3) is not None else (str(shape.array_size) if shape and shape.array_size is not None else None)
                    global_vars[v_name] = CVariable(
                        name=v_name,
                        type_name=type_prefix,
                        is_pointer=v_is_pointer,
                        is_signed=not is_unsigned_type(type_prefix, custom_typedefs),
                        is_volatile='volatile' in type_prefix,
                        is_vla=False,
                        array_size_expr=v_arr_dim,
                        has_initializer=m.group(4) is not None,
                        declaration_line=line_no,
                        is_array=v_is_array,
                    )
        return global_vars


# Alias for backward compatibility
ASTAnalyzer = CASTParser
