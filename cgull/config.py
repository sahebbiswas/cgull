"""
Configuration file handling and auto-discovery for C-GULL Static Analyzer.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore

from .models import Severity, ScanMode
from .semantic_models import (
    EMPTY_SEMANTIC_MODELS,
    SemanticModelConfigError,
    SemanticModelRegistry,
    parse_semantic_models,
)
import logging
from .rules import BaseRule

logger = logging.getLogger(__name__)



@dataclass
class CGullConfig:
    schema_version: int = 1
    skipped_rules: Dict[str, str] = field(default_factory=dict)  # rule_id -> justification
    severity_overrides: Dict[str, Severity] = field(default_factory=dict)  # rule_id -> Severity
    alloc_funcs: List[str] = field(default_factory=list)
    realloc_funcs: List[str] = field(default_factory=list)
    dealloc_funcs: List[str] = field(default_factory=list)
    banned_funcs: Dict[str, Dict[str, str]] = field(default_factory=dict)  # fn_name -> {"reason": ..., "remediation": ...}
    semantic_models: SemanticModelRegistry = field(default_factory=lambda: EMPTY_SEMANTIC_MODELS)
    exclude_paths: List[str] = field(default_factory=list)
    include_roots: List[str] = field(default_factory=list)
    mode: Optional[ScanMode] = None
    default_format: Optional[str] = None
    fail_on: Optional[str] = None
    warn_on_fallback: bool = False
    warnings: List[str] = field(default_factory=list)
    config_file_path: Optional[str] = None
    config_dir: Optional[str] = None
    error: Optional[str] = None

    def apply_to_rules(self, rules: List[BaseRule]) -> List[BaseRule]:
        """
        Filters skipped rules, applies severity overrides, and sets extra function synonyms.
        """
        filtered_rules: List[BaseRule] = []

        for rule in rules:
            if rule.rule_id in self.skipped_rules:
                continue

            # Apply severity override if configured
            if rule.rule_id in self.severity_overrides:
                rule.impact = self.severity_overrides[rule.rule_id]

            # Apply function synonyms to rule instances
            if hasattr(rule, "add_extra_banned_funcs") and self.banned_funcs:
                rule.add_extra_banned_funcs(self.banned_funcs)

            if hasattr(rule, "add_extra_alloc_funcs") and self.alloc_funcs:
                rule.add_extra_alloc_funcs(self.alloc_funcs)

            if hasattr(rule, "add_extra_realloc_funcs") and self.realloc_funcs:
                rule.add_extra_realloc_funcs(self.realloc_funcs)

            if hasattr(rule, "add_extra_dealloc_funcs") and self.dealloc_funcs:
                rule.add_extra_dealloc_funcs(self.dealloc_funcs)

            filtered_rules.append(rule)

        return filtered_rules

    def get_resolved_exclude_paths(self, base_dir: str) -> List[str]:
        """
        Resolves exclude_paths relative to base_dir while preserving config-dir
        project semantics.
        """
        if not self.exclude_paths:
            return []

        if not self.config_dir:
            return list(self.exclude_paths)

        abs_base = os.path.abspath(base_dir)
        abs_cfg_dir = os.path.abspath(self.config_dir)

        if abs_base == abs_cfg_dir:
            return list(self.exclude_paths)

        # Calculate relative path from config_dir to base_dir
        try:
            rel_prefix = os.path.relpath(abs_base, abs_cfg_dir).replace("\\", "/")
        except ValueError:
            return list(self.exclude_paths)

        if rel_prefix.startswith(".."):
            return list(self.exclude_paths)

        resolved: List[str] = []
        for pat in self.exclude_paths:
            clean_pat = pat.strip()
            # If unanchored (no internal slashes or only trailing slash)
            anchored = clean_pat.startswith("/") or "/" in clean_pat.rstrip("/")
            if not anchored:
                resolved.append(clean_pat)
                continue

            stripped = clean_pat.lstrip("/")
            if stripped.startswith(rel_prefix + "/"):
                resolved.append(stripped[len(rel_prefix) + 1:])
            elif not anchored:
                resolved.append(clean_pat)

        return resolved


def find_config_file(target_path: str) -> Optional[str]:
    """
    Auto-discovers .cgull.toml or pyproject.toml [tool.cgull] starting from
    target_path and searching upward to the root directory.

    .cgull.toml takes precedence over pyproject.toml in the same directory.
    """
    abs_target = os.path.abspath(target_path)
    curr_dir = abs_target if os.path.isdir(abs_target) else os.path.dirname(abs_target)

    while True:
        # Check .cgull.toml
        standalone = os.path.join(curr_dir, ".cgull.toml")
        if os.path.isfile(standalone):
            return standalone

        # Check pyproject.toml with [tool.cgull]
        pyproject = os.path.join(curr_dir, "pyproject.toml")
        if os.path.isfile(pyproject):
            try:
                with open(pyproject, "rb") as f:
                    data = tomllib.load(f)
                if "tool" in data and "cgull" in data["tool"]:
                    return pyproject
            except Exception:
                pass

        parent = os.path.dirname(curr_dir)
        if parent == curr_dir:
            break
        curr_dir = parent

    return None


def parse_bool_val(val: Any) -> Optional[bool]:
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        if val == 1:
            return True
        if val == 0:
            return False
        return None
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("true", "1", "yes"):
            return True
        if v in ("false", "0", "no"):
            return False
        return None
    return None


def parse_severity_str(sev_str: str) -> Optional[Severity]:
    sev_map = {
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return sev_map.get(str(sev_str).strip().lower())


def load_config(config_path: Optional[str] = None, target_path: Optional[str] = None) -> CGullConfig:
    """
    Loads configuration from config_path or auto-discovers starting at target_path.
    Returns CGullConfig instance.
    """
    from .includes import IncludeResolver

    cfg = CGullConfig()
    explicit_path_provided = config_path is not None

    if not config_path and target_path:
        config_path = find_config_file(target_path)

    if explicit_path_provided and not os.path.exists(config_path):
        cfg.error = f"Configuration file '{config_path}' does not exist."
        return cfg

    raw_toml = {}
    if config_path and os.path.exists(config_path):
        cfg.config_file_path = config_path
        cfg.config_dir = os.path.dirname(os.path.abspath(config_path))
        try:
            with open(config_path, "rb") as f:
                raw_toml = tomllib.load(f)
        except Exception as e:
            cfg.error = f"Failed to parse TOML configuration file {config_path}: {e}"
            return cfg

        # If pyproject.toml, extract [tool.cgull]
        if os.path.basename(config_path) == "pyproject.toml":
            raw_toml = raw_toml.get("tool", {}).get("cgull", {})
            if not isinstance(raw_toml, dict):
                raw_toml = {}

    base_search_dir = cfg.config_dir or (os.path.abspath(target_path) if target_path else os.getcwd())
    if os.path.isfile(base_search_dir):
        base_search_dir = os.path.dirname(base_search_dir)

    inc_resolver = IncludeResolver(base_dir=base_search_dir, load_cgullincludes=False)

    if raw_toml:
        # Validate schema version
        if "schema_version" in raw_toml:
            try:
                cfg.schema_version = int(raw_toml["schema_version"])
            except (ValueError, TypeError):
                cfg.warnings.append(f"Invalid schema_version in {config_path}: expected integer")

        # Check top-level keys for unknown keys
        known_top_keys = {"schema_version", "rules", "functions", "paths", "output", "includes", "scan", "mode", "semantic_models"}
        for key in raw_toml.keys():
            if key not in known_top_keys:
                cfg.warnings.append(f"Unknown key/section '[{key}]' in configuration file {config_path}")

        # Semantic trust-boundary models fail closed: a malformed security model
        # is a configuration error, never a warning that silently disables it.
        try:
            cfg.semantic_models = parse_semantic_models(raw_toml.get("semantic_models", {}))
        except SemanticModelConfigError as exc:
            cfg.error = f"Invalid [semantic_models] configuration in {config_path}: {exc}"
            return cfg

        # Top-level mode or section [scan]
        if "mode" in raw_toml:
            m_val = str(raw_toml["mode"]).strip().lower()
            if m_val in ("file", "tu"):
                cfg.mode = ScanMode(m_val)
            else:
                cfg.warnings.append(f"Invalid mode '{m_val}' in {config_path}. Expected 'file' or 'tu'.")

        scan_sec = raw_toml.get("scan", {})
        if isinstance(scan_sec, dict) and "mode" in scan_sec:
            m_val = str(scan_sec["mode"]).strip().lower()
            if m_val in ("file", "tu"):
                cfg.mode = ScanMode(m_val)
            else:
                cfg.warnings.append(f"Invalid [scan].mode '{m_val}' in {config_path}. Expected 'file' or 'tu'.")

        # Section [rules]
        rules_sec = raw_toml.get("rules", {})
        if isinstance(rules_sec, dict):
            # rules.skip
            skip_raw = rules_sec.get("skip", {})
            if isinstance(skip_raw, dict):
                for r_id, reason in skip_raw.items():
                    cfg.skipped_rules[str(r_id).strip().upper()] = str(reason)
            elif isinstance(skip_raw, list):
                for r_id in skip_raw:
                    cfg.skipped_rules[str(r_id).strip().upper()] = "Disabled via configuration"

            # rules.severity
            sev_raw = rules_sec.get("severity", {})
            if isinstance(sev_raw, dict):
                for r_id, val in sev_raw.items():
                    sev_enum = parse_severity_str(val)
                    if sev_enum:
                        cfg.severity_overrides[str(r_id).strip().upper()] = sev_enum
                    else:
                        cfg.warnings.append(f"Invalid severity value '{val}' for rule {r_id} in {config_path}")

        # Section [functions]
        funcs_sec = raw_toml.get("functions", {})
        if isinstance(funcs_sec, dict):
            # functions.memory
            mem_sec = funcs_sec.get("memory", {})
            if isinstance(mem_sec, dict):
                for key_name, target_attr in [("alloc", "alloc_funcs"), ("realloc", "realloc_funcs"), ("dealloc", "dealloc_funcs")]:
                    func_list = mem_sec.get(key_name, [])
                    if isinstance(func_list, list):
                        cleaned_funcs = []
                        for fn in func_list:
                            fn_str = str(fn).strip()
                            if not fn_str.isidentifier():
                                cfg.error = f"Invalid C function identifier '{fn}' in [functions.memory].{key_name} in {config_path}."
                                return cfg
                            cleaned_funcs.append(fn_str)
                        setattr(cfg, target_attr, cleaned_funcs)

            # functions.banned
            banned_sec = funcs_sec.get("banned", {})
            if isinstance(banned_sec, dict):
                for fn_name, details in banned_sec.items():
                    fn_str = str(fn_name).strip()
                    if not fn_str.isidentifier():
                        cfg.error = f"Invalid C function identifier '{fn_name}' in [functions.banned] in {config_path}."
                        return cfg
                    if isinstance(details, dict):
                        reason = details.get("reason", f"Banned function call '{fn_str}'")
                        remediation = details.get("remediation", f"Avoid using {fn_str}()")
                        cfg.banned_funcs[fn_str] = {
                            "reason": str(reason),
                            "remediation": str(remediation),
                        }
                    elif isinstance(details, str):
                        cfg.banned_funcs[fn_str] = {
                            "reason": str(details),
                            "remediation": f"Avoid using {fn_str}()",
                        }

        # Section [paths]
        paths_sec = raw_toml.get("paths", {})
        if isinstance(paths_sec, dict):
            exclude_list = paths_sec.get("exclude", [])
            if isinstance(exclude_list, list):
                cfg.exclude_paths = [str(x) for x in exclude_list]
            inc_list = paths_sec.get("include_roots", [])
            if isinstance(inc_list, list):
                for x in inc_list:
                    inc_resolver.add_include_root(str(x), relative_to=base_search_dir)

        # Section [includes]
        includes_sec = raw_toml.get("includes", {})
        if isinstance(includes_sec, dict):
            inc_list = includes_sec.get("include_roots", includes_sec.get("roots", []))
            if isinstance(inc_list, list):
                for x in inc_list:
                    inc_resolver.add_include_root(str(x), relative_to=base_search_dir)

    # Load .cgullincludes if present in base_search_dir
    cgullinc_path = os.path.join(base_search_dir, ".cgullincludes")
    if os.path.isfile(cgullinc_path):
        inc_resolver.load_from_file(cgullinc_path)

    cfg.include_roots = list(inc_resolver.include_roots)

    # Section [output]
    output_sec = raw_toml.get("output", {})
    if isinstance(output_sec, dict):
        if "default_format" in output_sec:
            fmt_val = str(output_sec["default_format"]).strip().lower()
            if fmt_val in ("text", "json", "sarif", "markdown"):
                cfg.default_format = fmt_val
            else:
                cfg.warnings.append(f"Invalid default_format '{fmt_val}' in {config_path}")
        if "fail_on" in output_sec:
            fail_val = str(output_sec["fail_on"]).strip().lower()
            if fail_val in ("high", "medium", "low", "all"):
                cfg.fail_on = fail_val
            else:
                cfg.error = f"Invalid [output].fail_on value '{fail_val}' in {config_path}. Expected one of: high, medium, low, all."
                return cfg
        if "warn_on_fallback" in output_sec:
            raw_wof = output_sec["warn_on_fallback"]
            b_val = parse_bool_val(raw_wof)
            if b_val is not None:
                cfg.warn_on_fallback = b_val
            else:
                cfg.warnings.append(f"Invalid boolean value '{raw_wof}' for [output].warn_on_fallback in {config_path}")

    return cfg
