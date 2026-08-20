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

from .models import Severity
from .rules import BaseRule


@dataclass
class CGullConfig:
    schema_version: int = 1
    skipped_rules: Dict[str, str] = field(default_factory=dict)  # rule_id -> justification
    severity_overrides: Dict[str, Severity] = field(default_factory=dict)  # rule_id -> Severity
    alloc_funcs: List[str] = field(default_factory=list)
    realloc_funcs: List[str] = field(default_factory=list)
    dealloc_funcs: List[str] = field(default_factory=list)
    banned_funcs: Dict[str, Dict[str, str]] = field(default_factory=dict)  # fn_name -> {"reason": ..., "remediation": ...}
    exclude_paths: List[str] = field(default_factory=list)
    default_format: Optional[str] = None
    fail_on: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    config_file_path: Optional[str] = None

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
    cfg = CGullConfig()
    if not config_path and target_path:
        config_path = find_config_file(target_path)

    if not config_path or not os.path.exists(config_path):
        return cfg

    cfg.config_file_path = config_path

    try:
        with open(config_path, "rb") as f:
            raw_toml = tomllib.load(f)
    except Exception as e:
        cfg.warnings.append(f"Failed to parse TOML configuration file {config_path}: {e}")
        return cfg

    # If pyproject.toml, extract [tool.cgull]
    if os.path.basename(config_path) == "pyproject.toml":
        raw_toml = raw_toml.get("tool", {}).get("cgull", {})
        if not isinstance(raw_toml, dict):
            return cfg

    # Validate schema version
    if "schema_version" in raw_toml:
        try:
            cfg.schema_version = int(raw_toml["schema_version"])
        except (ValueError, TypeError):
            cfg.warnings.append(f"Invalid schema_version in {config_path}: expected integer")

    # Check top-level keys for unknown keys
    known_top_keys = {"schema_version", "rules", "functions", "paths", "output"}
    for key in raw_toml.keys():
        if key not in known_top_keys:
            cfg.warnings.append(f"Unknown key/section '[{key}]' in configuration file {config_path}")

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
            alloc_list = mem_sec.get("alloc", [])
            if isinstance(alloc_list, list):
                cfg.alloc_funcs = [str(x) for x in alloc_list]
            realloc_list = mem_sec.get("realloc", [])
            if isinstance(realloc_list, list):
                cfg.realloc_funcs = [str(x) for x in realloc_list]
            dealloc_list = mem_sec.get("dealloc", [])
            if isinstance(dealloc_list, list):
                cfg.dealloc_funcs = [str(x) for x in dealloc_list]

        # functions.banned
        banned_sec = funcs_sec.get("banned", {})
        if isinstance(banned_sec, dict):
            for fn_name, details in banned_sec.items():
                if isinstance(details, dict):
                    reason = details.get("reason", f"Banned function call '{fn_name}'")
                    remediation = details.get("remediation", f"Avoid using {fn_name}()")
                    cfg.banned_funcs[str(fn_name)] = {
                        "reason": str(reason),
                        "remediation": str(remediation),
                    }
                elif isinstance(details, str):
                    cfg.banned_funcs[str(fn_name)] = {
                        "reason": str(details),
                        "remediation": f"Avoid using {fn_name}()",
                    }

    # Section [paths]
    paths_sec = raw_toml.get("paths", {})
    if isinstance(paths_sec, dict):
        exclude_list = paths_sec.get("exclude", [])
        if isinstance(exclude_list, list):
            cfg.exclude_paths = [str(x) for x in exclude_list]

    # Section [output]
    output_sec = raw_toml.get("output", {})
    if isinstance(output_sec, dict):
        if "default_format" in output_sec:
            cfg.default_format = str(output_sec["default_format"]).strip().lower()
        if "fail_on" in output_sec:
            cfg.fail_on = str(output_sec["fail_on"]).strip().lower()

    return cfg
