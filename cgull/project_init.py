"""Project initialization and legacy configuration migration for C-GULL."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, TextIO, Tuple

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore

from .config import find_config_file
from .models import Severity
from .rules import get_all_rules


FOCUSED_SKIPS: Dict[str, str] = {
    "CGULL-019": "Focused profile: explicit void style is project policy",
    "CGULL-025": "Focused profile: assertion placement is project policy",
}
DEFAULT_EXCLUDES: Tuple[str, ...] = (
    "build/",
    "dist/",
    "vendor/",
    "third_party/",
)
COMMON_INCLUDE_ROOTS: Tuple[str, ...] = (
    "include",
    "inc",
    "src/include",
)


class InitError(ValueError):
    """Raised when project initialization cannot safely proceed."""


def _write(stream: TextIO, message: str = "") -> None:
    stream.write(message + "\n")


def _is_interactive(stdin: TextIO, stdout: TextIO) -> bool:
    return bool(getattr(stdin, "isatty", lambda: False)() and getattr(stdout, "isatty", lambda: False)())


def _toml_quote(value: str) -> str:
    # JSON basic strings are valid TOML basic strings for the characters emitted
    # by json.dumps, and this keeps path/backslash escaping deterministic.
    return json.dumps(value, ensure_ascii=False)


def _dedupe(values: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen = set()
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def _normalize_ignore_pattern(pattern: str) -> str:
    raw = pattern.strip().replace("\\", "/")
    negated = raw.startswith("!")
    body = raw[1:] if negated else raw
    while body.startswith("./"):
        body = body[2:]
    normalized = ("!" if negated else "") + body
    return normalized


def _read_legacy_ignore(path: Path) -> List[str]:
    if not path.is_file():
        return []
    values: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        normalized = _normalize_ignore_pattern(raw)
        if normalized:
            values.append(normalized)
    return _dedupe(values)


def _normalize_include_root(root: str, project_root: Path) -> str:
    raw = root.strip()
    if not raw:
        return ""
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            relative = candidate.resolve().relative_to(project_root.resolve())
        except (OSError, ValueError):
            return candidate.as_posix()
        return relative.as_posix() or "."
    normalized = raw.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/") or "."


def _read_legacy_includes(path: Path, project_root: Path) -> List[str]:
    if not path.is_file():
        return []
    values: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        normalized = _normalize_include_root(raw, project_root)
        if normalized:
            values.append(normalized)
    return _dedupe(values)


def _detect_include_roots(project_root: Path) -> List[str]:
    detected: List[str] = []
    for relative in COMMON_INCLUDE_ROOTS:
        if (project_root / relative).is_dir():
            detected.append(relative)
    return detected


def _detect_compile_commands(project_root: Path) -> Optional[Path]:
    candidates = (
        project_root / "compile_commands.json",
        project_root / "build" / "compile_commands.json",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _validate_focused_profile() -> None:
    rules = {rule.rule_id: rule for rule in get_all_rules()}
    missing = [rule_id for rule_id in FOCUSED_SKIPS if rule_id not in rules]
    if missing:
        raise InitError(f"Focused profile references unknown rule(s): {', '.join(missing)}")
    unsafe = [
        rule_id
        for rule_id in FOCUSED_SKIPS
        if rules[rule_id].impact in (Severity.HIGH, Severity.MEDIUM)
    ]
    if unsafe:
        raise InitError(
            "Focused profile safety check failed; refusing to disable high/medium-severity rule(s): "
            + ", ".join(unsafe)
        )


def _prompt_profile(stdin: TextIO, stdout: TextIO) -> Tuple[str, Dict[str, str]]:
    _write(stdout, "Finding profile:")
    _write(stdout, "  1. Focused (recommended): skip CGULL-019 and CGULL-025 only")
    _write(stdout, "  2. Comprehensive: enable every registered rule")
    _write(stdout, "  3. Custom: choose rule exclusions explicitly")
    stdout.write("Select profile [1/2/3, default 1]: ")
    stdout.flush()
    choice = stdin.readline()
    if choice == "":
        raise InitError("No profile input received; initialization cancelled before writing configuration.")
    normalized = choice.strip().lower()
    if normalized in ("", "1", "focused", "f"):
        _validate_focused_profile()
        return "focused", dict(FOCUSED_SKIPS)
    if normalized in ("2", "comprehensive", "c"):
        return "comprehensive", {}
    if normalized not in ("3", "custom"):
        raise InitError("Invalid finding profile. Choose focused, comprehensive, or custom.")
    return "custom", _prompt_custom_skips(stdin, stdout)


def _prompt_custom_skips(stdin: TextIO, stdout: TextIO) -> Dict[str, str]:
    rules = sorted(get_all_rules(), key=lambda rule: rule.rule_id)
    by_id = {rule.rule_id: rule for rule in rules}
    _write(stdout, "Available rules (ID | name | category | severity):")
    for rule in rules:
        category = getattr(rule.category, "value", str(rule.category))
        severity = getattr(rule.impact, "value", str(rule.impact))
        _write(stdout, f"  {rule.rule_id} | {rule.name} | {category} | {severity}")
    stdout.write("Rule IDs to skip (comma-separated, blank for none): ")
    stdout.flush()
    response = stdin.readline()
    if response == "":
        raise InitError("No custom rule selection received; initialization cancelled before writing configuration.")
    tokens = [token.strip().upper() for token in response.split(",") if token.strip()]
    unknown = [token for token in tokens if token not in by_id]
    if unknown:
        raise InitError("Unknown rule ID(s): " + ", ".join(unknown))
    return {
        rule_id: "Custom profile: excluded during cgull init"
        for rule_id in _dedupe(tokens)
    }


def _confirm_include_roots(
    include_roots: Sequence[str], stdin: TextIO, stdout: TextIO
) -> List[str]:
    if not include_roots:
        _write(stdout, "No common include directories detected.")
        return []
    _write(stdout, "Detected include roots: " + ", ".join(include_roots))
    stdout.write("Use these include roots? [Y/n]: ")
    stdout.flush()
    response = stdin.readline()
    if response == "":
        raise InitError("No include-root confirmation received; initialization cancelled before writing configuration.")
    normalized = response.strip().lower()
    if normalized in ("", "y", "yes"):
        return list(include_roots)
    if normalized in ("n", "no"):
        return []
    raise InitError("Invalid include-root confirmation. Enter y or n.")


def _render_config(
    excludes: Sequence[str],
    include_roots: Sequence[str],
    profile: str,
    skipped_rules: Dict[str, str],
) -> str:
    lines = [
        "schema_version = 1",
        "",
        "[paths]",
        "exclude = [",
    ]
    for pattern in excludes:
        lines.append(f"    {_toml_quote(pattern)},")
    lines.extend(["]", "", "[includes]", "roots = ["])
    for root in include_roots:
        lines.append(f"    {_toml_quote(root)},")
    lines.extend(
        [
            "]",
            "",
            "[output]",
            'default_format = "text"',
            "warn_on_fallback = false",
            "",
        ]
    )
    if skipped_rules:
        if profile == "focused":
            lines.append("# Focused profile: opinionated low-severity policy checks disabled explicitly.")
        else:
            lines.append("# Custom profile: rule exclusions selected explicitly during initialization.")
        lines.extend(["[rules]", "skip = {"])
        for rule_id, reason in skipped_rules.items():
            lines.append(f"    {_toml_quote(rule_id)} = {_toml_quote(reason)},")
        lines.extend(["}", ""])
    else:
        lines.extend(
            [
                "# Comprehensive profile: every registered rule remains enabled.",
                "# Add a [rules].skip table only when the project intentionally disables a rule.",
                "",
            ]
        )
    lines.extend(
        [
            "# Optional explicit mode override:",
            "#",
            "# [scan]",
            '# mode = "file"',
            "#",
            "# Optional project rule policy:",
            "#",
            "# [rules]",
            '# skip = { "CGULL-019" = "Project policy does not require this rule" }',
            "",
        ]
    )
    rendered = "\n".join(lines)
    # Validate before any file is created.
    tomllib.loads(rendered)
    return rendered


def _existing_project_config(project_root: Path) -> Optional[Path]:
    found = find_config_file(str(project_root))
    return Path(found).resolve() if found else None


def initialize_project(
    project_root: Path,
    *,
    profile: Optional[str] = None,
    migrate: bool = False,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    root = project_root.expanduser().resolve()
    if not root.exists():
        _write(stderr, f"Error: project path '{project_root}' does not exist.")
        return 2
    if not root.is_dir():
        _write(stderr, f"Error: project path '{project_root}' is not a directory.")
        return 2

    existing = _existing_project_config(root)
    if existing is not None:
        _write(stderr, f"Error: C-GULL configuration already exists at '{existing}'. Not overwriting or shadowing it.")
        return 2

    interactive = _is_interactive(stdin, stdout)
    if profile is not None and profile not in ("focused", "comprehensive"):
        _write(stderr, "Error: --profile must be 'focused' or 'comprehensive'.")
        return 2

    try:
        if profile == "focused":
            _validate_focused_profile()
            selected_profile, skipped_rules = "focused", dict(FOCUSED_SKIPS)
        elif profile == "comprehensive":
            selected_profile, skipped_rules = "comprehensive", {}
        elif interactive:
            selected_profile, skipped_rules = _prompt_profile(stdin, stdout)
        else:
            _validate_focused_profile()
            selected_profile, skipped_rules = "focused", dict(FOCUSED_SKIPS)

        detected_roots = _detect_include_roots(root)
        legacy_ignores = _read_legacy_ignore(root / ".cgullignore") if migrate else []
        legacy_roots = _read_legacy_includes(root / ".cgullincludes", root) if migrate else []

        include_roots = _dedupe([*legacy_roots, *detected_roots])
        if interactive:
            include_roots = _confirm_include_roots(include_roots, stdin, stdout)

        excludes = _dedupe(legacy_ignores) if legacy_ignores else list(DEFAULT_EXCLUDES)
        rendered = _render_config(excludes, include_roots, selected_profile, skipped_rules)
    except (InitError, OSError, ValueError) as exc:
        _write(stderr, f"Error: {exc}")
        return 2

    destination = root / ".cgull.toml"
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
    except FileExistsError:
        _write(stderr, f"Error: '{destination}' already exists. Not overwriting it.")
        return 2
    except OSError as exc:
        _write(stderr, f"Error: unable to create '{destination}': {exc}")
        return 2

    compile_commands = _detect_compile_commands(root)
    _write(stdout, f"Created {destination}")
    _write(stdout, f"Finding profile: {selected_profile}")
    if compile_commands is not None:
        relative_cc = compile_commands.relative_to(root).as_posix()
        _write(stdout, f"Detected {relative_cc}; scans will auto-discover it, so build-derived include paths were not copied into TOML.")
    if migrate and ((root / ".cgullignore").exists() or (root / ".cgullincludes").exists()):
        _write(stdout, "Legacy project files were imported but not modified. Remove them only after reviewing the generated TOML.")
    _write(stdout, "Next commands:")
    _write(stdout, "  cgull scan .")
    _write(stdout, "  cgull rules")
    _write(stdout, "  cgull flags .")
    return 0


def handle_init(args, *, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout, stderr: TextIO = sys.stderr) -> int:
    return initialize_project(
        Path(getattr(args, "path", ".") or "."),
        profile=getattr(args, "profile", None),
        migrate=bool(getattr(args, "migrate", False)),
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
    )
