"""
Reporting module for C-GULL Static Analyzer.
Generates structured JSON, SARIF 2.1.0, Markdown audit summaries, and terminal output.
"""

import json
import re
from typing import Dict, Any, List
from .models import ScanResult, Severity, FixType
from . import __version__


import logging
from .utils import sanitize_terminal_text

logger = logging.getLogger(__name__)



def _escape_markdown_cell(text: str) -> str:
    s = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    s = s.replace("|", "\\|")
    s = s.replace("`", "\\`")
    return s


_sanitize_terminal_text = sanitize_terminal_text


def _get_condition_tag(issue: Any) -> str:
    r_under = getattr(issue, "reachable_under", None)
    if not r_under or r_under == ["unconditional"]:
        return ""
    tags = [t for t in r_under if t and t != "unconditional"]
    if not tags:
        return ""
    return f"[{', '.join(tags)}]"


def _sarif_fix_for_issue(issue: Any) -> Dict[str, Any] | None:
    """Build a SARIF fix only when the replacement is provably a full line.

    ``Issue`` does not yet carry an exact replacement span. Emitting a SARIF
    replacement for a sub-expression would therefore risk deleting unrelated
    source. Restrict one-click fixes to regex findings whose replacement text
    is already a complete source line (including any indentation).
    """
    if issue.fix_type != FixType.SAFE_FIX or not issue.auto_fix_replacement:
        return None
    if str(getattr(issue, "engine", "")).lower() != "regex":
        return None

    snippet_lines = issue.code_snippet.splitlines() or [""]
    replacement_lines = issue.auto_fix_replacement.splitlines() or [""]
    if len(snippet_lines) != 1:
        return None

    replacement_first = replacement_lines[0]
    replacement_indent = len(replacement_first) - len(replacement_first.lstrip())
    if replacement_indent == 0 and max(1, issue.column_number) != 1:
        return None

    snippet = snippet_lines[0]
    if snippet.rstrip() and replacement_lines[-1].rstrip():
        if snippet.rstrip()[-1] != replacement_lines[-1].rstrip()[-1]:
            return None

    rendered_replacement = "\n".join(replacement_lines)
    original_width = len(snippet)
    deleted_region: Dict[str, Any] = {
        "startLine": max(1, issue.line_number),
        "startColumn": 1,
        "endLine": max(1, issue.line_number),
        "endColumn": original_width + 1,
    }

    return {
        "description": {"text": "Apply C-GULL mechanically safe fix"},
        "artifactChanges": [{
            "artifactLocation": {"uri": issue.file_path.replace("\\", "/")},
            "replacements": [{
                "deletedRegion": deleted_region,
                "insertedContent": {"text": rendered_replacement},
            }],
        }],
    }


class ReportGenerator:
    """
    Formats ScanResult into various standard security reporting formats.
    """

    @staticmethod
    def to_json(result: ScanResult, pretty: bool = True) -> str:
        """Generates standard JSON security report."""
        data = result.to_dict()
        indent = 2 if pretty else None
        return json.dumps(data, indent=indent)

    @staticmethod
    def to_sarif(result: ScanResult) -> str:
        """
        Generates OASIS SARIF v2.1.0 JSON format for GitHub Security Scanning & CI/CD.
        """
        rules_dict: Dict[str, Dict[str, Any]] = {}
        results_list: List[Dict[str, Any]] = []

        from .rules import RULE_REGISTRY

        for issue in result.issues:
            if issue.rule_id not in rules_dict:
                rule_cls = RULE_REGISTRY.get(issue.rule_id)
                full_desc = (getattr(rule_cls, "description", None) or issue.rule_name) if rule_cls else issue.rule_name
                rules_dict[issue.rule_id] = {
                    "id": issue.rule_id,
                    "name": issue.rule_name.replace(" ", ""),
                    "shortDescription": {"text": issue.rule_name},
                    "fullDescription": {"text": full_desc},
                    "help": {
                        "text": f"Remediation: {issue.remediation}\nCWE: {issue.cwe_id}",
                        "markdown": f"### Remediation\n{issue.remediation}\n\n**CWE**: {issue.cwe_id}"
                    },
                    "properties": {
                        "problem.severity": "error" if issue.impact == Severity.HIGH else ("warning" if issue.impact == Severity.MEDIUM else "note"),
                        "cwe": issue.cwe_id,
                    }
                }

            level = "error" if issue.impact == Severity.HIGH else ("warning" if issue.impact == Severity.MEDIUM else "note")

            props: Dict[str, Any] = {
                "cwe": issue.cwe_id,
                "remediation": issue.remediation,
                "fixType": issue.fix_type.value if isinstance(issue.fix_type, FixType) else str(issue.fix_type),
                "autoFix": issue.auto_fix_replacement,
                "suggestedFix": issue.suggested_fix_replacement,
                "reachableUnder": list(issue.reachable_under),
                "reachable_under": list(issue.reachable_under),
                "relatedTUs": list(issue.related_tus) if hasattr(issue, "related_tus") else [],
            }
            if issue.confidence:
                props["confidence"] = issue.confidence.value if hasattr(issue.confidence, "value") else str(issue.confidence)

            sarif_result: Dict[str, Any] = {
                "ruleId": issue.rule_id,
                "level": level,
                "message": {"text": issue.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": issue.file_path.replace("\\", "/")},
                        "region": {
                            "startLine": max(1, issue.line_number),
                            "startColumn": max(1, issue.column_number),
                            "snippet": {"text": issue.code_snippet}
                        }
                    }
                }],
                "properties": props,
                "partialFingerprints": {
                    "cgullFingerprint/v1": issue.fingerprint
                } if issue.fingerprint else {}
            }
            sarif_fix = _sarif_fix_for_issue(issue)
            if sarif_fix is not None:
                sarif_result["fixes"] = [sarif_fix]
            results_list.append(sarif_result)

        disc = result.files_discovered or (result.scanned_files_count + len(result.ignored_paths) + len(result.failed_paths))
        analyzed = result.files_analyzed or result.scanned_files_count
        ignored = result.files_ignored or len(result.ignored_paths)
        failed = result.files_failed or len(result.failed_paths)

        inv_props: Dict[str, Any] = {
            "parser": result.get_overall_parser_status(),
            "analysisStatus": result.get_overall_analysis_status(),
            "filesDiscovered": disc,
            "filesAnalyzed": analyzed,
            "filesIgnored": ignored,
            "filesFailed": failed,
            "scanErrors": [err.to_dict() for err in result.scan_errors],
        }
        inv_obj: Dict[str, Any] = {
            "executionSuccessful": failed == 0,
            "properties": inv_props,
        }
        if result.scan_errors:
            inv_obj["toolExecutionNotifications"] = [{
                "descriptor": {"id": err.error_type},
                "message": {"text": f"{err.file_path}: [{err.error_type}] {err.message}"},
                "level": "error",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": err.file_path.replace("\\", "/")}
                    }
                }]
            } for err in result.scan_errors]

        sarif_obj = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "C-GULL",
                        "fullName": "C-GULL: Code Guardian for Unchecked Logic & Leaks",
                        "version": __version__,
                        "informationUri": "https://github.com/sahebbiswas/cgull",
                        "rules": list(rules_dict.values()),
                    }
                },
                "invocations": [inv_obj],
                "results": results_list
            }]
        }
        return json.dumps(sarif_obj, indent=2)

    @staticmethod
    def to_markdown(result: ScanResult) -> str:
        """Generates executive Markdown audit report."""
        disc = result.files_discovered or (result.scanned_files_count + len(result.ignored_paths) + len(result.failed_paths))
        analyzed = result.files_analyzed or result.scanned_files_count
        ignored = result.files_ignored or len(result.ignored_paths)
        failed = result.files_failed or len(result.failed_paths)

        lines = [
            f"# 🛡️ C-GULL v{__version__} Security Audit Report",
            "",
            f"**Target**: `{result.target_path}`  ",
            f"**Scan Date**: `{result.timestamp}`  ",
            f"**Duration**: `{result.scan_duration_seconds:.3f}s`  ",
            f"**Parser Mode**: `{result.get_overall_parser_status()}`  ",
            f"**Analysis Status**: `{result.get_overall_analysis_status()}`  ",
            f"**Files Discovered**: `{disc}`  ",
            f"**Files Analyzed**: `{analyzed}`  ",
            f"**Files Ignored**: `{ignored}`  ",
            f"**Files Failed**: `{failed}`  ",
            f"**Total Lines of Code**: `{result.total_lines_of_code}`  ",
        ]
        if result.is_baseline_filtered:
            lines.append(
                f"**Baseline Diff**: `{result.baseline_total_before_filter}` total finding(s) found; "
                f"`{result.baseline_new_count}` new since baseline, `{result.baseline_resolved_count}` resolved since baseline  "
            )
        lines.extend([
            "",
            "## 📊 Executive Summary",
            "",
            "| Metric | Count | Status |",
            "| :--- | :--- | :--- |",
            f"| **Total Issues** | **{result.total_issues_count}** | {'🚨 Needs Immediate Remediation' if result.high_severity_count > 0 else '✅ Passed'} |",
            f"| 🔴 High Severity | {result.high_severity_count} | {'CRITICAL' if result.high_severity_count > 0 else 'None'} |",
            f"| 🟡 Medium Severity | {result.medium_severity_count} | Warning |",
            f"| 🔵 Low Severity | {result.low_severity_count} | Notice |",
            "",
            "---",
            "",
            "## 🚨 Detected Vulnerabilities & Security Findings",
            "",
        ])

        if result.scan_errors:
            lines.extend([
                "",
                "## ⚠️ Scan Errors",
                "",
                "| File Path | Error Type | Message |",
                "| :--- | :--- | :--- |",
            ])
            for err in result.scan_errors:
                p = _escape_markdown_cell(err.file_path)
                t = _escape_markdown_cell(err.error_type)
                m = _escape_markdown_cell(err.message)
                lines.append(f"| `{p}` | `{t}` | {m} |")

        if not result.issues:
            msg = "🎉 *No new vulnerabilities since baseline!*" if result.is_baseline_filtered else "🎉 *No vulnerabilities detected! The code complies with all checked security rules.*"
            lines.append(msg)
        else:
            for idx, issue in enumerate(result.issues, 1):
                badge = "🔴 HIGH" if issue.impact == Severity.HIGH else ("🟡 MEDIUM" if issue.impact == Severity.MEDIUM else "🔵 LOW")
                fix_type_label = issue.fix_type.value if isinstance(issue.fix_type, FixType) else str(issue.fix_type)
                cond_tag = _get_condition_tag(issue)
                if cond_tag:
                    cond_tag = _escape_markdown_cell(cond_tag)
                cond_prefix = f"{cond_tag} " if cond_tag else ""
                lines.extend([
                    f"### #{idx} [{badge}] {cond_prefix}{issue.rule_name} (`{issue.rule_id}`)",
                    f"- **Location**: `{issue.file_path}:{issue.line_number}`",
                    f"- **CWE**: `{issue.cwe_id}`",
                    f"- **Engine**: `{issue.engine}`",
                    f"- **Fix Type**: `{fix_type_label}`",
                    "",
                    f"**Vulnerability Finding**:",
                    f"> {issue.message}",
                    "",
                    "**Code Context**:",
                    "```c",
                    issue.code_snippet,
                    "```",
                    "",
                    "**Remediation Recommendation**:",
                    f"> {issue.remediation}",
                    "",
                ])
                if issue.auto_fix_replacement:
                    lines.extend([
                        "**Automatic Fix (Mechanically Safe)**:",
                        "```c",
                        issue.auto_fix_replacement,
                        "```",
                        "",
                    ])
                elif issue.suggested_fix_replacement:
                    lines.extend([
                        "**Suggested Fix (Manual Verification Required)**:",
                        "```c",
                        issue.suggested_fix_replacement,
                        "```",
                        "",
                    ])
                lines.append("---")

        return "\n".join(lines)

    @staticmethod
    def to_terminal_text(result: ScanResult) -> str:
        """Generates clean human-readable CLI terminal output."""
        disc = result.files_discovered or (result.scanned_files_count + len(result.ignored_paths) + len(result.failed_paths))
        analyzed = result.files_analyzed or result.scanned_files_count
        ignored = result.files_ignored or len(result.ignored_paths)
        failed = result.files_failed or len(result.failed_paths)

        lines = [
            "=======================================================================",
            f" 🛡️  C-GULL v{__version__}: Code Guardian for Unchecked Logic & Leaks",
            "=======================================================================",
            f" Target Path      : {result.target_path}",
            f" Parser Mode      : {result.get_overall_parser_status()}",
            f" Analysis Status  : {result.get_overall_analysis_status()}",
            f" Discovered Files : {disc}",
            f" Analyzed Files   : {analyzed}",
            f" Ignored Files    : {ignored}",
            f" Failed Files     : {failed}",
            f" Lines of Code    : {result.total_lines_of_code}",
            f" Scan Duration    : {result.scan_duration_seconds:.3f}s",
            f" Total Findings   : {result.total_issues_count} (High: {result.high_severity_count}, Medium: {result.medium_severity_count}, Low: {result.low_severity_count})",
        ]
        if result.is_baseline_filtered:
            lines.append(
                f" Baseline Diff    : {result.baseline_total_before_filter} total, "
                f"{result.baseline_new_count} new, {result.baseline_resolved_count} resolved since baseline"
            )
        lines.append("=======================================================================")

        if result.scan_errors:
            lines.extend([
                "",
                "=======================================================================",
                f" ⚠️  SCAN ERRORS ({len(result.scan_errors)} failed file(s))",
                "=======================================================================",
            ])
            for err in result.scan_errors:
                p = _sanitize_terminal_text(err.file_path)
                t = _sanitize_terminal_text(err.error_type)
                m = _sanitize_terminal_text(err.message)
                lines.append(f" [ERROR] {p} -> [{t}] {m}")
            lines.append("=======================================================================")

        if not result.issues:
            msg = " ✅ No new vulnerabilities since baseline!" if result.is_baseline_filtered else " ✅ No vulnerabilities found. Clean audit!"
            lines.append(msg)
            return "\n".join(lines)

        lines.append("")
        for issue in result.issues:
            sev_tag = f"[{issue.impact.value.upper()}]"
            fix_type_label = issue.fix_type.value if isinstance(issue.fix_type, FixType) else str(issue.fix_type)
            cond_tag = _get_condition_tag(issue)
            if cond_tag:
                cond_tag = _sanitize_terminal_text(cond_tag)
            cond_prefix = f"{cond_tag} " if cond_tag else ""
            lines.append(f" {sev_tag:<8} {issue.file_path}:{issue.line_number} -> {cond_prefix}{issue.rule_name} ({issue.rule_id})")
            lines.append(f"          Detail: {issue.message}")
            if issue.code_snippet:
                lines.append(f"          Code  : {issue.code_snippet}")
            lines.append(f"          CWE   : {issue.cwe_id}")
            lines.append(f"          Fix Type: {fix_type_label}")
            lines.append(f"          Fix   : {issue.remediation}")
            if issue.auto_fix_replacement:
                lines.append(f"          Auto-Fix : {issue.auto_fix_replacement}")
            elif issue.suggested_fix_replacement:
                lines.append(f"          Suggested: {issue.suggested_fix_replacement}")
            lines.append("")

        lines.append("=======================================================================")
        return "\n".join(lines)
