"""
Reporting module for C-GULL Static Analyzer.
Generates structured JSON, SARIF 2.1.0, Markdown audit summaries, and terminal output.
"""

import json
from typing import Dict, Any, List
from .models import ScanResult, Severity


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

        for issue in result.issues:
            # Rule entry
            if issue.rule_id not in rules_dict:
                rules_dict[issue.rule_id] = {
                    "id": issue.rule_id,
                    "name": issue.rule_name.replace(" ", ""),
                    "shortDescription": {"text": issue.rule_name},
                    "fullDescription": {"text": issue.remediation},
                    "help": {
                        "text": f"Remediation: {issue.remediation}\nCWE: {issue.cwe_id}",
                        "markdown": f"### Remediation\n{issue.remediation}\n\n**CWE**: {issue.cwe_id}"
                    },
                    "properties": {
                        "problem.severity": "error" if issue.impact == Severity.HIGH else ("warning" if issue.impact == Severity.MEDIUM else "note"),
                        "cwe": issue.cwe_id,
                    }
                }

            # SARIF level
            level = "error" if issue.impact == Severity.HIGH else ("warning" if issue.impact == Severity.MEDIUM else "note")

            results_list.append({
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
                "properties": {
                    "cwe": issue.cwe_id,
                    "remediation": issue.remediation,
                    "autoFix": issue.auto_fix_replacement
                }
            })

        sarif_obj = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "C-GULL",
                        "fullName": "C-GULL: Code Guardian for Unchecked Logic & Leaks",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/sahebbiswas/cgull",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results_list
            }]
        }
        return json.dumps(sarif_obj, indent=2)

    @staticmethod
    def to_markdown(result: ScanResult) -> str:
        """Generates executive Markdown audit report."""
        lines = [
            "# 🛡️ C-GULL Security Audit Report",
            "",
            f"**Target**: `{result.target_path}`  ",
            f"**Scan Date**: `{result.timestamp}`  ",
            f"**Duration**: `{result.scan_duration_seconds:.3f}s`  ",
            f"**Files Scanned**: `{result.scanned_files_count}`  ",
            f"**Total Lines of Code**: `{result.total_lines_of_code}`  ",
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
        ]

        if not result.issues:
            lines.append("🎉 *No vulnerabilities detected! The code complies with all checked security rules.*")
        else:
            for idx, issue in enumerate(result.issues, 1):
                badge = "🔴 HIGH" if issue.impact == Severity.HIGH else ("🟡 MEDIUM" if issue.impact == Severity.MEDIUM else "🔵 LOW")
                lines.extend([
                    f"### #{idx} [{badge}] {issue.rule_name} (`{issue.rule_id}`)",
                    f"- **Location**: `{issue.file_path}:{issue.line_number}`",
                    f"- **CWE**: `{issue.cwe_id}`",
                    f"- **Engine**: `{issue.engine}`",
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
                        "**Suggested Fix / Code Replacement**:",
                        "```c",
                        issue.auto_fix_replacement,
                        "```",
                        "",
                    ])
                lines.append("---")

        return "\n".join(lines)

    @staticmethod
    def to_terminal_text(result: ScanResult) -> str:
        """Generates clean human-readable CLI terminal output."""
        lines = [
            "=======================================================================",
            " 🛡️  C-GULL: Code Guardian for Unchecked Logic & Leaks",
            "=======================================================================",
            f" Target Path      : {result.target_path}",
            f" Files Scanned    : {result.scanned_files_count}",
            f" Lines of Code    : {result.total_lines_of_code}",
            f" Scan Duration    : {result.scan_duration_seconds:.3f}s",
            f" Total Findings   : {result.total_issues_count} (High: {result.high_severity_count}, Medium: {result.medium_severity_count}, Low: {result.low_severity_count})",
            "=======================================================================",
        ]

        if not result.issues:
            lines.append(" ✅ No vulnerabilities found. Clean audit!")
            return "\n".join(lines)

        lines.append("")
        for issue in result.issues:
            sev_tag = f"[{issue.impact.value.upper()}]"
            lines.append(f" {sev_tag:<8} {issue.file_path}:{issue.line_number} -> {issue.rule_name} ({issue.rule_id})")
            lines.append(f"          Detail: {issue.message}")
            if issue.code_snippet:
                lines.append(f"          Code  : {issue.code_snippet}")
            lines.append(f"          CWE   : {issue.cwe_id}")
            lines.append(f"          Fix   : {issue.remediation}")
            lines.append("")

        lines.append("=======================================================================")
        return "\n".join(lines)
