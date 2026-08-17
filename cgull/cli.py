"""
Command Line Interface (CLI) for C-GULL Static Analyzer.
"""

import sys
import os
import argparse
from typing import List, Optional

from .engine import CGullScanner
from .models import Severity, AnalysisEngine
from .ignore import CGullIgnoreFilter
from .reporter import ReportGenerator
from .rules import get_all_rules
from .baseline import load_baseline_fingerprints, apply_baseline, BaselineError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cgull",
        description="C-GULL: Code Guardian for Unchecked Logic & Leaks (C Code Security Static Analyzer)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cgull scan src/
  cgull scan src/ -o report.json --format json
  cgull scan src/ --engine regex --severity high
  cgull scan main.c --format sarif -o results.sarif
  cgull scan src/ --ignore-file .cgullignore --fail-on-high
  cgull scan src/ -j 0            # parallelize across all CPU cores
  cgull scan src/ --update-baseline baseline.json     # snapshot current findings
  cgull scan src/ --baseline baseline.json --fail-on-high  # only fail on NEW issues
  cgull rules
  cgull init-ignore

Suppressing findings inline:
  // cgull-ignore                          suppress all rules on this line
  // cgull-ignore: CGULL-001                suppress a specific rule on this line
  // cgull-ignore-next-line: CGULL-001,CGULL-003
        """
    )
    parser.add_argument("--version", "-v", action="version", version="C-GULL 0.5.0")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # SCAN subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan C source files or directories for vulnerabilities")
    scan_parser.add_argument("target", nargs="?", default=".", help="Target file or directory to scan (default: current directory)")
    scan_parser.add_argument("-o", "--output", help="Path to write the report file (defaults to stdout)")
    scan_parser.add_argument("-f", "--format", choices=["text", "json", "sarif", "markdown"], default="text", help="Report format (default: text)")
    scan_parser.add_argument("--ignore-file", help="Path to .cgullignore file")
    scan_parser.add_argument("--ignore-pattern", action="append", default=[], help="Pattern to ignore (can be specified multiple times)")
    scan_parser.add_argument("--severity", choices=["high", "medium", "low", "all"], default="all", help="Severity filter threshold")
    scan_parser.add_argument("--engine", choices=["regex", "ast", "hybrid"], default="hybrid", help="Scan engine mode (default: hybrid)")
    scan_parser.add_argument("--fail-on-high", action="store_true", help="Exit with code 1 if high-severity vulnerabilities are found (useful for CI/CD)")
    scan_parser.add_argument("-j", "--jobs", type=int, default=1, help="Number of files to scan in parallel (default: 1, sequential). Use 0 to auto-detect CPU count.")
    scan_parser.add_argument("--baseline", metavar="PATH", help="Path to a previous C-GULL JSON report; only findings NOT present in it are reported/counted (see --update-baseline to create one)")
    scan_parser.add_argument("--update-baseline", metavar="PATH", help="Write the full current scan as a new baseline JSON report to PATH (independent of --format/--output), for later use with --baseline")

    # RULES subcommand
    subparsers.add_parser("rules", help="List all security audit rules supported by C-GULL")

    # INIT-IGNORE subcommand
    subparsers.add_parser("init-ignore", help="Generate a default .cgullignore template file")

    return parser


def handle_scan(args) -> int:
    target = args.target
    if not os.path.exists(target):
        print(f"Error: Target path '{target}' does not exist.", file=sys.stderr)
        return 1

    # Determine severity filter
    sev_filter = None
    if args.severity == "high":
        sev_filter = {Severity.HIGH}
    elif args.severity == "medium":
        sev_filter = {Severity.HIGH, Severity.MEDIUM}
    elif args.severity == "low":
        sev_filter = {Severity.HIGH, Severity.MEDIUM, Severity.LOW}

    # Determine engine mode
    eng_mode = AnalysisEngine.HYBRID
    if args.engine == "regex":
        eng_mode = AnalysisEngine.REGEX
    elif args.engine == "ast":
        eng_mode = AnalysisEngine.AST

    scanner = CGullScanner(
        severity_filter=sev_filter,
        engine_mode=eng_mode
    )

    jobs = args.jobs
    if jobs == 0:
        jobs = os.cpu_count() or 1

    result = scanner.scan_path(
        target_path=target,
        ignore_file=args.ignore_file,
        custom_ignore_patterns=args.ignore_pattern,
        jobs=jobs,
    )

    # --update-baseline always snapshots the full (pre-baseline-filter)
    # result, so it reflects everything currently found regardless of
    # whether --baseline was also passed in the same invocation.
    if args.update_baseline:
        try:
            with open(args.update_baseline, "w", encoding="utf-8") as f:
                f.write(ReportGenerator.to_json(result))
            print(f"✅ Baseline saved to: {args.update_baseline} ({result.total_issues_count} issue(s) recorded)")
        except Exception as e:
            print(f"Error writing baseline to {args.update_baseline}: {e}", file=sys.stderr)
            return 1

    if args.baseline:
        try:
            baseline_counts = load_baseline_fingerprints(args.baseline)
        except BaselineError as e:
            print(f"Error loading baseline: {e}", file=sys.stderr)
            return 1
        result = apply_baseline(result, baseline_counts)

    # Format output
    fmt = args.format.lower()
    # Auto-detect format if output filename specified
    if args.output and args.format == "text":
        if args.output.endswith(".json"):
            fmt = "json"
        elif args.output.endswith(".sarif"):
            fmt = "sarif"
        elif args.output.endswith(".md"):
            fmt = "markdown"

    if fmt == "json":
        output_str = ReportGenerator.to_json(result)
    elif fmt == "sarif":
        output_str = ReportGenerator.to_sarif(result)
    elif fmt == "markdown":
        output_str = ReportGenerator.to_markdown(result)
    else:
        output_str = ReportGenerator.to_terminal_text(result)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_str)
            print(f"✅ Report saved to: {args.output}")
        except Exception as e:
            print(f"Error writing report to {args.output}: {e}", file=sys.stderr)
            return 1
    else:
        print(output_str)

    if args.fail_on_high and result.high_severity_count > 0:
        return 1
    return 0


def handle_rules() -> int:
    rules = get_all_rules()
    print("=" * 80)
    print(f" 🛡️  C-GULL Security Rules Catalog ({len(rules)} Active Rules)")
    print("=" * 80)
    print(f"{'ID':<11} | {'Impact':<7} | {'CWE':<15} | {'Rule Name'}")
    print("-" * 80)
    for r in sorted(rules, key=lambda x: (0 if x.impact == Severity.HIGH else (1 if x.impact == Severity.MEDIUM else 2), x.rule_id)):
        imp = r.impact.value.upper()
        print(f"{r.rule_id:<11} | {imp:<7} | {r.cwe_id:<15} | {r.name}")
        print(f"   Description : {r.description}")
        print(f"   Remediation : {r.remediation_suggestion}")
        print("-" * 80)
    return 0


def handle_init_ignore() -> int:
    ignore_content = """# .cgullignore - C-GULL Static Analyzer Ignore Rules
# Exclude third-party vendor directories
vendor/
third_party/
deps/

# Build artifacts
build/
dist/
*.o
*.obj
*.so
*.dylib
*.a

# Test suites & mocks if desired
test/mocks/
temp_*.c
"""
    file_path = ".cgullignore"
    if os.path.exists(file_path):
        print(f"⚠️  {file_path} already exists. Not overwriting.")
        return 0
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(ignore_content)
    print(f"✅ Created default '{file_path}' template.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    # Default to 'scan .' if no args provided or path given without subcommand
    if not argv:
        argv = ["scan", "."]
    elif argv[0] not in ("scan", "rules", "init-ignore", "--help", "-h", "--version", "-v"):
        argv = ["scan"] + argv

    args = parser.parse_args(argv)

    if args.command == "rules":
        return handle_rules()
    elif args.command == "init-ignore":
        return handle_init_ignore()
    elif args.command == "scan":
        return handle_scan(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
