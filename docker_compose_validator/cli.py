"""Command-line interface for docker-compose-validator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence
from docker_compose_validator.__version__ import __version__
from docker_compose_validator.formatter import (
    JsonFormatter,
    MarkdownFormatter,
    QuietFormatter,
    SarifFormatter,
    TableFormatter,
)
from docker_compose_validator.models import Category, Severity
from docker_compose_validator.rules import RuleRegistry
from docker_compose_validator.runner import ValidationRunner, find_compose_files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docker-compose-validator",
        description=(
            "Production-grade Docker Compose linter, security auditor, and best-practices analyzer."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "targets",
        nargs="*",
        default=[],
        help="Path to compose file(s) or directories to scan (default: current directory).",
    )

    parser.add_argument(
        "-f",
        "--file",
        action="append",
        dest="explicit_files",
        help="Specify compose file explicitly (can be used multiple times).",
    )

    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Search directories recursively for docker-compose files.",
    )

    parser.add_argument(
        "--format",
        choices=["table", "json", "sarif", "markdown", "quiet"],
        default="table",
        help="Output format for validation findings.",
    )

    parser.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default="info",
        help="Minimum severity level of findings to display.",
    )

    parser.add_argument(
        "--fail-on",
        choices=["none", "info", "low", "medium", "high", "critical"],
        default="medium",
        help="Exit with code 1 if any finding reaches or exceeds this severity.",
    )

    parser.add_argument(
        "--strict",
        action="store_true",
        help="Strict mode: exit with code 1 on ANY finding (equivalent to --fail-on info).",
    )

    parser.add_argument(
        "--ignore",
        metavar="RULES",
        help="Comma-separated list of rule IDs to skip (e.g. SEC001,BP001).",
    )

    parser.add_argument(
        "--select",
        metavar="RULES",
        help="Comma-separated list of rule IDs to run exclusively.",
    )

    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write output report directly to specified file instead of stdout.",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output in terminal table.",
    )

    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Display all available validation rules and exit.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def print_rules_catalog(no_color: bool = False) -> None:
    rules = sorted(RuleRegistry.all_rules(), key=lambda r: (r.category.value, r.severity.level * -1, r.rule_id))
    print(f"\nDocker Compose Validator Rules Catalog (v{__version__})\n")
    current_cat = None
    for r in rules:
        if r.category.value != current_cat:
            current_cat = r.category.value
            print(f"[{current_cat.upper()}]")
        print(f"  {r.rule_id:<8} [{r.severity.value:<8}] {r.name}")
        print(f"           Description: {r.description}")
        print(f"           Recommendation: {r.recommendation}\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Ensure stdout/stderr handles UTF-8 safely without crashing on Windows
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        print_rules_catalog(no_color=args.no_color)
        return 0

    # Collect target paths
    targets: List[str] = []
    if args.explicit_files:
        targets.extend(args.explicit_files)
    if args.targets:
        targets.extend(args.targets)

    if not targets:
        # Default to current directory
        targets = ["."]

    # Parse rules selection & ignores
    ignore_list = [r.strip() for r in args.ignore.split(",")] if args.ignore else []
    select_list = [r.strip() for r in args.select.split(",")] if args.select else []

    min_sev = Severity.from_str(args.min_severity)

    fail_on_sev: Optional[Severity]
    if args.strict:
        fail_on_sev = Severity.INFO
    elif args.fail_on.lower() == "none":
        fail_on_sev = None
    else:
        fail_on_sev = Severity.from_str(args.fail_on)

    # Initialize runner
    runner = ValidationRunner(
        ignore_rules=ignore_list,
        select_rules=select_list,
        min_severity=min_sev,
    )

    # Verify if explicit files exist
    for t in targets:
        p = Path(t)
        if not p.exists() and not (p.parent.exists() and any(p.parent.glob(p.name))):
            sys.stderr.write(f"Error: Path does not exist: {t}\n")
            return 2

    # Discover and run
    report = runner.run(targets, recursive=args.recursive)

    if report.total_files == 0:
        sys.stderr.write("Error: No Docker Compose files found in specified target(s).\n")
        return 2

    # Format output
    use_color = not args.no_color and sys.stdout.isatty()
    output_str: str
    if args.format == "json":
        output_str = JsonFormatter.format(report)
    elif args.format == "sarif":
        output_str = SarifFormatter.format(report)
    elif args.format == "markdown":
        output_str = MarkdownFormatter.format(report)
    elif args.format == "quiet":
        output_str = QuietFormatter.format(report)
    else:
        output_str = TableFormatter.format(report, use_color=use_color)

    # Output to stdout or file
    if args.output:
        try:
            Path(args.output).write_text(output_str, encoding="utf-8")
        except Exception as e:
            sys.stderr.write(f"Error writing to output file '{args.output}': {e}\n")
            return 2
    else:
        if output_str:
            print(output_str)

    # Determine exit code
    if report.has_failures(fail_on_sev):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
