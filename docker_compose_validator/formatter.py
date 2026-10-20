"""Output formatters for validation reports."""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Tuple
from docker_compose_validator.__version__ import __version__
from docker_compose_validator.models import Finding, Severity, ValidationReport
from docker_compose_validator.rules import RuleRegistry

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

SEVERITY_COLORS = {
    Severity.CRITICAL: RED + BOLD,
    Severity.HIGH: RED,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: CYAN,
    Severity.INFO: DIM,
}


def _color(text: str, color_code: str, use_color: bool = True) -> str:
    if not use_color:
        return text
    return f"{color_code}{text}{RESET}"


def _get_symbols() -> Tuple[str, str, str]:
    """Returns (pass_symbol, fail_symbol, arrow_symbol) safe for current terminal encoding."""
    try:
        encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
        "✔✖↳".encode(encoding)
        return "✔", "✖", "↳"
    except Exception:
        return "[OK]", "[X]", "->"


class TableFormatter:
    """Formats validation report into human-readable terminal table output."""

    @classmethod
    def format(cls, report: ValidationReport, use_color: bool = True) -> str:
        lines: List[str] = []
        pass_sym, fail_sym, arrow_sym = _get_symbols()

        if report.total_files == 0:
            return _color("No Docker Compose files found to validate.", YELLOW, use_color)

        lines.append("")
        header = f"Docker Compose Validator v{__version__}"
        lines.append(_color(header, BOLD + WHITE, use_color))
        lines.append("=" * len(header))
        lines.append("")

        for res in report.results:
            status_symbol = _color(pass_sym, GREEN, use_color) if not res.findings else _color(fail_sym, RED, use_color)
            file_header = f"{status_symbol} {res.file_path} ({res.service_count} services, {len(res.findings)} issues)"
            lines.append(_color(file_header, BOLD, use_color))

            if not res.is_valid_syntax:
                lines.append("  " + _color(f"[SYNTAX ERROR] {res.error_message}", RED + BOLD, use_color))

            for f in res.findings:
                sev_color = SEVERITY_COLORS.get(f.severity, WHITE)
                sev_badge = _color(f"[{f.severity.value:<8}]", sev_color, use_color)
                line_str = f"L{f.line_number}:" if f.line_number else ""
                svc_str = f"({f.service_name})" if f.service_name else ""
                rule_str = _color(f"{f.rule_id}", DIM, use_color)

                prefix = f"  {sev_badge} {line_str:<5} {rule_str} {svc_str}"
                lines.append(f"{prefix} {f.message}")
                if f.recommendation:
                    recom_line = "  " + " " * 10 + _color(f"{arrow_sym} Fix: {f.recommendation}", DIM, use_color)
                    lines.append(recom_line)

            lines.append("")

        # Summary box
        lines.append("-" * 60)
        lines.append(_color("SCAN SUMMARY:", BOLD, use_color))
        lines.append(f"  Files scanned:    {report.total_files}")
        lines.append(f"  Services scanned: {report.total_services}")
        lines.append(f"  Total findings:   {report.total_findings}")

        sev_summary = [
            f"{_color('CRITICAL:', RED, use_color)} {report.critical_count}",
            f"{_color('HIGH:', RED, use_color)} {report.high_count}",
            f"{_color('MEDIUM:', YELLOW, use_color)} {report.medium_count}",
            f"{_color('LOW:', CYAN, use_color)} {report.low_count}",
            f"{_color('INFO:', DIM, use_color)} {report.info_count}",
        ]
        lines.append("  " + "  |  ".join(sev_summary))
        lines.append("-" * 60)

        if report.total_findings == 0 and all(r.is_valid_syntax for r in report.results):
            lines.append(_color(f"{pass_sym} All docker-compose checks passed! No violations found.", GREEN + BOLD, use_color))
        else:
            lines.append(_color(f"{fail_sym} Found {report.total_findings} violation(s).", RED, use_color))

        lines.append("")
        return "\n".join(lines)


class JsonFormatter:
    """Formats validation report into JSON output."""

    @classmethod
    def format(cls, report: ValidationReport, indent: int = 2) -> str:
        return json.dumps(report.to_dict(), indent=indent)


class SarifFormatter:
    """Formats findings into OASIS SARIF 2.1.0 format for GitHub Code Scanning."""

    @classmethod
    def format(cls, report: ValidationReport) -> str:
        sarif_level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }

        # Collect distinct rules
        rules_dict: Dict[str, Dict[str, Any]] = {}
        for rule in RuleRegistry.all_rules():
            rules_dict[rule.rule_id] = {
                "id": rule.rule_id,
                "name": rule.name,
                "shortDescription": {"text": rule.name.replace("-", " ").title()},
                "fullDescription": {"text": rule.description},
                "defaultConfiguration": {
                    "level": sarif_level_map.get(rule.severity, "warning")
                },
                "properties": {
                    "category": rule.category.value,
                    "severity": rule.severity.value,
                    "precision": "high",
                },
            }

        sarif_results: List[Dict[str, Any]] = []
        for finding in report.all_findings:
            line = finding.line_number or 1
            sarif_res = {
                "ruleId": finding.rule_id,
                "level": sarif_level_map.get(finding.severity, "warning"),
                "message": {
                    "text": finding.message + (f" Fix: {finding.recommendation}" if finding.recommendation else "")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path.replace("\\", "/"),
                            },
                            "region": {
                                "startLine": line,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }
            sarif_results.append(sarif_res)

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "docker-compose-validator",
                            "version": __version__,
                            "informationUri": "https://github.com/slopggobblercobbler81/docker-compose-validator",
                            "rules": list(rules_dict.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
        return json.dumps(sarif_doc, indent=2)


class MarkdownFormatter:
    """Formats validation report into GitHub-flavored Markdown."""

    @classmethod
    def format(cls, report: ValidationReport) -> str:
        lines: List[str] = [
            f"# Docker Compose Validation Report",
            f"",
            f"**Version:** `{__version__}`  ",
            f"**Files Scanned:** {report.total_files} | **Services:** {report.total_services} | **Findings:** {report.total_findings}",
            f"",
            f"| Critical | High | Medium | Low | Info |",
            f"|:--------:|:----:|:------:|:---:|:----:|",
            f"| {report.critical_count} | {report.high_count} | {report.medium_count} | {report.low_count} | {report.info_count} |",
            f"",
        ]

        if report.total_findings == 0:
            lines.append("### All Checks Passed! :white_check_mark:")
            lines.append("No security, reliability, or syntax issues detected.")
            return "\n".join(lines)

        lines.append("## Detailed Findings")
        lines.append("")
        lines.append("| Severity | Rule | Service | File:Line | Issue & Recommendation |")
        lines.append("|:---|:---|:---|:---|:---|")

        for f in report.all_findings:
            loc = f"`{f.file_path}:{f.line_number or 1}`"
            svc = f"`{f.service_name}`" if f.service_name else "-"
            fix = f"<br/>*Fix:* {f.recommendation}" if f.recommendation else ""
            desc = f"**{f.message}**{fix}"
            lines.append(f"| **{f.severity.value}** | `{f.rule_id}` ({f.rule_name}) | {svc} | {loc} | {desc} |")

        lines.append("")
        return "\n".join(lines)


class QuietFormatter:
    """Formats validation report into compact Unix linter style."""

    @classmethod
    def format(cls, report: ValidationReport) -> str:
        lines: List[str] = []
        for f in report.all_findings:
            line = f.line_number or 1
            svc = f" [{f.service_name}]" if f.service_name else ""
            lines.append(f"{f.file_path}:{line}: [{f.severity.value}] [{f.rule_id}]{svc} {f.message}")
        return "\n".join(lines)
