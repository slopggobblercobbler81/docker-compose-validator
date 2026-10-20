"""Execution engine for validating compose files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Sequence, Set, Union
from docker_compose_validator.models import Finding, Severity, ValidationReport, ValidationResult
from docker_compose_validator.parser import ComposeParser, ParsedComposeFile
from docker_compose_validator.rules import RuleRegistry

COMPOSE_FILE_NAMES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}


def find_compose_files(paths: Sequence[Union[str, Path]], recursive: bool = False) -> List[Path]:
    """Finds Docker Compose files from provided file or directory paths."""
    discovered: List[Path] = []
    seen: Set[str] = set()

    def add_if_new(p: Path) -> None:
        resolved = str(p.resolve())
        if resolved not in seen and p.is_file():
            seen.add(resolved)
            discovered.append(p)

    for item in paths:
        path_obj = Path(item)
        if not path_obj.exists():
            continue

        if path_obj.is_file():
            add_if_new(path_obj)
        elif path_obj.is_dir():
            if recursive:
                for root, _, files in os.walk(path_obj):
                    for f in files:
                        lower = f.lower()
                        if lower in COMPOSE_FILE_NAMES or lower.startswith("docker-compose.") or lower.startswith("compose."):
                            if lower.endswith((".yml", ".yaml")):
                                add_if_new(Path(root) / f)
            else:
                for entry in path_obj.iterdir():
                    if entry.is_file():
                        lower = entry.name.lower()
                        if lower in COMPOSE_FILE_NAMES or lower.startswith("docker-compose.") or lower.startswith("compose."):
                            if lower.endswith((".yml", ".yaml")):
                                add_if_new(entry)

    return sorted(discovered)


class ValidationRunner:
    """Orchestrates validation of Docker Compose files against configured rules."""

    def __init__(
        self,
        ignore_rules: Optional[List[str]] = None,
        select_rules: Optional[List[str]] = None,
        min_severity: Optional[Severity] = None,
    ) -> None:
        self.ignore_rules = [r.strip().upper() for r in (ignore_rules or []) if r.strip()]
        self.select_rules = [r.strip().upper() for r in (select_rules or []) if r.strip()]
        self.min_severity = min_severity

    def validate_file(self, file_path: Union[str, Path]) -> ValidationResult:
        """Validates a single compose file on disk."""
        parsed = ComposeParser.parse_file(file_path)
        return self._evaluate_parsed(parsed)

    def validate_string(self, content: str, file_path: str = "<inline>") -> ValidationResult:
        """Validates compose YAML content from memory."""
        parsed = ComposeParser.parse_string(content, file_path=file_path)
        return self._evaluate_parsed(parsed)

    def _evaluate_parsed(self, parsed: ParsedComposeFile) -> ValidationResult:
        findings: List[Finding] = []
        rules = RuleRegistry.filter_rules(
            ignore_rules=self.ignore_rules,
            select_rules=self.select_rules,
            min_severity=self.min_severity,
        )

        # Count services if available
        svc_count = len(parsed.services) if isinstance(parsed.services, dict) else 0

        # Run rules
        for rule in rules:
            if parsed.is_rule_ignored(rule.rule_id):
                continue
            rule_findings = rule.check(parsed)
            # Filter rule findings by min_severity if specified
            if self.min_severity:
                rule_findings = [f for f in rule_findings if f.severity >= self.min_severity]
            findings.extend(rule_findings)

        # Sort findings by line number, then severity level descending
        findings.sort(key=lambda f: (f.line_number or 0, -f.severity.level))

        return ValidationResult(
            file_path=parsed.file_path,
            findings=findings,
            is_valid_syntax=parsed.is_valid_yaml,
            error_message=parsed.error_message,
            service_count=svc_count,
            scanned_rules_count=len(rules),
        )

    def run(self, targets: Sequence[Union[str, Path]], recursive: bool = False) -> ValidationReport:
        """Finds and validates compose files across targets."""
        files = find_compose_files(targets, recursive=recursive)
        results: List[ValidationResult] = []
        total_services = 0

        for f in files:
            res = self.validate_file(f)
            results.append(res)
            total_services += res.service_count

        return ValidationReport(
            results=results,
            total_files=len(results),
            total_services=total_services,
        )
