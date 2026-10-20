"""Syntax and structure validation rules."""

from __future__ import annotations

from typing import List
from docker_compose_validator.models import Category, Finding, Severity
from docker_compose_validator.parser import LineDict, ParsedComposeFile
from docker_compose_validator.rules.base import BaseRule, RuleRegistry


@RuleRegistry.register
class InvalidYamlRule(BaseRule):
    """Rule for checking valid YAML syntax."""
    rule_id = "SYN001"
    name = "invalid-yaml-syntax"
    description = "Checks that the file is well-formed YAML."
    severity = Severity.CRITICAL
    category = Category.SYNTAX
    recommendation = "Fix the YAML syntax error at the indicated line and column."

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        if not parsed.is_valid_yaml:
            msg = parsed.error_message or "Invalid YAML syntax"
            return [
                self.create_finding(
                    parsed=parsed,
                    message=f"YAML syntax error: {msg}",
                    line_number=parsed.error_line or 1,
                    details={"column": parsed.error_column},
                )
            ]
        return []


@RuleRegistry.register
class MissingServicesRule(BaseRule):
    """Rule for checking that a valid 'services' section exists."""
    rule_id = "SYN002"
    name = "missing-services-section"
    description = "Checks that top-level 'services' section is defined as a mapping."
    severity = Severity.CRITICAL
    category = Category.SYNTAX
    recommendation = "Add a 'services:' section defining the application containers."

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        if not parsed.is_valid_yaml or parsed.data is None:
            return []

        if not isinstance(parsed.data, dict):
            return [
                self.create_finding(
                    parsed=parsed,
                    message="Top-level compose document must be a YAML mapping (dictionary).",
                    line_number=1,
                )
            ]

        if "services" not in parsed.data:
            return [
                self.create_finding(
                    parsed=parsed,
                    message="Missing top-level 'services' definition.",
                    line_number=1,
                )
            ]

        services = parsed.data["services"]
        if not isinstance(services, dict):
            line = None
            if isinstance(parsed.data, LineDict):
                line = parsed.data.get_line("services")
            return [
                self.create_finding(
                    parsed=parsed,
                    message=f"'services' section must be a mapping, but got {type(services).__name__}.",
                    line_number=line or 1,
                )
            ]

        return []


@RuleRegistry.register
class EmptyServicesRule(BaseRule):
    """Rule for checking that services section contains at least one service."""
    rule_id = "SYN003"
    name = "empty-services-section"
    description = "Checks that the 'services' section defines at least one service."
    severity = Severity.HIGH
    category = Category.SYNTAX
    recommendation = "Define at least one container service under 'services:'."

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        if not parsed.is_valid_yaml or not isinstance(parsed.data, dict):
            return []

        services = parsed.data.get("services")
        if isinstance(services, dict) and len(services) == 0:
            line = 1
            if isinstance(parsed.data, LineDict):
                line = parsed.data.get_line("services") or 1
            return [
                self.create_finding(
                    parsed=parsed,
                    message="'services' section is defined but contains no service entries.",
                    line_number=line,
                )
            ]

        return []
