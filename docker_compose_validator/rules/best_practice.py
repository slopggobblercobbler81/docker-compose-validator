"""Best practice and maintainability validation rules."""

from __future__ import annotations

from typing import List
from docker_compose_validator.models import Category, Finding, Severity
from docker_compose_validator.parser import LineDict, ParsedComposeFile
from docker_compose_validator.rules.base import BaseRule, RuleRegistry


@RuleRegistry.register
class DeprecatedVersionRule(BaseRule):
    """Rule detecting obsolete 'version:' attribute in Compose files."""
    rule_id = "BP001"
    name = "deprecated-version-attribute"
    description = "Checks for the obsolete top-level 'version:' attribute."
    severity = Severity.INFO
    category = Category.BEST_PRACTICE
    recommendation = (
        "Remove the top-level `version:` attribute; modern Docker Compose automatically uses the Compose Specification."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        if not parsed.is_valid_yaml or not isinstance(parsed.data, dict):
            return []

        if "version" in parsed.data:
            line = 1
            if isinstance(parsed.data, LineDict):
                line = parsed.data.get_line("version") or 1

            if parsed.is_rule_ignored(self.rule_id, line):
                return []

            val = parsed.data["version"]
            return [
                self.create_finding(
                    parsed=parsed,
                    message=f"Top-level 'version: \"{val}\"' is obsolete and deprecated in modern Compose specifications.",
                    line_number=line,
                )
            ]

        return []


@RuleRegistry.register
class HardcodedContainerNameRule(BaseRule):
    """Rule detecting hardcoded container_name which breaks horizontal scaling."""
    rule_id = "BP002"
    name = "hardcoded-container-name"
    description = "Checks for static 'container_name:' that prevents scaling."
    severity = Severity.INFO
    category = Category.BEST_PRACTICE
    recommendation = (
        "Avoid `container_name:` if you plan to scale this service with `docker compose up --scale`."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            c_name = svc_cfg.get("container_name")
            if c_name:
                line = parsed.get_service_field_line(svc_name, "container_name")
                if parsed.is_rule_ignored(self.rule_id, line):
                    continue
                findings.append(
                    self.create_finding(
                        parsed=parsed,
                        message=f"Service '{svc_name}' specifies static container_name '{c_name}', disabling horizontal scaling.",
                        line_number=line,
                        service_name=svc_name,
                        details={"container_name": str(c_name)},
                    )
                )

        return findings


@RuleRegistry.register
class MissingLoggingConfigRule(BaseRule):
    """Rule detecting containers without rotation or max-size in logging."""
    rule_id = "BP003"
    name = "missing-logging-limits"
    description = "Checks that services define log rotation limits to prevent disk exhaustion."
    severity = Severity.INFO
    category = Category.BEST_PRACTICE
    recommendation = (
        "Define `logging: options: max-size: '10m'` and `max-file: '3'` to prevent unbounded container log growth."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            logging_cfg = svc_cfg.get("logging")
            line = parsed.get_service_field_line(svc_name, "logging") or parsed.get_service_line(svc_name)

            if parsed.is_rule_ignored(self.rule_id, line):
                continue

            if not logging_cfg:
                findings.append(
                    self.create_finding(
                        parsed=parsed,
                        message=f"Service '{svc_name}' has no log limits configured; container logs could exhaust host disk.",
                        line_number=line,
                        service_name=svc_name,
                    )
                )

        return findings
