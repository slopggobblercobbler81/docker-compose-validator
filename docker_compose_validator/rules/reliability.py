"""Reliability and operational stability validation rules."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from docker_compose_validator.models import Category, Finding, Severity
from docker_compose_validator.parser import ParsedComposeFile
from docker_compose_validator.rules.base import BaseRule, RuleRegistry

UNPINNED_TAGS = {"latest", "master", "main", "dev", "nightly", "edge"}


def _is_image_pinned(image_str: str) -> bool:
    """
    Checks if a Docker image string is properly pinned.
    Examples of pinned:
      - 'python:3.11-slim'
      - 'myregistry.io/app:v1.2.3'
      - 'alpine@sha256:7144f7ba3b443186d59db4a55cfad64da3b212840a5e4d5fa7e37c7793d8c342'
    Examples of unpinned:
      - 'python'
      - 'python:latest'
      - 'python:main'
    """
    image_str = image_str.strip()
    # Check for sha256 digest
    if "@sha256:" in image_str:
        return True

    # Strip registry hostname if present (e.g., ghcr.io/org/repo:1.0)
    # Registry hostnames contain '.' or ':' followed by port
    parts = image_str.split("/")
    repo_and_tag = parts[-1]

    if ":" not in repo_and_tag:
        # No tag specified -> defaults to latest
        return False

    tag = repo_and_tag.rsplit(":", 1)[1].strip().lower()
    if tag in UNPINNED_TAGS:
        return False

    return True


@RuleRegistry.register
class MissingRestartPolicyRule(BaseRule):
    """Rule detecting missing or disabled container restart policies."""
    rule_id = "REL001"
    name = "missing-restart-policy"
    description = "Checks that services specify a resilient restart policy."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    recommendation = (
        "Set `restart: unless-stopped` or `restart: on-failure` to ensure automatic crash recovery."
    )

    RECOMMENDED_POLICIES = {"always", "unless-stopped", "on-failure"}

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            restart_val = svc_cfg.get("restart")
            # Check deploy.restart_policy if restart not present
            deploy_restart = None
            deploy_block = svc_cfg.get("deploy")
            if isinstance(deploy_block, dict):
                deploy_restart_block = deploy_block.get("restart_policy")
                if isinstance(deploy_restart_block, dict):
                    deploy_restart = deploy_restart_block.get("condition")

            line = parsed.get_service_field_line(svc_name, "restart") or parsed.get_service_line(svc_name)
            if parsed.is_rule_ignored(self.rule_id, line):
                continue

            if restart_val is None and deploy_restart is None:
                findings.append(
                    self.create_finding(
                        parsed=parsed,
                        message=f"Service '{svc_name}' has no restart policy defined and will not recover on failure.",
                        line_number=line,
                        service_name=svc_name,
                    )
                )
            elif restart_val is not None:
                restart_str = str(restart_val).strip().lower()
                if restart_str in ("no", "none", "false"):
                    findings.append(
                        self.create_finding(
                            parsed=parsed,
                            message=f"Service '{svc_name}' explicitly disables restart policy (`restart: '{restart_val}'`).",
                            line_number=line,
                            service_name=svc_name,
                        )
                    )

        return findings


@RuleRegistry.register
class UnpinnedImageRule(BaseRule):
    """Rule detecting unpinned container images."""
    rule_id = "REL002"
    name = "unpinned-image-version"
    description = "Checks that container images use pinned semantic tags or immutable digest SHA."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    recommendation = (
        "Pin image to an explicit version tag or immutable SHA256 digest (e.g. `redis:7.2.4-alpine`)."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            image_val = svc_cfg.get("image")
            # If no image is specified and build is present, image is built locally
            if not image_val:
                continue

            image_str = str(image_val).strip()
            line = parsed.get_service_field_line(svc_name, "image")

            if parsed.is_rule_ignored(self.rule_id, line):
                continue

            if not _is_image_pinned(image_str):
                findings.append(
                    self.create_finding(
                        parsed=parsed,
                        message=(
                            f"Service '{svc_name}' uses unpinned image '{image_str}', risking unexpected upstream changes."
                        ),
                        line_number=line,
                        service_name=svc_name,
                        details={"image": image_str},
                    )
                )

        return findings


@RuleRegistry.register
class MissingHealthcheckRule(BaseRule):
    """Rule detecting missing health checks."""
    rule_id = "REL003"
    name = "missing-healthcheck"
    description = "Checks that services define a healthcheck for orchestration and dependency readiness."
    severity = Severity.LOW
    category = Category.RELIABILITY
    recommendation = (
        "Add a `healthcheck:` section with `test: [...]`, `interval: 30s`, and `retries: 3`."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            healthcheck = svc_cfg.get("healthcheck")
            line = parsed.get_service_field_line(svc_name, "healthcheck") or parsed.get_service_line(svc_name)

            if parsed.is_rule_ignored(self.rule_id, line):
                continue

            if healthcheck is None:
                findings.append(
                    self.create_finding(
                        parsed=parsed,
                        message=f"Service '{svc_name}' does not configure a healthcheck.",
                        line_number=line,
                        service_name=svc_name,
                    )
                )
            elif isinstance(healthcheck, dict) and healthcheck.get("disable") is True:
                findings.append(
                    self.create_finding(
                        parsed=parsed,
                        message=f"Service '{svc_name}' explicitly disables healthcheck.",
                        line_number=line,
                        service_name=svc_name,
                    )
                )

        return findings


@RuleRegistry.register
class MissingResourceLimitsRule(BaseRule):
    """Rule detecting containers with unbounded memory and CPU limits."""
    rule_id = "REL004"
    name = "missing-resource-limits"
    description = "Checks that services declare memory or CPU constraints to prevent resource starvation."
    severity = Severity.LOW
    category = Category.RELIABILITY
    recommendation = (
        "Specify resource limits via `mem_limit` and `cpus` or under `deploy.resources.limits`."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            line = parsed.get_service_line(svc_name)
            if parsed.is_rule_ignored(self.rule_id, line):
                continue

            has_mem = "mem_limit" in svc_cfg
            has_cpu = "cpus" in svc_cfg

            # Check deploy.resources.limits
            deploy = svc_cfg.get("deploy")
            if isinstance(deploy, dict):
                resources = deploy.get("resources")
                if isinstance(resources, dict):
                    limits = resources.get("limits")
                    if isinstance(limits, dict):
                        if "memory" in limits:
                            has_mem = True
                        if "cpus" in limits:
                            has_cpu = True

            if not has_mem and not has_cpu:
                findings.append(
                    self.create_finding(
                        parsed=parsed,
                        message=f"Service '{svc_name}' has no CPU or memory limits configured.",
                        line_number=line,
                        service_name=svc_name,
                    )
                )

        return findings
