"""Tests for reliability validation rules (REL001-REL004)."""

from docker_compose_validator.models import Severity
from docker_compose_validator.parser import ComposeParser
from docker_compose_validator.rules.reliability import (
    MissingHealthcheckRule,
    MissingResourceLimitsRule,
    MissingRestartPolicyRule,
    UnpinnedImageRule,
)


def test_rel001_missing_restart_policy():
    rule = MissingRestartPolicyRule()
    content = """
services:
  web:
    image: nginx:1.25
  worker:
    image: python:3.11
    restart: "no"
  safe_web:
    image: nginx:1.25
    restart: unless-stopped
  swarm_svc:
    image: nginx:1.25
    deploy:
      restart_policy:
        condition: on-failure
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 2
    services = {f.service_name for f in findings}
    assert services == {"web", "worker"}


def test_rel002_unpinned_image():
    rule = UnpinnedImageRule()
    content = """
services:
  unpinned_latest:
    image: redis:latest
  unpinned_notag:
    image: redis
  unpinned_main:
    image: myrepo/app:main
  pinned_tag:
    image: redis:7.2.4-alpine
  pinned_sha:
    image: redis@sha256:7144f7ba3b443186d59db4a55cfad64da3b212840a5e4d5fa7e37c7793d8c342
  built_locally:
    build: .
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 3
    services = {f.service_name for f in findings}
    assert services == {"unpinned_latest", "unpinned_notag", "unpinned_main"}


def test_rel003_missing_healthcheck():
    rule = MissingHealthcheckRule()
    content = """
services:
  no_hc:
    image: nginx:1.25
  disabled_hc:
    image: nginx:1.25
    healthcheck:
      disable: true
  with_hc:
    image: nginx:1.25
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 2
    services = {f.service_name for f in findings}
    assert services == {"no_hc", "disabled_hc"}


def test_rel004_missing_resource_limits():
    rule = MissingResourceLimitsRule()
    content = """
services:
  unlimited:
    image: app:1.0
  limits_v2:
    image: app:1.0
    mem_limit: 512m
  limits_v3:
    image: app:1.0
    deploy:
      resources:
        limits:
          cpus: "0.50"
          memory: 50M
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert findings[0].service_name == "unlimited"
