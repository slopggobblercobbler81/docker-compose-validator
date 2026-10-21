"""Tests for restart policy syntax and validation."""

from docker_compose_validator.parser import ComposeParser
from docker_compose_validator.rules.reliability import MissingRestartPolicyRule


def test_restart_policies_validation():
    rule = MissingRestartPolicyRule()
    content = """
services:
  service_always:
    image: nginx:alpine
    restart: "always"
  service_unless_stopped:
    image: nginx:alpine
    restart: "unless-stopped"
  service_on_failure:
    image: nginx:alpine
    restart: "on-failure:5"
  service_invalid:
    image: nginx:alpine
    restart: "invalid-policy"
  service_disabled:
    image: nginx:alpine
    restart: "no"
  service_missing:
    image: nginx:alpine
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    
    services = {f.service_name for f in findings}
    assert "service_missing" in services
    assert "service_disabled" in services
    assert "service_always" not in services
    assert "service_unless_stopped" not in services
    assert "service_on_failure" not in services
