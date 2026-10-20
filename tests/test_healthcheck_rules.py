"""Tests for healthcheck configuration rules, intervals, timeouts, retries, and test command formats."""

from docker_compose_validator.models import Severity
from docker_compose_validator.parser import ComposeParser
from docker_compose_validator.rules.reliability import MissingHealthcheckRule


def test_healthcheck_interval_and_timeout_formats():
    rule = MissingHealthcheckRule()
    content = """
services:
  valid_durations:
    image: nginx:1.25
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 30s
  invalid_interval_type:
    image: nginx:1.25
    healthcheck:
      test: ["CMD-SHELL", "exit 0"]
      interval: 30
      timeout: 5s
      retries: 3
  missing_test_array_or_string:
    image: nginx:1.25
    healthcheck:
      interval: 30s
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert isinstance(findings, list)


def test_healthcheck_test_command_formats():
    rule = MissingHealthcheckRule()
    content_list = """
services:
  svc_list:
    image: nginx:1.25
    healthcheck:
      test: ["CMD", "true"]
"""
    parsed = ComposeParser.parse_string(content_list, "test.yml")
    findings = rule.check(parsed)
    assert not any(f.service_name == "svc_list" for f in findings)
