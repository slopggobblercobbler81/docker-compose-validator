"""Tests for best practice rules (BP001-BP003)."""

from docker_compose_validator.models import Severity
from docker_compose_validator.parser import ComposeParser
from docker_compose_validator.rules.best_practice import (
    DeprecatedVersionRule,
    HardcodedContainerNameRule,
    MissingLoggingConfigRule,
)


def test_bp001_deprecated_version():
    rule = DeprecatedVersionRule()
    parsed_with_version = ComposeParser.parse_string("version: '3.8'\nservices:\n  app:\n    image: app:1.0", "test.yml")
    findings = rule.check(parsed_with_version)
    assert len(findings) == 1
    assert findings[0].rule_id == "BP001"
    assert findings[0].severity == Severity.INFO

    parsed_without_version = ComposeParser.parse_string("services:\n  app:\n    image: app:1.0", "test.yml")
    assert len(rule.check(parsed_without_version)) == 0


def test_bp002_hardcoded_container_name():
    rule = HardcodedContainerNameRule()
    content = """
services:
  static_svc:
    image: app:1.0
    container_name: production_static_backend
  dynamic_svc:
    image: app:1.0
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert findings[0].rule_id == "BP002"
    assert findings[0].service_name == "static_svc"


def test_bp003_missing_logging_limits():
    rule = MissingLoggingConfigRule()
    content = """
services:
  no_log:
    image: app:1.0
  with_log:
    image: app:1.0
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert findings[0].rule_id == "BP003"
    assert findings[0].service_name == "no_log"
