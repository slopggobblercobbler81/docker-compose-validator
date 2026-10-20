"""Tests for syntax rules (SYN001, SYN002, SYN003)."""

from docker_compose_validator.models import Severity
from docker_compose_validator.parser import ComposeParser
from docker_compose_validator.rules.syntax import EmptyServicesRule, InvalidYamlRule, MissingServicesRule


def test_syn001_invalid_yaml():
    rule = InvalidYamlRule()
    parsed = ComposeParser.parse_string("services:\n  broken: [missing closing bracket", "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert findings[0].rule_id == "SYN001"
    assert findings[0].severity == Severity.CRITICAL


def test_syn001_valid_yaml():
    rule = InvalidYamlRule()
    parsed = ComposeParser.parse_string("services:\n  app:\n    image: alpine:3.18", "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 0


def test_syn002_missing_services():
    rule = MissingServicesRule()
    parsed = ComposeParser.parse_string("version: '3.8'\nnetworks:\n  net1:\n", "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert findings[0].rule_id == "SYN002"
    assert "Missing top-level 'services'" in findings[0].message


def test_syn002_services_not_a_mapping():
    rule = MissingServicesRule()
    parsed = ComposeParser.parse_string("services:\n  - item1\n  - item2\n", "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert findings[0].rule_id == "SYN002"
    assert "must be a mapping" in findings[0].message


def test_syn003_empty_services():
    rule = EmptyServicesRule()
    parsed = ComposeParser.parse_string("services: {}\n", "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert findings[0].rule_id == "SYN003"
    assert "contains no service entries" in findings[0].message
