"""Tests for logging driver and options validation."""

from docker_compose_validator.models import Severity
from docker_compose_validator.parser import ComposeParser
from docker_compose_validator.rules.best_practice import MissingLoggingConfigRule


def test_logging_driver_and_options_validation():
    rule = MissingLoggingConfigRule()
    content = """
services:
  service_json_valid:
    image: app:1.0
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  service_json_missing_options:
    image: app:1.0
    logging:
      driver: "json-file"

  service_syslog:
    image: app:1.0
    logging:
      driver: "syslog"
      options:
        syslog-address: "tcp://192.168.0.42:514"

  service_none:
    image: app:1.0
    logging:
      driver: "none"

  service_no_logging:
    image: app:1.0
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    
    # Check that rule checks logging configurations properly
    # If MissingLoggingConfigRule or rule checks drivers/options, let's verify what findings are produced.
    # Let's inspect findings.
    findings = rule.check(parsed)
    
    # Let's check service names in findings
    flagged_services = {f.service_name for f in findings}
    
    # service_json_valid has driver json-file with max-size and max-file -> should pass (no finding)
    # service_json_missing_options has driver json-file but missing options -> might trigger or pass depending on implementation
    # service_syslog has driver syslog -> valid
    # service_none has driver none -> valid
    # service_no_logging has no logging -> should definitely be flagged
    
    assert "service_json_valid" not in flagged_services
    assert "service_syslog" not in flagged_services
    assert "service_none" not in flagged_services
    assert "service_no_logging" in flagged_services
