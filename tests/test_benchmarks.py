"""Benchmark and performance tests for docker-compose-validator."""

import time
from docker_compose_validator.parser import ComposeParser
from docker_compose_validator.runner import ValidationRunner
from docker_compose_validator.rules.base import RuleRegistry


def _generate_multi_service_compose(service_count: int) -> str:
    """Generate a valid Compose file YAML string with N services."""
    services = []
    for i in range(service_count):
        services.append(
            f"""  service_{i}:
    image: redis:7.2-alpine
    user: "1000:1000"
    restart: "unless-stopped"
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: "0.5"
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3"""
        )
    return "services:\n" + "\n".join(services) + "\n"


def test_parser_benchmark_large_file():
    """Benchmark ComposeParser parsing performance on a 50-service Compose configuration."""
    yaml_content = _generate_multi_service_compose(50)

    start_time = time.perf_counter()
    parsed = ComposeParser.parse_string(yaml_content, "benchmark_50.yml")
    elapsed = time.perf_counter() - start_time

    assert parsed.is_valid_yaml is True
    assert len(parsed.services) == 50
    # Parsing 50 services should complete in under 2.0 seconds
    assert elapsed < 2.0


def test_validation_runner_benchmark_large_file():
    """Benchmark ValidationRunner execution throughput on multi-service configurations."""
    yaml_content = _generate_multi_service_compose(50)
    runner = ValidationRunner()

    start_time = time.perf_counter()
    result = runner.validate_string(yaml_content, file_path="benchmark_runner_50.yml")
    elapsed = time.perf_counter() - start_time

    assert result.service_count == 50
    assert result.is_valid_syntax is True
    # Clean compose file should have zero security/reliability/syntax findings
    assert result.has_findings is False
    # Validating all rules against 50 services should execute in under 3.0 seconds
    assert elapsed < 3.0


def test_individual_rules_benchmark():
    """Benchmark each individual rule's execution latency."""
    yaml_content = _generate_multi_service_compose(25)
    parsed = ComposeParser.parse_string(yaml_content, "benchmark_rules.yml")

    rules = RuleRegistry.all_rules()
    assert len(rules) > 0

    for rule in rules:
        start = time.perf_counter()
        findings = rule.check(parsed)
        duration = time.perf_counter() - start

        # Individual rule check across 25 services should take well under 1 second
        assert duration < 1.0
        assert isinstance(findings, list)
