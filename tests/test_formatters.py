"""Tests for report formatters (Table, JSON, SARIF, Markdown, Quiet)."""

import json
from docker_compose_validator.formatter import (
    JsonFormatter,
    MarkdownFormatter,
    QuietFormatter,
    SarifFormatter,
    TableFormatter,
)
from docker_compose_validator.models import Category, Finding, Severity, ValidationReport, ValidationResult


def _make_dummy_report() -> ValidationReport:
    finding1 = Finding(
        rule_id="SEC001",
        rule_name="root-user-container",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        message="Service 'app' runs as root by default.",
        file_path="docker-compose.yml",
        line_number=4,
        service_name="app",
        recommendation="Specify non-root user.",
    )
    finding2 = Finding(
        rule_id="REL001",
        rule_name="missing-restart-policy",
        severity=Severity.MEDIUM,
        category=Category.RELIABILITY,
        message="Service 'app' has no restart policy.",
        file_path="docker-compose.yml",
        line_number=4,
        service_name="app",
        recommendation="Set restart: unless-stopped.",
    )
    res = ValidationResult(
        file_path="docker-compose.yml",
        findings=[finding1, finding2],
        is_valid_syntax=True,
        service_count=1,
        scanned_rules_count=10,
    )
    return ValidationReport(results=[res], total_files=1, total_services=1)


def test_table_formatter():
    report = _make_dummy_report()
    out = TableFormatter.format(report, use_color=False)
    assert "docker-compose.yml" in out
    assert "SEC001" in out
    assert "REL001" in out
    assert "SCAN SUMMARY" in out
    assert "Total findings:   2" in out


def test_table_formatter_clean():
    clean_res = ValidationResult(
        file_path="clean.yml",
        findings=[],
        is_valid_syntax=True,
        service_count=2,
    )
    report = ValidationReport(results=[clean_res], total_files=1, total_services=2)
    out = TableFormatter.format(report, use_color=False)
    assert "All docker-compose checks passed" in out


def test_json_formatter():
    report = _make_dummy_report()
    raw_json = JsonFormatter.format(report)
    parsed = json.loads(raw_json)
    assert "summary" in parsed
    assert parsed["summary"]["total_findings"] == 2
    assert parsed["summary"]["high"] == 1
    assert parsed["summary"]["medium"] == 1
    assert len(parsed["files"]) == 1
    assert parsed["files"][0]["findings_count"] == 2


def test_sarif_formatter():
    report = _make_dummy_report()
    raw_sarif = SarifFormatter.format(report)
    parsed = json.loads(raw_sarif)
    assert parsed["version"] == "2.1.0"
    assert "runs" in parsed
    run = parsed["runs"][0]
    assert run["tool"]["driver"]["name"] == "docker-compose-validator"
    assert len(run["results"]) == 2
    rule_ids = {r["ruleId"] for r in run["results"]}
    assert "SEC001" in rule_ids
    assert "REL001" in rule_ids


def test_markdown_formatter():
    report = _make_dummy_report()
    md = MarkdownFormatter.format(report)
    assert "# Docker Compose Validation Report" in md
    assert "| Critical | High | Medium | Low | Info |" in md
    assert "`SEC001`" in md
    assert "`docker-compose.yml:4`" in md


def test_quiet_formatter():
    report = _make_dummy_report()
    quiet = QuietFormatter.format(report)
    lines = quiet.strip().splitlines()
    assert len(lines) == 2
    assert "docker-compose.yml:4: [HIGH] [SEC001] [app]" in lines[0]
    assert "docker-compose.yml:4: [MEDIUM] [REL001] [app]" in lines[1]
