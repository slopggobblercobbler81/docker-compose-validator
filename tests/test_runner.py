"""Tests for runner and directory discovery."""

import tempfile
from pathlib import Path
from docker_compose_validator.models import Severity
from docker_compose_validator.runner import ValidationRunner, find_compose_files


def test_find_compose_files_recursive():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        sub1 = base / "sub1"
        sub2 = base / "sub1" / "sub2"
        sub1.mkdir(parents=True)
        sub2.mkdir(parents=True)

        f1 = base / "docker-compose.yml"
        f2 = sub1 / "docker-compose.prod.yaml"
        f3 = sub2 / "compose.yaml"
        f4 = base / "ignored.txt"

        f1.write_text("services:\n  a:\n    image: a:1.0\n", encoding="utf-8")
        f2.write_text("services:\n  b:\n    image: b:1.0\n", encoding="utf-8")
        f3.write_text("services:\n  c:\n    image: c:1.0\n", encoding="utf-8")
        f4.write_text("not a compose file", encoding="utf-8")

        # Non-recursive
        found_shallow = find_compose_files([base], recursive=False)
        assert len(found_shallow) == 1
        assert found_shallow[0].name == "docker-compose.yml"

        # Recursive
        found_deep = find_compose_files([base], recursive=True)
        names = {p.name for p in found_deep}
        assert names == {"docker-compose.yml", "docker-compose.prod.yaml", "compose.yaml"}


def test_runner_validate_string():
    runner = ValidationRunner(min_severity=Severity.HIGH)
    raw = """
services:
  insecure:
    image: redis:latest
    privileged: true
"""
    result = runner.validate_string(raw, file_path="inline.yml")
    assert result.has_findings is True
    # SEC003 (CRITICAL) and SEC001 (HIGH) should be in findings since min_severity is HIGH
    rule_ids = {f.rule_id for f in result.findings}
    assert "SEC003" in rule_ids
    assert "SEC001" in rule_ids
    # REL002 (MEDIUM) should be filtered out by min_severity
    assert "REL002" not in rule_ids


def test_runner_run_multiple():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        f1 = base / "docker-compose.yml"
        f2 = base / "compose.yaml"
        f1.write_text("services:\n  web:\n    image: nginx:1.25\n", encoding="utf-8")
        f2.write_text("services:\n  api:\n    image: node:20\n", encoding="utf-8")

        runner = ValidationRunner()
        report = runner.run([f1, f2])
        assert report.total_files == 2
        assert report.total_services == 2
