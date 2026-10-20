"""Tests for CLI flags, exit codes, and workflows."""

import tempfile
from pathlib import Path
import pytest

from docker_compose_validator.cli import main


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "docker-compose-validator" in captured.out or "1.0.0" in captured.out


def test_cli_list_rules(capsys):
    code = main(["--list-rules"])
    assert code == 0
    captured = capsys.readouterr()
    assert "SEC001" in captured.out
    assert "REL001" in captured.out
    assert "SYN001" in captured.out
    assert "BP001" in captured.out


def test_cli_clean_file_passes():
    clean_compose = """
services:
  web:
    image: nginx:1.25.3-alpine
    user: "1000:1000"
    restart: unless-stopped
    mem_limit: 512m
    cpus: "1.0"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
    ports:
      - "127.0.0.1:8080:80"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tmp:
        tmp.write(clean_compose)
        tmp_path = tmp.name

    try:
        code = main([tmp_path])
        assert code == 0
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_cli_violation_fails_on_medium():
    insecure_compose = """
services:
  redis:
    image: redis:latest
    ports:
      - "6379:6379"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tmp:
        tmp.write(insecure_compose)
        tmp_path = tmp.name

    try:
        # Default fail-on is medium, this triggers SEC001, SEC002, REL001, REL002
        code = main([tmp_path])
        assert code == 1

        # With --fail-on critical, medium & high won't trigger exit 1
        code_crit = main([tmp_path, "--fail-on", "critical"])
        assert code_crit == 0

        # With --fail-on none, never fails
        code_none = main([tmp_path, "--fail-on", "none"])
        assert code_none == 0
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_cli_ignore_flag():
    insecure_compose = """
services:
  web:
    image: nginx:latest
    restart: unless-stopped
    user: "1000:1000"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tmp:
        tmp.write(insecure_compose)
        tmp_path = tmp.name

    try:
        # REL002 is triggered by nginx:latest. With ignore, it should pass
        code_ignored = main([tmp_path, "--ignore", "REL002,REL003,REL004,BP003"])
        assert code_ignored == 0
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_cli_select_flag():
    insecure_compose = """
services:
  web:
    image: nginx:latest
    restart: "no"
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tmp:
        tmp.write(insecure_compose)
        tmp_path = tmp.name

    try:
        # Select only BP001 (which does not trigger here)
        code = main([tmp_path, "--select", "BP001"])
        assert code == 0
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_cli_output_to_file():
    insecure_compose = """
services:
  web:
    image: nginx:1.25
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tmp:
        tmp.write(insecure_compose)
        tmp_path = tmp.name

    out_file = Path(tmp_path).with_suffix(".json")
    try:
        code = main([tmp_path, "--format", "json", "-o", str(out_file), "--fail-on", "none"])
        assert code == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "summary" in content
    finally:
        Path(tmp_path).unlink(missing_ok=True)
        out_file.unlink(missing_ok=True)


def test_cli_nonexistent_target(capsys):
    code = main(["nonexistent_folder_or_file_xyz_9999.yml"])
    assert code == 2
    captured = capsys.readouterr()
    assert "does not exist" in captured.err.lower()
