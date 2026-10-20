"""Tests for ComposeParser and LineLoader."""

import tempfile
from pathlib import Path
import pytest

from docker_compose_validator.parser import ComposeParser, LineDict, LineList


def test_parse_valid_compose_string():
    content = """
services:
  web:
    image: nginx:1.25-alpine
    restart: unless-stopped
    ports:
      - "80:80"
"""
    parsed = ComposeParser.parse_string(content, file_path="test.yml")
    assert parsed.is_valid_yaml is True
    assert parsed.error_message is None
    assert "web" in parsed.services
    assert parsed.services["web"]["image"] == "nginx:1.25-alpine"

    # Line number checks
    assert parsed.get_service_line("web") == 3
    assert parsed.get_service_field_line("web", "image") == 4
    assert parsed.get_service_field_line("web", "restart") == 5


def test_parse_invalid_yaml_string():
    content = """
services:
  web:
    image: [unclosed list
"""
    parsed = ComposeParser.parse_string(content, file_path="bad.yml")
    assert parsed.is_valid_yaml is False
    assert parsed.error_message is not None
    assert parsed.error_line is not None


def test_parse_empty_string():
    parsed = ComposeParser.parse_string("", file_path="empty.yml")
    assert parsed.is_valid_yaml is False
    assert "empty" in parsed.error_message.lower()


def test_parse_nonexistent_file():
    parsed = ComposeParser.parse_file("does_not_exist_file_12345.yml")
    assert parsed.is_valid_yaml is False
    assert "not found" in parsed.error_message.lower()


def test_parse_file_from_disk():
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tmp:
        tmp.write("services:\n  app:\n    image: python:3.11\n")
        tmp_path = tmp.name

    try:
        parsed = ComposeParser.parse_file(tmp_path)
        assert parsed.is_valid_yaml is True
        assert "app" in parsed.services
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_inline_ignore_directives():
    content = """# docker-compose-validator: disable=SEC001,BP001
services:
  web:
    image: nginx:latest # dc-validator: ignore=REL002
    privileged: true
"""
    parsed = ComposeParser.parse_string(content, file_path="directives.yml")
    assert "SEC001" in parsed.file_ignores
    assert "BP001" in parsed.file_ignores
    assert parsed.is_rule_ignored("SEC001") is True
    assert parsed.is_rule_ignored("BP001") is True

    # Check line-specific ignore
    img_line = parsed.get_service_field_line("web", "image")
    assert parsed.is_rule_ignored("REL002", line_number=img_line) is True
    assert parsed.is_rule_ignored("SEC003", line_number=img_line) is False
