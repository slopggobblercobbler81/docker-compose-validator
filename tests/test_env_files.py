import pytest
from docker_compose_validator.parser import ComposeParser

def test_env_file_equals_in_values(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("DATABASE_URL=postgres://user:pass@localhost:5432/db?sslmode=disable\nCOMPLEX_VAL=foo=bar=baz\n")
    
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(f"""
version: '3.8'
services:
  web:
    image: nginx:alpine
    env_file:
      - {env_file}
""")
    
    parsed = ComposeParser.parse_file(str(compose_file))
    assert parsed.is_valid_yaml

def test_env_file_empty_quoted_strings(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text('EMPTY_VAL=""\nEMPTY_SINGLE=\'\'\n')
    
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(f"""
version: '3.8'
services:
  web:
    image: nginx:alpine
    env_file:
      - {env_file}
""")
    
    parsed = ComposeParser.parse_file(str(compose_file))
    assert parsed.is_valid_yaml
