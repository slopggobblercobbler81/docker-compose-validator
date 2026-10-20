import pytest
from docker_compose_validator.parser import ComposeParser

def test_network_mode_syntax_valid():
    content = """
    services:
      web:
        image: nginx:alpine
        network_mode: "host"
      app:
        image: myapp:latest
        network_mode: "none"
      db:
        image: postgres:15
        network_mode: "service:web"
    """
    parsed = ComposeParser.parse_string(content)
    assert parsed.is_valid_yaml is True
    assert parsed.services["web"]["network_mode"] == "host"
    assert parsed.services["app"]["network_mode"] == "none"
    assert parsed.services["db"]["network_mode"] == "service:web"
