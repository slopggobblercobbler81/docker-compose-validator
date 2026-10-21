import pytest
from docker_compose_validator.parser import ComposeParser

def test_extra_hosts_syntax_valid():
    content = """
    services:
      web:
        image: nginx:alpine
        extra_hosts:
          - "somehost:162.242.195.82"
          - "otherhost:50.116.42.210"
      app:
        image: myapp:latest
        extra_hosts:
          apphost: "192.168.1.100"
          dbhost: "192.168.1.101"
    """
    parsed = ComposeParser.parse_string(content)
    assert parsed.is_valid_yaml is True
    assert "somehost:162.242.195.82" in parsed.services["web"]["extra_hosts"]
    assert parsed.services["app"]["extra_hosts"]["apphost"] == "192.168.1.100"
