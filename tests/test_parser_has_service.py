from docker_compose_validator.parser import ComposeParser

def test_has_service():
    yml = "services:\n  redis:\n    image: redis:alpine\n"
    parsed = ComposeParser.parse_string(yml)
    assert parsed.has_service("redis") is True
    assert parsed.has_service("nonexistent") is False
