from docker_compose_validator.parser import ComposeParser

def test_get_service_names():
    yml = "services:\n  frontend:\n    image: node\n  backend:\n    image: python\n"
    parsed = ComposeParser.parse_string(yml)
    names = parsed.get_service_names()
    assert names == ["frontend", "backend"]
