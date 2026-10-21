from docker_compose_validator.parser import ComposeParser

def test_get_service_ports():
    yml = "services:\n  web:\n    image: nginx\n    ports:\n      - '8080:80'\n"
    parsed = ComposeParser.parse_string(yml)
    ports = parsed.get_service_ports("web")
    assert ports == ["8080:80"]
