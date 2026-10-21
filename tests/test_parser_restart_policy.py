from docker_compose_validator.parser import ComposeParser

def test_get_service_restart_policy():
    yml = "services:\n  web:\n    image: nginx\n    restart: always\n"
    parsed = ComposeParser.parse_string(yml)
    assert parsed.get_service_restart_policy("web") == "always"
