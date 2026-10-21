from docker_compose_validator.parser import ComposeParser

def test_get_service_environment():
    yml = "services:\n  app:\n    image: python\n    environment:\n      MODE: production\n"
    parsed = ComposeParser.parse_string(yml)
    env = parsed.get_service_environment("app")
    assert env == {"MODE": "production"}
