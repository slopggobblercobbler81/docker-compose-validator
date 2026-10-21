from docker_compose_validator.parser import ComposeParser

def test_get_service_volumes():
    yml = "services:\n  db:\n    image: postgres\n    volumes:\n      - ./data:/var/lib/postgresql/data\n"
    parsed = ComposeParser.parse_string(yml)
    vols = parsed.get_service_volumes("db")
    assert vols == ["./data:/var/lib/postgresql/data"]
