"""Tests for security validation rules (SEC001-SEC007)."""

from docker_compose_validator.models import Severity
from docker_compose_validator.parser import ComposeParser
from docker_compose_validator.rules.security import (
    DangerousCapabilitiesRule,
    DockerSocketMountRule,
    HostNamespaceRule,
    InsecurePortRule,
    PlaintextSecretsRule,
    PrivilegedModeRule,
    RootUserRule,
)


def test_sec001_root_user_missing():
    rule = RootUserRule()
    parsed = ComposeParser.parse_string("services:\n  app:\n    image: node:20-alpine", "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"
    assert "runs as root by default" in findings[0].message


def test_sec001_root_user_explicit():
    rule = RootUserRule()
    parsed = ComposeParser.parse_string(
        "services:\n  app:\n    image: node:20-alpine\n    user: '0:0'", "test.yml"
    )
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert "explicitly runs as root" in findings[0].message


def test_sec001_non_root_user_passes():
    rule = RootUserRule()
    parsed = ComposeParser.parse_string(
        "services:\n  app:\n    image: node:20-alpine\n    user: '1000:1000'", "test.yml"
    )
    findings = rule.check(parsed)
    assert len(findings) == 0


def test_sec002_insecure_port_exposed():
    rule = InsecurePortRule()
    # Sensitive ports: 3306 (MySQL), 5432 (Postgres), 6379 (Redis)
    content = """
services:
  db:
    image: postgres:15-alpine
    ports:
      - "5432:5432"
  cache:
    image: redis:7-alpine
    ports:
      - "0.0.0.0:6379:6379"
  web:
    image: nginx:1.25-alpine
    ports:
      - "80:80"
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    # db and cache should trigger SEC002, web (port 80) should not
    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"SEC002"}
    services = {f.service_name for f in findings}
    assert services == {"db", "cache"}


def test_sec002_loopback_port_binding_passes():
    rule = InsecurePortRule()
    content = """
services:
  db:
    image: postgres:15-alpine
    ports:
      - "127.0.0.1:5432:5432"
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 0


def test_sec002_dict_port_syntax():
    rule = InsecurePortRule()
    content = """
services:
  db:
    image: mysql:8.0
    ports:
      - target: 3306
        published: 3306
        protocol: tcp
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert "3306" in findings[0].message


def test_sec003_privileged_mode():
    rule = PrivilegedModeRule()
    content = """
services:
  worker:
    image: alpine:3.18
    privileged: true
  web:
    image: alpine:3.18
    privileged: false
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC003"
    assert findings[0].service_name == "worker"
    assert findings[0].severity == Severity.CRITICAL


def test_sec004_docker_socket_mount():
    rule = DockerSocketMountRule()
    content = """
services:
  builder:
    image: docker:cli
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  traefik:
    image: traefik:v2.10
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
  app:
    image: alpine:3.18
    volumes:
      - ./data:/app/data
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 2
    services = {f.service_name for f in findings}
    assert services == {"builder", "traefik"}


def test_sec005_plaintext_secrets_in_env():
    rule = PlaintextSecretsRule()
    content = """
services:
  app:
    image: myapp:1.0
    environment:
      DB_PASSWORD: "super_secret_password"
      API_KEY: "prod-xyz-987"
      SAFE_SECRET: "${EXTERNAL_PASS}"
      NORMAL_VAR: "production"
  worker:
    image: worker:1.0
    environment:
      - AUTH_TOKEN=my-static-token-12345
      - VAR2=${INTERPOLATED}
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 3
    # Check that secrets are masked in message
    for f in findings:
        assert "super_secret_password" not in f.message
        assert "prod-xyz-987" not in f.message
        assert "my-static-token-12345" not in f.message


def test_sec006_host_namespaces():
    rule = HostNamespaceRule()
    content = """
services:
  monitor:
    image: netdata/netdata
    network_mode: host
    pid: host
    ipc: host
  regular:
    image: alpine:3.18
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 3
    for f in findings:
        assert f.service_name == "monitor"
        assert f.rule_id == "SEC006"


def test_sec007_dangerous_capabilities():
    rule = DangerousCapabilitiesRule()
    content = """
services:
  bad_app:
    image: alpine:3.18
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
  safe_app:
    image: alpine:3.18
    cap_add:
      - CHOWN
      - SETUID
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 2
    assert findings[0].service_name == "bad_app"
    assert findings[1].service_name == "bad_app"


def test_sec007_additional_dangerous_capabilities():
    rule = DangerousCapabilitiesRule()
    content = """
services:
  rawio_app:
    image: alpine:3.18
    cap_add:
      - SYS_RAWIO
      - CAP_SYS_BOOT
      - MAC_ADMIN
"""
    parsed = ComposeParser.parse_string(content, "test.yml")
    findings = rule.check(parsed)
    assert len(findings) == 3
    caps = {f.details["capability"] for f in findings}
    assert "SYS_RAWIO" in caps
    assert "CAP_SYS_BOOT" in caps
    assert "MAC_ADMIN" in caps
