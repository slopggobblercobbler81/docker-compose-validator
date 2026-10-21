"""Security-focused validation rules for Docker Compose."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from docker_compose_validator.models import Category, Finding, Severity
from docker_compose_validator.parser import LineDict, LineList, ParsedComposeFile
from docker_compose_validator.rules.base import BaseRule, RuleRegistry


# Well-known sensitive and database ports that should not be exposed to 0.0.0.0
SENSITIVE_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    2181: "Apache ZooKeeper",
    2375: "Docker Daemon (Unencrypted HTTP)",
    2376: "Docker Daemon (TLS)",
    2379: "etcd client",
    2380: "etcd peer",
    3306: "MySQL / MariaDB",
    445: "SMB",
    5432: "PostgreSQL",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    7474: "Neo4j",
    8500: "Consul",
    8529: "ArangoDB",
    9042: "Apache Cassandra",
    9092: "Apache Kafka",
    9200: "Elasticsearch HTTP",
    9300: "Elasticsearch Node Comms",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB Shard",
    27019: "MongoDB Config Server",
}

SECRET_KEY_PATTERN = re.compile(
    r"(?:password|passwd|pwd|secret|api[_-]?key|token|auth[_-]?token|private[_-]?key|access[_-]?key|credentials)",
    re.IGNORECASE,
)

ENV_INTERPOLATION_PATTERN = re.compile(r"^\$\{[^}]+\}$|^\$[A-Za-z0-9_]+$")


def _is_loopback_ip(ip: str) -> bool:
    """Checks if an IP address is loopback (localhost only)."""
    ip = ip.strip()
    return (
        ip == "127.0.0.1"
        or ip == "localhost"
        or ip.startswith("127.")
        or ip == "::1"
        or ip == "[::1]"
    )


def _parse_port_entry(port_spec: Union[str, int, dict]) -> Optional[Tuple[Optional[str], Optional[int], int]]:
    """
    Parses a Docker Compose port entry into (host_ip, host_port, container_port).
    Returns None if cannot be determined.
    """
    if isinstance(port_spec, int):
        # Just container port published to random host port or internal
        return (None, None, port_spec)

    if isinstance(port_spec, dict):
        host_ip = port_spec.get("host_ip")
        published = port_spec.get("published")
        target = port_spec.get("target")
        try:
            target_int = int(target) if target is not None else 0
            pub_int = int(published) if published is not None else None
            return (host_ip, pub_int, target_int)
        except (ValueError, TypeError):
            return None

    if not isinstance(port_spec, str):
        return None

    port_str = port_spec.strip().split("/")[0]  # Strip protocol (/tcp, /udp)

    # Patterns:
    # 1. "target"
    # 2. "published:target"
    # 3. "ip:published:target"
    # 4. "ip::target"
    parts = port_str.split(":")
    if len(parts) == 1:
        try:
            return (None, None, int(parts[0]))
        except ValueError:
            return None
    elif len(parts) == 2:
        try:
            pub = int(parts[0]) if parts[0] else None
            target = int(parts[1])
            return ("0.0.0.0", pub, target)
        except ValueError:
            return None
    elif len(parts) == 3:
        host_ip = parts[0]
        pub = int(parts[1]) if parts[1] else None
        try:
            target = int(parts[2])
            return (host_ip, pub, target)
        except ValueError:
            return None

    return None


@RuleRegistry.register
class RootUserRule(BaseRule):
    """Rule detecting containers running as default root."""
    rule_id = "SEC001"
    name = "root-user-container"
    description = "Checks that containers specify a non-root user for execution."
    severity = Severity.HIGH
    category = Category.SECURITY
    recommendation = (
        "Specify a non-root user in the service definition (e.g. `user: '1000:1000'` or `user: 'appuser'`)."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            user_val = svc_cfg.get("user")
            line = parsed.get_service_field_line(svc_name, "user") or parsed.get_service_line(svc_name)

            if parsed.is_rule_ignored(self.rule_id, line):
                continue

            if user_val is None:
                findings.append(
                    self.create_finding(
                        parsed=parsed,
                        message=f"Service '{svc_name}' does not specify a 'user' directive and runs as root by default.",
                        line_number=line,
                        service_name=svc_name,
                    )
                )
            else:
                user_str = str(user_val).strip()
                if user_str in ("0", "root", "0:0", "root:root"):
                    findings.append(
                        self.create_finding(
                            parsed=parsed,
                            message=f"Service '{svc_name}' explicitly runs as root user (`user: {user_val}`).",
                            line_number=line,
                            service_name=svc_name,
                        )
                    )

        return findings


@RuleRegistry.register
class InsecurePortRule(BaseRule):
    """Rule detecting sensitive/internal ports exposed publicly or to 0.0.0.0."""
    rule_id = "SEC002"
    name = "insecure-exposed-ports"
    description = "Checks for sensitive database and management ports exposed to 0.0.0.0 or without IP restriction."
    severity = Severity.HIGH
    category = Category.SECURITY
    recommendation = (
        "Bind sensitive ports to loopback (e.g. `127.0.0.1:PORT:PORT`) or use Docker internal network routing."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            ports = svc_cfg.get("ports")
            if not ports or not isinstance(ports, list):
                continue

            ports_line = parsed.get_service_field_line(svc_name, "ports")

            for idx, port_entry in enumerate(ports):
                entry_line = None
                if isinstance(ports, LineList):
                    entry_line = ports.get_line(idx)
                entry_line = entry_line or ports_line

                if parsed.is_rule_ignored(self.rule_id, entry_line):
                    continue

                parsed_port = _parse_port_entry(port_entry)
                if not parsed_port:
                    continue

                host_ip, host_port, container_port = parsed_port
                # Check if this port is a known sensitive port
                target_port = container_port or host_port
                if target_port in SENSITIVE_PORTS:
                    # If host_port is published and host_ip is not restricted to loopback
                    if host_port is not None and (host_ip is None or not _is_loopback_ip(host_ip)):
                        port_name = SENSITIVE_PORTS[target_port]
                        ip_display = host_ip if host_ip else "0.0.0.0 (all interfaces)"
                        findings.append(
                            self.create_finding(
                                parsed=parsed,
                                message=(
                                    f"Service '{svc_name}' exposes sensitive port {target_port} ({port_name}) "
                                    f"on {ip_display} via '{port_entry}'."
                                ),
                                line_number=entry_line,
                                service_name=svc_name,
                                details={
                                    "port": target_port,
                                    "service_type": port_name,
                                    "binding": str(port_entry),
                                },
                            )
                        )

        return findings


@RuleRegistry.register
class PrivilegedModeRule(BaseRule):
    """Rule detecting containers running in privileged mode."""
    rule_id = "SEC003"
    name = "privileged-container"
    description = "Checks that containers do not run with 'privileged: true'."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    recommendation = (
        "Remove `privileged: true`. Grant only specific Linux capabilities using `cap_add` if strictly required."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            privileged = svc_cfg.get("privileged")
            if privileged is True or str(privileged).lower() == "true":
                line = parsed.get_service_field_line(svc_name, "privileged")
                if parsed.is_rule_ignored(self.rule_id, line):
                    continue
                findings.append(
                    self.create_finding(
                        parsed=parsed,
                        message=f"Service '{svc_name}' runs in privileged mode, granting full host kernel capabilities.",
                        line_number=line,
                        service_name=svc_name,
                    )
                )

        return findings


@RuleRegistry.register
class DockerSocketMountRule(BaseRule):
    """Rule detecting Docker daemon socket mounted inside containers."""
    rule_id = "SEC004"
    name = "docker-socket-mount"
    description = "Checks that the Docker daemon socket is not mounted into container volumes."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    recommendation = (
        "Do not mount `/var/run/docker.sock`. Use Docker context, rootless Docker, or a scoped API proxy."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            volumes = svc_cfg.get("volumes")
            if not volumes or not isinstance(volumes, list):
                continue

            vol_line = parsed.get_service_field_line(svc_name, "volumes")

            for idx, vol in enumerate(volumes):
                entry_line = None
                if isinstance(volumes, LineList):
                    entry_line = volumes.get_line(idx)
                entry_line = entry_line or vol_line

                if parsed.is_rule_ignored(self.rule_id, entry_line):
                    continue

                is_docker_sock = False
                if isinstance(vol, str):
                    if "docker.sock" in vol.lower():
                        is_docker_sock = True
                elif isinstance(vol, dict):
                    source = str(vol.get("source", "")).lower()
                    if "docker.sock" in source:
                        is_docker_sock = True

                if is_docker_sock:
                    findings.append(
                        self.create_finding(
                            parsed=parsed,
                            message=f"Service '{svc_name}' mounts the Docker socket ('{vol}'), enabling container escape.",
                            line_number=entry_line,
                            service_name=svc_name,
                            details={"volume": str(vol)},
                        )
                    )

        return findings


@RuleRegistry.register
class PlaintextSecretsRule(BaseRule):
    """Rule detecting plaintext secrets, tokens, and passwords in environment variables."""
    rule_id = "SEC005"
    name = "plaintext-secrets-in-env"
    description = "Checks for hardcoded plaintext passwords, secrets, and API keys in environment declarations."
    severity = Severity.HIGH
    category = Category.SECURITY
    recommendation = (
        "Store secrets in external environment files (`.env`), use variable interpolation (`${VAR}`), or Docker secrets."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            env = svc_cfg.get("environment")
            if not env:
                continue

            env_line = parsed.get_service_field_line(svc_name, "environment")

            # Environment can be a dict or a list of "KEY=VALUE"
            items_to_check: List[Tuple[str, Any, Optional[int]]] = []
            if isinstance(env, dict):
                for k, v in env.items():
                    key_line = None
                    if isinstance(env, LineDict):
                        key_line = env.get_line(k)
                    items_to_check.append((k, v, key_line or env_line))
            elif isinstance(env, list):
                for idx, entry in enumerate(env):
                    elem_line = None
                    if isinstance(env, LineList):
                        elem_line = env.get_line(idx)
                    if isinstance(entry, str) and "=" in entry:
                        parts = entry.split("=", 1)
                        items_to_check.append((parts[0].strip(), parts[1].strip(), elem_line or env_line))

            for key, val, line_num in items_to_check:
                if parsed.is_rule_ignored(self.rule_id, line_num):
                    continue

                if SECRET_KEY_PATTERN.search(key):
                    val_str = str(val).strip() if val is not None else ""
                    # If empty or uses interpolation like ${DB_PASSWORD} or $DB_PASSWORD, safe
                    if not val_str or ENV_INTERPOLATION_PATTERN.match(val_str):
                        continue

                    # Mask secret in finding
                    masked = val_str[:2] + "*" * (max(len(val_str) - 2, 4)) if len(val_str) > 2 else "****"
                    findings.append(
                        self.create_finding(
                            parsed=parsed,
                            message=f"Service '{svc_name}' contains plain-text secret '{key}={masked}' in environment.",
                            line_number=line_num,
                            service_name=svc_name,
                            details={"variable": key},
                        )
                    )

        return findings


@RuleRegistry.register
class HostNamespaceRule(BaseRule):
    """Rule detecting host namespace sharing (network, pid, ipc)."""
    rule_id = "SEC006"
    name = "host-namespace-sharing"
    description = "Checks that containers do not share host networking, PID, or IPC namespaces."
    severity = Severity.HIGH
    category = Category.SECURITY
    recommendation = (
        "Isolate containers using custom bridge networks and avoid host PID/IPC sharing."
    )

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        host_keys = [
            ("network_mode", "host", "host network mode"),
            ("pid", "host", "host PID namespace"),
            ("ipc", "host", "host IPC namespace"),
        ]

        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            for field_name, bad_value, desc in host_keys:
                val = str(svc_cfg.get(field_name, "")).strip().lower()
                if val == bad_value:
                    line = parsed.get_service_field_line(svc_name, field_name)
                    if parsed.is_rule_ignored(self.rule_id, line):
                        continue
                    findings.append(
                        self.create_finding(
                            parsed=parsed,
                            message=f"Service '{svc_name}' shares {desc} with the host (`{field_name}: {val}`).",
                            line_number=line,
                            service_name=svc_name,
                        )
                    )

        return findings


@RuleRegistry.register
class DangerousCapabilitiesRule(BaseRule):
    """Rule detecting dangerous Linux capabilities added to containers."""
    rule_id = "SEC007"
    name = "dangerous-capabilities"
    description = "Checks that containers do not add dangerous Linux capabilities (SYS_ADMIN, ALL, etc.)."
    severity = Severity.HIGH
    category = Category.SECURITY
    recommendation = (
        "Drop unnecessary capabilities with `cap_drop: [ALL]` and add only minimal specific capabilities."
    )

    DANGEROUS_CAPS: Set[str] = {
        "ALL",
        "SYS_ADMIN",
        "CAP_SYS_ADMIN",
        "SYS_PTRACE",
        "CAP_SYS_PTRACE",
        "NET_ADMIN",
        "CAP_NET_ADMIN",
        "SYS_MODULE",
        "CAP_SYS_MODULE",
        "DAC_OVERRIDE",
        "CAP_DAC_OVERRIDE",
        "SYS_RAWIO",
        "CAP_SYS_RAWIO",
        "SYS_BOOT",
        "CAP_SYS_BOOT",
        "MAC_ADMIN",
        "CAP_MAC_ADMIN",
        "SYS_CHROOT",
        "CAP_SYS_CHROOT",
        "MKNOD",
        "CAP_MKNOD",
        "AUDIT_CONTROL",
        "CAP_AUDIT_CONTROL",
        "SYSLOG",
        "CAP_SYSLOG",
    }

    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        findings: List[Finding] = []
        for svc_name, svc_cfg in parsed.services.items():
            if not isinstance(svc_cfg, dict):
                continue

            cap_add = svc_cfg.get("cap_add")
            if not cap_add or not isinstance(cap_add, list):
                continue

            cap_line = parsed.get_service_field_line(svc_name, "cap_add")

            for idx, cap in enumerate(cap_add):
                cap_str = str(cap).strip().upper()
                entry_line = None
                if isinstance(cap_add, LineList):
                    entry_line = cap_add.get_line(idx)
                entry_line = entry_line or cap_line

                if parsed.is_rule_ignored(self.rule_id, entry_line):
                    continue

                if cap_str in self.DANGEROUS_CAPS:
                    findings.append(
                        self.create_finding(
                            parsed=parsed,
                            message=f"Service '{svc_name}' grants dangerous Linux capability '{cap_str}'.",
                            line_number=entry_line,
                            service_name=svc_name,
                            details={"capability": cap_str},
                        )
                    )

        return findings
