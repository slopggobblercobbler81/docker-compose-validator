# docker-compose-validator

[![CI](https://github.com/slopggobblercobbler81/docker-compose-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/slopggobblercobbler81/docker-compose-validator/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://pypi.org/project/docker-compose-validator/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: pytest](https://img.shields.io/badge/tests-100%25%20passed-brightgreen.svg)](https://github.com/slopggobblercobbler81/docker-compose-validator)

> **Production-grade Docker Compose linter, security auditor, and best-practices analyzer for CI/CD pipelines and developer workstations.**

`docker-compose-validator` inspects Docker Compose files (`docker-compose.yml`, `compose.yaml`) for security misconfigurations, syntax errors, missing reliability policies, unpinned images, container privilege escalation risks, and deprecated Compose patterns.

---

## Highlights

- 🔒 **Comprehensive Security Auditing**: Flags root user execution, sensitive ports exposed to `0.0.0.0`, privileged containers, Docker daemon socket mounts, plaintext secrets, dangerous capabilities, and host namespace sharing.
- ⚡ **Operational Reliability**: Identifies missing restart policies, unpinned image tags (`:latest`), missing healthchecks, and unbounded CPU/memory resource limits.
- 📍 **Exact Line-Number Tracking**: Pinpoints the exact line number of every violation in your compose files.
- 📊 **Multi-Format Output**: Beautiful ANSI terminal tables, JSON, Markdown (ready for GitHub PR comments), compact Unix format, and **OASIS SARIF 2.1.0** for native GitHub Code Scanning integration.
- 🛡️ **CI/CD Ready**: Configurable failure thresholds (`--fail-on`), strict mode, exit codes (0 for pass, 1 for violations, 2 for fatal error).
- 🏷️ **Flexible Overrides**: Ignore rules globally, per-command with `--ignore`, or inline via comments (`# docker-compose-validator: disable=SEC001`).
- 🪶 **Lightweight**: Zero external dependencies other than standard library and `PyYAML`.

---

## Installation

### From PyPI
```bash
pip install docker-compose-validator
```

### From Source
```bash
git clone https://github.com/slopggobblercobbler81/docker-compose-validator.git
cd docker-compose-validator
pip install -e .
```

---

## Quick Start

### 1. Scan default Compose files in current directory
```bash
docker-compose-validator
```

### 2. Scan a specific file
```bash
docker-compose-validator docker-compose.prod.yml
```

### 3. Scan a directory recursively
```bash
docker-compose-validator -r ./deployments
```

### 4. Output as SARIF for GitHub Code Scanning
```bash
docker-compose-validator --format sarif -o results.sarif
```

### 5. Enforce in CI (Fail on High or Critical only)
```bash
docker-compose-validator --fail-on high
```

---

## Rules Catalog

Run `docker-compose-validator --list-rules` anytime to view the built-in rule catalog:

| Rule ID | Severity | Category | Description |
|:---|:---:|:---:|:---|
| **`SYN001`** | `CRITICAL` | Syntax | Invalid YAML syntax or unparseable document structure. |
| **`SYN002`** | `CRITICAL` | Syntax | Missing or non-mapping top-level `services:` section. |
| **`SYN003`** | `HIGH` | Syntax | Top-level `services:` defined but contains no service entries. |
| **`SEC001`** | `HIGH` | Security | Service runs as root (missing `user:` or set to `0` / `root`). |
| **`SEC002`** | `HIGH` | Security | Sensitive port (DB, SSH, Redis, etc.) exposed without loopback binding. |
| **`SEC003`** | `CRITICAL` | Security | Container runs in privileged mode (`privileged: true`). |
| **`SEC004`** | `CRITICAL` | Security | Docker daemon socket (`/var/run/docker.sock`) mounted inside container. |
| **`SEC005`** | `HIGH` | Security | Plaintext secret, token, or password hardcoded in `environment:`. |
| **`SEC006`** | `HIGH` | Security | Container shares host namespaces (`network_mode: host`, `pid: host`, `ipc: host`). |
| **`SEC007`** | `HIGH` | Security | Container adds dangerous Linux capabilities (`SYS_ADMIN`, `ALL`, etc.). |
| **`REL001`** | `MEDIUM` | Reliability | Service has no restart policy defined or explicitly disabled (`restart: 'no'`). |
| **`REL002`** | `MEDIUM` | Reliability | Unpinned container image version (uses `:latest` or omitted tag). |
| **`REL003`** | `LOW` | Reliability | Missing `healthcheck:` for service readiness and monitoring. |
| **`REL004`** | `LOW` | Reliability | Container lacks CPU or memory limits (`mem_limit` / `deploy.resources.limits`). |
| **`BP001`** | `INFO` | Best Practice | Obsolete top-level `version:` attribute in modern Compose spec. |
| **`BP002`** | `INFO` | Best Practice | Static `container_name:` prevents horizontal scaling (`--scale`). |
| **`BP003`** | `INFO` | Best Practice | Missing container logging limits (`max-size` / `max-file`). |

---

## CLI Options Reference

```text
usage: docker-compose-validator [-h] [-f EXPLICIT_FILES] [-r]
                                [--format {table,json,sarif,markdown,quiet}]
                                [--min-severity {info,low,medium,high,critical}]
                                [--fail-on {none,info,low,medium,high,critical}]
                                [--strict] [--ignore RULES] [--select RULES]
                                [-o FILE] [--no-color] [--list-rules] [-v]
                                [targets ...]
```

| Flag | Argument | Default | Description |
|:---|:---|:---:|:---|
| `targets` | paths | `.` | Compose file(s) or folder(s) to scan. |
| `-f, --file` | `FILE` | - | Specify compose file explicitly (repeatable). |
| `-r, --recursive` | flag | `false` | Scan subdirectories recursively for compose files. |
| `--format` | choice | `table` | Output format: `table`, `json`, `sarif`, `markdown`, `quiet`. |
| `--min-severity`| choice | `info` | Minimum severity of findings to display (`info` to `critical`). |
| `--fail-on` | choice | `medium` | Exit with status code `1` if findings match/exceed severity. |
| `--strict` | flag | `false` | Strict mode: exit code `1` on any finding (same as `--fail-on info`). |
| `--ignore` | `RULES` | - | Comma-separated list of rule IDs to ignore (e.g. `SEC001,BP001`). |
| `--select` | `RULES` | - | Run only specified rule IDs exclusively. |
| `-o, --output` | `FILE` | stdout | Save output report to file. |
| `--no-color` | flag | `false` | Disable ANSI terminal color formatting. |
| `--list-rules` | flag | - | Print all available rules and exit. |
| `-v, --version` | flag | - | Display version and exit. |

---

## Suppressing Findings

### 1. Via Command Line
```bash
docker-compose-validator --ignore SEC001,BP001
```

### 2. Inline in Compose File
Suppress rules file-wide or on a specific line using comments:
```yaml
# docker-compose-validator: disable=BP001
services:
  database:
    image: postgres:15-alpine
    user: "999:999"
    restart: unless-stopped
    ports:
      - "5432:5432" # docker-compose-validator: disable=SEC002
```

---

## GitHub Actions CI Workflow

Add this step to `.github/workflows/ci.yml` to automatically audit Compose files on every pull request and upload SARIF security alerts:

```yaml
name: Docker Compose Security & Linting

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Validator
        run: pip install docker-compose-validator

      - name: Run Validator (Terminal Report)
        run: docker-compose-validator -r . --fail-on high

      - name: Generate SARIF Security Report
        if: always()
        run: docker-compose-validator -r . --format sarif -o results.sarif --fail-on none

      - name: Upload to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Contributing

Contributions, bug reports, and rule suggestions are warmly welcomed!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-rule`)
3. Install development dependencies (`pip install -e ".[dev]"`)
4. Run tests (`pytest -v --cov=docker_compose_validator`)
5. Commit changes (`git commit -m 'Add new rule'`)
6. Push to branch (`git push origin feature/amazing-rule`)
7. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
