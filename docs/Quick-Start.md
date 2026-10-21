# 🚀 Quick Start Guide

Get started with **Docker Compose Validator** in under 3 minutes.

---

## 📥 Installation

```bash
# Install via pip
pip install docker-compose-validator

# Or install from source
git clone https://github.com/slopggobblercobbler81/docker-compose-validator.git
cd docker-compose-validator
pip install -e .
```

---

## 💻 Essential CLI Invocations

### 1. Validate Current Directory
Automatically discovers `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, and `compose.yaml`:
```bash
docker-compose-validator
```

### 2. Validate Specific File
```bash
docker-compose-validator docker-compose.prod.yml
```

### 3. Recursive Directory Scanning
Recursively search folders for any Compose definitions:
```bash
docker-compose-validator -r ./deployments/
```

### 4. Enforce Severity Thresholds in CI
Fail the pipeline (exit code `1`) only when `CRITICAL` or `HIGH` violations are found:
```bash
docker-compose-validator --fail-on high
```

### 5. Export to SARIF for GitHub Code Scanning
```bash
docker-compose-validator --format sarif -o results.sarif
```

---

## 🤖 GitHub Actions Workflow

Add `.github/workflows/compose-lint.yml`:

```yaml
name: Docker Compose Security Lint

on:
  pull_request:
    paths:
      - '**/docker-compose*.yml'
      - '**/compose*.yml'
  push:
    branches: [main]

jobs:
  lint-compose:
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

      - name: Run Linter
        run: |
          docker-compose-validator -r . --format sarif -o compose-results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: compose-results.sarif
```
