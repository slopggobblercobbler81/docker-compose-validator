# 🐳 Docker Compose Validator Documentation

Welcome to the comprehensive documentation for **Docker Compose Validator**, the production-grade linter, security auditor, and best-practices analyzer for container deployments.

---

## 📚 Documentation Index

| Guide | Description |
|---|---|
| [**Architecture**](Architecture.md) | Deep dive into YAML AST line-number mapping, the rule registry, validation engine, and SARIF exporter. |
| [**Quick Start**](Quick-Start.md) | Fast setup, essential CLI invocations, recursive scanning, and CI/CD pipeline integration. |
| [**Troubleshooting**](Troubleshooting.md) | Handling inline rule suppressions, unparseable Compose syntaxes, exit code troubleshooting, and FAQ. |
| [**Performance Guide**](PERFORMANCE_GUIDE.md) | Parser execution benchmarks, memory footprints, and large-scale repository scanning. |

---

## 🛡️ Rule Categories

```mermaid
flowchart TD
    subgraph Core Linter Rules
        R1["Security (SECxxx)"] --> R1a["Root User Execution"]
        R1 --> R1b["Privileged Containers"]
        R1 --> R1c["Host Namespace Sharing"]
        R1 --> R1d["Exposed Sensitive Ports"]
        
        R2["Reliability (RELxxx)"] --> R2a["Missing Restart Policy"]
        R2 --> R2b["Unpinned Image Tags (:latest)"]
        R2 --> R2c["Missing Healthchecks"]
        R2 --> R2d["Unbounded Memory/CPU"]
        
        R3["Syntax & Structure (SYNxxx)"] --> R3a["Invalid YAML"]
        R3 --> R3b["Missing Services Mapping"]
        
        R4["Best Practices (BPxxx)"] --> R4a["Deprecated Version Tag"]
        R4 --> R4b["Fixed Container Name"]
        R4 --> R4c["Missing Log Limits"]
    end
```

- **Security (`SEC`)**: Hardens containers against privilege escalation, host compromises, and unauthorized network exposure.
- **Reliability (`REL`)**: Prevents production outages caused by container crashes, unpinned updates, and out-of-memory cascades.
- **Syntax (`SYN`)**: Ensures compliant Compose file structure before calling docker-compose or container runtimes.
- **Best Practices (`BP`)**: Keeps compose definitions aligned with the modern Compose Specification.
