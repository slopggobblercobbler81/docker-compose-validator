# 🔧 Troubleshooting & FAQ

Solutions to common questions and edge cases when using **Docker Compose Validator**.

---

## ❓ Frequently Asked Questions

### 1. How do I suppress a false positive or intentional configuration?

You can suppress rules either inline or globally:

#### Inline Suppression
Add a comment directly above or beside the offending line:
```yaml
services:
  debugger:
    image: alpine:3.19
    privileged: true  # docker-compose-validator: disable=SEC003
```

#### Command-Line Suppression
Pass the `--ignore` flag:
```bash
docker-compose-validator --ignore SEC003,BP001
```

---

### 2. What do the exit codes mean?

| Exit Code | Meaning |
|---|---|
| `0` | All audited files passed validation (or findings were below the `--fail-on` threshold). |
| `1` | One or more rule violations met or exceeded the failure threshold. |
| `2` | Execution error (e.g. file not found, unparseable YAML syntax error). |

---

### 3. How are environment variable interpolations handled?

Compose files often contain `${VAR:-default}` or `$PORT`. 
The validator preserves these expressions as string literals rather than attempting host environment substitution, ensuring rules that validate ports and hosts evaluate the expression without crashing when variables are unset in CI.

---

### 4. Why is `BP001` flagging my `version: '3.8'` tag?

The official Compose Specification has deprecated top-level `version:` keys in favor of dynamic schema resolution. Removing `version: '3.8'` aligns your files with modern Compose v2 standards. If you must retain it for legacy tools, pass `--ignore BP001`.

---

## 📞 Support & Issue Tracker

If you find a bug or would like to propose a new rule:
👉 [https://github.com/slopggobblercobbler81/docker-compose-validator/issues](https://github.com/slopggobblercobbler81/docker-compose-validator/issues)
