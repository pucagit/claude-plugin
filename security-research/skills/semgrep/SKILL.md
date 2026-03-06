---
name: semgrep
description: Run Semgrep static analysis scans on target source code. Supports registry rule packs(security-audit, owasp-top-ten, secrets), custom taint rule writing, and structured JSON output parsing. Use when performing SAST scanning, writing taint analysis rules, hunting for vulnerabilities with pattern matching, or running automated security scans during any audit phase.
argument-hint: "<scan|rule|taint|sweep> [target_path] [options]"
---

# Semgrep Security Scanner

Run Semgrep against `$ARGUMENTS`.

## Prerequisites

Ensure semgrep is installed:

```bash
source /home/kali/.venv/bin/activate
if ! command -v semgrep &> /dev/null; then
    pip3 install semgrep
fi
semgrep --version
```

## Usage Modes

Parse `$ARGUMENTS` to determine mode:

### Mode: `scan` — Registry Scan

Run pre-built security rules from the Semgrep registry.

```bash
# Determine target language from file extensions
# Choose appropriate config packs

semgrep scan \
  --config p/security-audit \
  --config p/owasp-top-ten \
  --config p/secrets \
  --json --output ${AUDIT_DIR:-./}/logs/semgrep-registry.json \
  --severity WARNING --severity ERROR \
  --dataflow-traces \
  --timeout 10 \
  --max-target-bytes 2000000 \
  --exclude "vendor" --exclude "node_modules" --exclude "*.min.js" \
  ${TARGET_PATH}
```

Add language-specific packs based on what's detected:

| Language | Pack |
|---|---|
| Python | `p/python` |
| JavaScript | `p/javascript` |
| TypeScript | `p/typescript` |
| Java | `p/java` |
| Go | `p/go` |
| PHP | `p/php` |
| Ruby | `p/ruby` |
| Rust | `p/rust` |
| C/C++ | `p/c` |
| C# | `p/csharp` |

Additional security-focused packs: `p/xss`, `p/sql-injection`, `p/command-injection`, `p/jwt`, `p/insecure-transport`, `p/supply-chain`.

### Mode: `rule` — Write Custom Rules

Write target-specific Semgrep rules. See [rule-syntax.md](rule-syntax.md) for the complete YAML schema and pattern syntax reference.

Basic rule structure:

```yaml
rules:
  - id: unique-rule-id
    message: "What was found and why it matters"
    severity: ERROR    # ERROR, WARNING, INFO
    languages: [python]
    pattern: dangerous_function($USER_INPUT)
    metadata:
      cwe: CWE-XXX
      confidence: HIGH
```

Key pattern operators:
- `pattern` — match code directly
- `patterns` — AND logic (all must match)
- `pattern-either` — OR logic (any can match)
- `pattern-not` — exclude matches
- `pattern-inside` — require enclosing context
- `pattern-regex` — PCRE2 regex matching
- `$X` — metavariable capturing any expression
- `...` — ellipsis matching zero or more items
- `<... P ...>` — deep expression matching

Validate before running:

```bash
semgrep --validate --config ${AUDIT_DIR}/semgrep-rules/
```

### Mode: `taint` — Taint Analysis

Write taint tracking rules that follow data from sources to sinks. See [taint-rules.md](taint-rules.md) for pre-built rules covering SQLi, CMDi, SSRF, path traversal, XSS, and deserialization.

Taint rule structure:

```yaml
rules:
  - id: taint-rule-id
    mode: taint                    # Required for taint analysis
    message: "Tainted data reaches dangerous sink"
    severity: ERROR
    languages: [python]
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sanitizers:
      - pattern: sanitize($X)
    pattern-sinks:
      - pattern: cursor.execute($QUERY)
```

When writing target-specific taint rules:
1. Get sources from the recon phase entry points
2. Get sinks from the code review phase sink inventory
3. Get sanitizers from the code review phase validation analysis
4. Save rules to `${AUDIT_DIR}/semgrep-rules/`

### Mode: `sweep` — Full Security Sweep

Combined registry + custom taint rules:

```bash
# Step 1: Registry scan
semgrep scan \
  --config p/security-audit \
  --config p/owasp-top-ten \
  --config p/secrets \
  --config p/${LANGUAGE} \
  --json --output ${AUDIT_DIR}/logs/semgrep-registry.json \
  --severity WARNING --severity ERROR \
  --dataflow-traces \
  --timeout 10 \
  --max-target-bytes 2000000 \
  ${TARGET_SOURCE}

# Step 2: Custom taint rules (if they exist)
if [ -d "${AUDIT_DIR}/semgrep-rules" ] && [ "$(ls -A ${AUDIT_DIR}/semgrep-rules/*.yaml 2>/dev/null)" ]; then
  semgrep scan \
    --config ${AUDIT_DIR}/semgrep-rules/ \
    --json --output ${AUDIT_DIR}/logs/semgrep-custom.json \
    --dataflow-traces \
    --timeout 15 \
    ${TARGET_SOURCE}
fi
```

## Processing Results

### JSON Output Structure

```json
{
  "results": [{
    "check_id": "rule-id",
    "path": "file/path.py",
    "start": {"line": 10, "col": 5},
    "end": {"line": 10, "col": 42},
    "extra": {
      "message": "Description",
      "severity": "ERROR",
      "metadata": { "cwe": ["CWE-89"], "confidence": "HIGH" },
      "dataflow_trace": { "taint_source": [...], "taint_sink": [...] },
      "lines": "matching source code"
    }
  }]
}
```

### Mapping to Audit Candidates

| Semgrep Field | Audit Field |
|---|---|
| `check_id` | Reference ID |
| `extra.severity` | Severity (ERROR→HIGH, WARNING→MEDIUM) |
| `path` + `start.line` | Location (file:line) |
| `extra.metadata.cwe` | CWE classification |
| `extra.lines` | Vulnerable code snippet |
| `extra.dataflow_trace` | Source → Sink chain |

### Tagging Convention

Tag all Semgrep findings for traceability:
- `[SEMGREP:rule-id]` — detected by Semgrep
- `[MANUAL-DETECTED]` — found by manual review
- `[SEMGREP+MANUAL]` — confirmed by both (highest confidence)

## Performance Tuning

| Flag | Default | Recommendation |
|---|---|---|
| `--jobs` | 0.85x CPUs | Default is fine |
| `--timeout` | 5s | 10-15s for complex taint rules |
| `--max-target-bytes` | 1MB | 2MB for large files |
| `--exclude` | none | Always exclude `vendor/`, `node_modules/` |

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | No findings |
| 1 | Findings detected — parse results |
| 2 | Fatal error |
| 4 | Invalid rule pattern — validate rules |
| 5 | Unparseable YAML — fix syntax |
| 7 | Config not found |

## Audit Pipeline Integration

| Phase | Semgrep Task | Config |
|---|---|---|
| Phase 1 (Recon) | Secret detection | `p/secrets` |
| Phase 2 (Code Review) | Dataflow trace bootstrap | `p/security-audit --dataflow-traces` |
| Phase 3 (Vuln Detection) | Full scan + custom rules | Registry + custom YAML |

Semgrep supplements manual analysis. It **cannot** catch:
- Business logic flaws
- Complex multi-step chains across trust boundaries
- Framework-specific auth bypass patterns
- Race conditions and desync attacks

## Supporting Files

- [rule-syntax.md](rule-syntax.md) — complete YAML rule schema, pattern syntax, metavariable operators
- [taint-rules.md](taint-rules.md) — pre-built taint rules for SQLi, CMDi, SSRF, path traversal, XSS, deserialization
