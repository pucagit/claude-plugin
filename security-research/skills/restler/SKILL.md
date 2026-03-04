---
name: restler
description: >-
  Run Microsoft RESTler stateful REST API fuzzing against a target API using an OpenAPI/Swagger specification. Supports compile, test, fuzz-lean, and fuzz modes with security checkers for IDOR, use-after-free, resource hierarchy bypass, payload body mutation, and input validation. Use when performing dynamic API security testing, fuzzing REST endpoints, or detecting runtime vulnerabilities in web APIs.
argument-hint: "<compile|test|fuzz-lean|fuzz|replay> <spec_or_grammar_path> [options]"
---

# RESTler REST API Fuzzer

Run RESTler against `$ARGUMENTS`.

## Prerequisites

Ensure RESTler is built and .NET 8.0 is available:

```bash
RESTLER_BIN="/home/kali/restler_bin"
DOTNET_PATH="$HOME/.dotnet/dotnet"

if [ ! -f "$RESTLER_BIN/restler/Restler.dll" ]; then
    echo "ERROR: RESTler not found at $RESTLER_BIN"
    echo "Build it: cd /home/kali/restler-fuzzer && python3 build-restler.py --dest_dir $RESTLER_BIN"
    exit 1
fi

if ! "$DOTNET_PATH" --version 2>/dev/null | grep -q "^8\."; then
    echo "ERROR: .NET 8.0 required. Install: /tmp/dotnet-install.sh --channel 8.0 --install-dir \$HOME/.dotnet"
    exit 1
fi
```

Set environment for all commands:

```bash
export DOTNET_ROOT="$HOME/.dotnet"
export PATH="$HOME/.dotnet:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
export RESTLER_TELEMETRY_OPTOUT=1
RESTLER="dotnet /home/kali/restler_bin/restler/Restler.dll"
```

## Usage Modes

Parse `$ARGUMENTS` to determine mode:

### Mode: `compile` — Compile OpenAPI Spec to Grammar

Convert an OpenAPI/Swagger specification into RESTler's fuzzing grammar.

```bash
# $0 = path to OpenAPI spec (JSON or YAML)
SPEC_PATH="$0"
WORK_DIR="${AUDIT_DIR:-./}/restler-workdir"
mkdir -p "$WORK_DIR" && cd "$WORK_DIR"

$RESTLER compile --api_spec "$SPEC_PATH"
```

**Output** in `Compile/`:

| File | Purpose |
|------|---------|
| `grammar.py` | Executable fuzzing grammar |
| `grammar.json` | Human-editable grammar (for PayloadBody/Examples checkers) |
| `dict.json` | Fuzzing dictionary — customize with attack payloads |
| `engine_settings.json` | Engine configuration — set host, port, auth, checkers |
| `config.json` | Compiler configuration for recompilation |

After compiling, **customize the dictionary** with security payloads:

```bash
# Inject attack payloads into dict.json for security testing
python3 -c "
import json
d = json.load(open('Compile/dict.json'))
d['restler_fuzzable_string'] = [
    'fuzzstring',
    '\\'OR 1=1--',
    '<script>alert(1)</script>',
    '{{7*7}}',
    '../../../etc/passwd',
    '; ls -la',
    '{\"__proto__\":{\"admin\":true}}'
]
json.dump(d, open('Compile/dict.json','w'), indent=2)
"
```

### Mode: `test` — Smoketest (Coverage Validation)

Execute every endpoint once to validate the spec and measure API coverage.

```bash
# $0 = path to Compile/ dir or grammar.py
COMPILE_DIR="$0"
cd "$(dirname "$COMPILE_DIR")"

$RESTLER test \
    --grammar_file "$COMPILE_DIR/grammar.py" \
    --dictionary_file "$COMPILE_DIR/dict.json" \
    --settings "$COMPILE_DIR/engine_settings.json" \
    --no_ssl \
    --host ${TARGET_HOST:-localhost} \
    --target_port ${TARGET_PORT:-8080}
```

**Success criteria**: Check `testing_summary.json` for coverage. Target ~50%+ `rendered_requests_valid_status` before fuzzing.

**Output** in `Test/`:
- `RestlerResults/experiment*/logs/testing_summary.json` — coverage stats
- `RestlerResults/experiment*/logs/speccov.json` — per-endpoint coverage
- `RestlerResults/experiment*/logs/network.testing.*.txt` — full HTTP traffic
- `ResponseBuckets/runSummary.json` — HTTP status code distribution
- `ResponseBuckets/errorBuckets.json` — sample error request/response pairs

### Mode: `fuzz-lean` — Quick Security Scan

Each endpoint tested once with all security checkers enabled. Best balance of speed vs coverage for security auditing.

```bash
COMPILE_DIR="$0"
cd "$(dirname "$COMPILE_DIR")"

$RESTLER fuzz-lean \
    --grammar_file "$COMPILE_DIR/grammar.py" \
    --dictionary_file "$COMPILE_DIR/dict.json" \
    --settings "$COMPILE_DIR/engine_settings.json" \
    --no_ssl \
    --host ${TARGET_HOST:-localhost} \
    --target_port ${TARGET_PORT:-8080}
```

### Mode: `fuzz` — Deep Fuzzing

Breadth-first exploration with time budget. Use for thorough security testing.

```bash
COMPILE_DIR="$0"
cd "$(dirname "$COMPILE_DIR")"

$RESTLER fuzz \
    --grammar_file "$COMPILE_DIR/grammar.py" \
    --dictionary_file "$COMPILE_DIR/dict.json" \
    --settings "$COMPILE_DIR/engine_settings.json" \
    --time_budget ${TIME_BUDGET:-1} \
    --no_ssl \
    --host ${TARGET_HOST:-localhost} \
    --target_port ${TARGET_PORT:-8080}
```

### Mode: `replay` — Reproduce Bug

Replay a specific bug from a `.replay.txt` file.

```bash
REPLAY_FILE="$0"

$RESTLER replay \
    --replay_log "$REPLAY_FILE" \
    --no_ssl \
    --host ${TARGET_HOST:-localhost} \
    --target_port ${TARGET_PORT:-8080}
```

## Security Checkers

RESTler runs these checkers automatically during fuzz-lean and fuzz modes:

| Checker | Default | Detects | Security Mapping |
|---------|---------|---------|-----------------|
| UseAfterFree | Enabled | Access to deleted resources | Resource lifecycle, incomplete deletion |
| NamespaceRule | **Disabled** | Unauthorized cross-user access | IDOR, authorization bypass, multi-tenant isolation |
| ResourceHierarchy | Enabled | Child accessible from wrong parent | Broken access control |
| LeakageRule | Enabled | Data from failed creation requests | Information disclosure |
| InvalidDynamicObject | Enabled | 500 from invalid resource IDs | Input validation, injection |
| PayloadBody | Enabled | 500 from body mutations | Deserialization, type confusion |
| Examples | Enabled | 5xx from documented examples | Spec correctness, error handling |
| InvalidValue | Disabled | 5xx from invalid parameter values | Input validation |

**Enable NamespaceRule** for IDOR/authz testing (requires second user credentials):
```bash
--enable_checkers namespacerule
```

## Processing Results

### Output Directory Structure

```
<Mode>/
  RestlerResults/experiment*/
    logs/
      bug_buckets.txt              # Aggregated bug summary
      bug_buckets/                 # Individual replay files
        <Checker>_<code>_<N>.replay.txt
      testing_summary.json         # Coverage and bug stats
      speccov.json                 # Per-endpoint coverage
      network.testing.*.txt        # Full HTTP traffic
    ResponseBuckets/
      runSummary.json              # HTTP status distribution
      errorBuckets.json            # Error samples
```

### Bug-to-Finding Mapping

| RESTler Bug Type | Vulnerability Class | CWE |
|-----------------|---------------------|-----|
| `NamespaceRule` bugs | IDOR / Authorization bypass | CWE-639, CWE-284 |
| `UseAfterFree` bugs | Resource lifecycle issue | CWE-672 |
| `ResourceHierarchy` bugs | Broken access control | CWE-285 |
| `LeakageRule` bugs | Information disclosure | CWE-200 |
| `InvalidDynamicObject` bugs | Input validation failure | CWE-20 |
| `PayloadBody` bugs | Type confusion / deserialization | CWE-502, CWE-20 |
| `main_driver_500` bugs | Unhandled exceptions / DoS | CWE-755 |

### Mapping to Audit Candidates

For each bug in `bug_buckets/`:
1. Read the `.replay.txt` file to extract the request sequence
2. Map the checker name to a vulnerability class (table above)
3. Replay the bug to capture full request/response evidence
4. Trace the vulnerable endpoint back to source code using the path from the request
5. Tag as `[RESTLER:<checker_name>]` for traceability

## Authentication Configuration

For targets requiring authentication, configure `engine_settings.json`:

```json
{
    "authentication": {
        "token": {
            "token_refresh_interval": 300,
            "token_refresh_cmd": "python3 ${AUDIT_DIR}/scripts/get_token.py"
        }
    }
}
```

Token script must output:
```
{u'user1': {}}
Authorization: Bearer <token_value>
```

## Supporting Files

- [checkers-reference.md](checkers-reference.md) — detailed checker configuration and custom checker setup
- [engine-settings-reference.md](engine-settings-reference.md) — complete engine settings schema
- [dictionary-reference.md](dictionary-reference.md) — fuzzing dictionary schema and attack payload templates
