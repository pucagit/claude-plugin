---
name: verify-finding
description: Verification methodology for security findings. 5-step verification with adversarial disproval, severity calibration via CVSS 3.1, variant expansion, and PoC execution against live targets. Transforms UNVERIFIED findings into CONFIRMED/DOWNGRADED/FALSE_POSITIVE with evidence. User-invocable for re-verification and PoC execution.
argument-hint: "<vuln_id> <target_source> <audit_dir>"
user-invocable: true
---

# Verify Finding — Adversarial Verification Methodology

## Goal

Every finding is **guilty of being a false positive** until proven otherwise. This methodology independently verifies each finding through source code re-reading, PoC review, PoC execution against live targets, impact validation, and adversarial disproval. Target: <5% false positive rate in confirmed findings.

## Inputs

- `VULN_ID`: The finding ID (e.g., VULN-001) — or "all" to verify all findings
- `TARGET_SOURCE`: Path to the target source code
- `AUDIT_DIR`: Path to the audit workspace
- Finding files: `{AUDIT_DIR}/findings/VULN-NNN/VULN-NNN.md` and `poc/`

## LSP Integration

For HIGH or CRITICAL findings, run `mcp__ide__getDiagnostics` on the vulnerable file. This is **mandatory** for high-severity verifications. Use it to:
- Confirm code reachability (not dead code)
- Check type constraints that may prevent exploitation
- Validate PoC script correctness
- Verify sanitization function signatures

## Verification Steps (per finding)

### Step 1: Code-Level Verification

Re-read the vulnerable code yourself from `TARGET_SOURCE` — **never trust the hunter's quotations**.

- Does the source-to-sink chain actually exist? Trace it yourself.
- Is there sanitization between source and sink that was missed?
- Is there framework-level protection not accounted for? (Check `recon/architecture.md` Section 3)
- Is the code actually reachable? (Not dead code, not dev-only, not behind a feature flag)
- Is the vulnerable function actually called with user-controlled input?
- Quote exact lines: `file/path.ext:LINE — <code>`

### Step 2: PoC Review

Read the PoC artifacts in `findings/VULN-NNN/poc/`:
- **`exploit.py`** — Does it do what it claims? Would it actually exploit the vulnerability?
- **`request.txt`** — Is the request well-formed? Does it target the right endpoint with the right payload?
- **`response.txt`** — Does the response actually prove exploitation? Could the same response come from normal functionality?
- **Additional artifacts** — Are payloads correct? Are multi-step chains logically sound?

Run `mcp__ide__getDiagnostics` on `exploit.py` to catch type errors, missing imports, or incorrect API usage.

### Step 3: PoC Execution (when live target configured)

> This step runs the PoC script against an actual live target. **Skip if no live target is configured.**

#### 3a: Pre-flight Checks

1. Read CLAUDE.md to get `TARGET_IP`, `TARGET_PORT`, `CREDENTIALS`
2. If TARGET_IP is "N/A" → skip this step entirely, proceed to Step 4
3. Read `poc/exploit.py` (or `.sh`, `.rb`, `.go`, etc.) completely
4. **Safety scan** — check for destructive operations:
   - SQL: `DROP`, `DELETE`, `TRUNCATE`, `UPDATE` (without WHERE)
   - File: `rm`, `unlink`, `rmdir`, `shutil.rmtree`
   - System: `shutdown`, `reboot`, `kill`
   - Network: hardcoded external targets (not matching TARGET_IP)
   - If ANY destructive operation found → **WARN the user and wait for approval** before executing

#### 3b: Input Validation

1. Check if the script accepts target as argument (`--target`, `--host`, `--url`, `-t`, `-h`, `-u`)
2. If the script has **hardcoded targets** (IPs, hostnames, URLs not matching TARGET_IP):
   - Create a patched copy: `poc/exploit_patched.py`
   - Replace hardcoded target with `TARGET_IP:TARGET_PORT`
   - Use the patched version for execution
3. Check required dependencies:
   ```bash
   # Extract imports and check availability
   grep -E "^import |^from " poc/exploit.py | while read line; do
     module=$(echo "$line" | awk '{print $2}' | cut -d. -f1)
     python3 -c "import $module" 2>/dev/null || echo "MISSING: $module"
   done
   ```
4. Install missing dependencies if safe to do so (standard security libs like requests, pwntools, etc.)

#### 3c: Execution

```bash
# Set timeout (30 seconds default)
TIMEOUT=30

# Build command with target info
export TARGET_IP TARGET_PORT CREDENTIALS

# Execute and capture all output
timeout ${TIMEOUT} python3 poc/exploit.py \
  --target "${TARGET_IP}" --port "${TARGET_PORT}" \
  2>&1 | tee poc/execution-output.txt

# Capture exit code
echo "EXIT_CODE=$?" >> poc/execution-output.txt
```

Adapt the command based on what the script actually accepts (check `--help` or read the docstring).

If the script requires credentials, pass them appropriately.

#### 3d: Output Verification

1. Read `poc/execution-output.txt`
2. Compare actual output against expected output documented in the finding:
   - Does it show exploitation indicators? (shell prompt, admin access, data leak, error-based info)
   - Does the HTTP response code match expectations?
   - Is the response body consistent with exploitation?
3. **Verdict**:
   - Output matches expected → **EXECUTION_CONFIRMED**
   - Output partially matches → **EXECUTION_PARTIAL** (document what worked and what didn't)
   - Output doesn't match → **EXECUTION_FAILED** (document actual output)
   - Script errors/crashes → **EXECUTION_ERROR** (document the error)

#### 3e: Reproducibility Check

Run the PoC a **second time** to confirm consistent results:
```bash
timeout ${TIMEOUT} python3 poc/exploit.py \
  --target "${TARGET_IP}" --port "${TARGET_PORT}" \
  2>&1 | tee poc/execution-output-run2.txt
```

Compare both runs. Document:
- **Reliable**: Both runs produce same result
- **Intermittent**: Results differ between runs (note: may indicate race condition)
- **One-shot**: Second run fails (note: may indicate state-changing exploit)

#### 3f: Log Execution

Append to `{AUDIT_DIR}/logs/poc-execution.log`:
```
[TIMESTAMP] VULN-NNN: Executed poc/exploit.py against {TARGET_IP}:{TARGET_PORT}
[TIMESTAMP] VULN-NNN: Exit code: {code}, Output: {summary}
[TIMESTAMP] VULN-NNN: Reproducibility: {Reliable/Intermittent/One-shot}
[TIMESTAMP] VULN-NNN: Verdict: {EXECUTION_CONFIRMED/PARTIAL/FAILED/ERROR}
```

---

### Step 4: Impact Validation

Does the exploit cross a **real security boundary**?

| Boundary | Example |
|---|---|
| Unauthenticated → authenticated data | Reading user data without login |
| Low-privilege → high-privilege action | User performing admin operations |
| User A → User B's data | Accessing another user's resources |
| Application → underlying system | RCE, file system access |
| Internal → external data exposure | Leaking secrets, PII, credentials |

If the "vulnerability" doesn't cross a security boundary, it's likely not a real finding. A SQL injection that only reads public data is lower impact than one that reads credentials.

### Step 5: Adversarial Disproval

**For HIGH and CRITICAL findings — this step is mandatory.**

Actively try to prove the finding is **NOT exploitable**:

1. **Search for additional sanitization** — grep for the variable name between source and sink. Is there middleware, a decorator, or a utility function that sanitizes it?
2. **Check deployment context** — Is this code behind a WAF, reverse proxy, or API gateway that would block the payload?
3. **Check conditions** — Are the preconditions for exploitation realistic in production? (e.g., requires specific config, specific timing, specific user state)
4. **Run diagnostics** — `mcp__ide__getDiagnostics` on the vulnerable file to check for type constraints, dead code, and unreachable paths
5. **Document the attempt** — Write what you tried to disprove and why it failed (or succeeded)

If your disproval attempt **succeeds**: downgrade or mark as false positive.
If your disproval attempt **fails**: the finding is strengthened — document why the protections are insufficient.

### Step 6: Verdict

Assign exactly one:

| Verdict | Meaning |
|---|---|
| **CONFIRMED** | Verified exploitable with evidence. Source→sink chain confirmed, protections insufficient. If PoC executed: includes execution evidence. |
| **CONFIRMED-THEORETICAL** | Code vulnerability confirmed, but no live target to prove exploitation. Would be exploitable in a running instance. |
| **DOWNGRADED** | Real issue, but lower severity than originally rated. State original + new severity + reason. |
| **FALSE_POSITIVE** | Not a real vulnerability. |

False positive reason codes:
`FRAMEWORK_PROTECTION`, `SANITIZATION_PRESENT`, `NOT_REACHABLE`, `INTENDED_FUNCTIONALITY`, `TYPE_CONSTRAINT`, `DEAD_CODE`, `ADDITIONAL_CONTROLS`, `NON_QUALIFYING_TYPE`, `OUT_OF_SCOPE`

## Severity Calibration

Apply CVSS 3.1 strictly based on **verified** impact:

| Severity | CVSS Range | Examples |
|---|---|---|
| **CRITICAL** | 9.0–10.0 | Unauthenticated RCE, mass data breach, auth bypass to admin, pre-auth deserialization |
| **HIGH** | 7.0–8.9 | Authenticated RCE, significant data exposure, privilege escalation, SSRF to internal services |
| **MEDIUM** | 4.0–6.9 | Stored XSS, non-critical IDOR, auth CSRF, limited path traversal, information disclosure |
| **LOW** | 0.1–3.9 | Reflected XSS (requires interaction), info disclosure (non-sensitive), missing headers without exploit chain |

Never rate higher than verified impact supports. Write the full CVSS 3.1 vector string:
`CVSS:3.1/AV:[N|A|L|P]/AC:[L|H]/PR:[N|L|H]/UI:[N|R]/S:[U|C]/C:[N|L|H]/I:[N|L|H]/A:[N|L|H]`

## Variant Expansion

**For every CONFIRMED finding**, before moving to the next:

1. **Extract the vulnerable pattern** — What specific code construct made this exploitable?
2. **Grep for siblings** — Search the codebase for the same pattern in other files/functions
3. **Quick-verify each match** — Read the code, check if it's the same dangerous pattern unfixed
4. **Create new VULN-NNN entries** for confirmed variants — use the same finding template, reference the original as "Variant of VULN-NNN"

## Output Format

### For CONFIRMED / CONFIRMED-THEORETICAL / DOWNGRADED findings

Update `findings/VULN-NNN/VULN-NNN.md` in-place:

1. Change `Status` from `UNVERIFIED` to the verdict
2. If DOWNGRADED: update Severity and add reason
3. Update `CVSS` with verified full string: `X.X (CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...)`
4. Add `Reproducibility`: `Reliable / Intermittent / Untested`
5. Append these sections:

```markdown
## Execution Evidence

[Only if PoC was executed against live target]

**Command**: `python3 poc/exploit.py --target {IP} --port {PORT}`
**Exit code**: {code}
**Timestamp**: {YYYY-MM-DD HH:MM:SS}
**Reproducibility**: {Reliable / Intermittent / One-shot}

### Run 1 Output
\`\`\`
{stdout/stderr from first execution}
\`\`\`

### Run 2 Output
\`\`\`
{stdout/stderr from second execution}
\`\`\`

**Execution Verdict**: {EXECUTION_CONFIRMED / EXECUTION_PARTIAL / EXECUTION_FAILED / EXECUTION_ERROR}
**Analysis**: [What the output proves about exploitability]

## Verification Notes

[What you re-read, framework protections checked, code path reachability confirmed.
What confirmed this is real — or what you couldn't fully verify and why.
For HIGH/CRITICAL: document the adversarial disproval attempt and why it failed.]

## Mitigation

### Immediate
[Quick risk reduction — disable feature, add validation, restrict access]

### Short-term Fix
[Code-level fix specific to this codebase — include secure code snippet]

### Long-term
[Architectural improvement needed]
```

### For FALSE_POSITIVE findings

**Do NOT delete** the `findings/VULN-NNN/` directory — preserve poc/ evidence.

1. Update `findings/VULN-NNN/VULN-NNN.md`: set `Status` to `FALSE_POSITIVE`, add brief explanation
2. Append to `{AUDIT_DIR}/false-positives.md`:

```markdown
### VULN-NNN: [Original Title]
**Verdict**: FALSE_POSITIVE
**Reason**: [reason code from list above]
**Evidence**: [why this is not real — with file:line proof of the protection mechanism]
```

## Completion

Every finding must have a verdict. No finding left in `UNVERIFIED` state. Create `false-positives.md` even if empty (write a header line: `# False Positives`).
