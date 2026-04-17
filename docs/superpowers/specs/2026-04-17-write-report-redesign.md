# write-report Skill Redesign

## Context

The current `write-report` skill generates a single aggregate report across all VULN-NNN findings in an audit session. In practice this produces reports that reference audit session identifiers (VULN-NNN IDs), cross-reference other findings, and lack the reproducibility artifacts needed to share a single vulnerability externally.

The redesign replaces this with a per-vulnerability standalone report generator. Each report is a self-contained advisory — no VULN-NNN references, no cross-finding references, no audit session metadata — accompanied by a Docker Compose setup script and a cleaned PoC script that a recipient can run independently to reproduce the vulnerability.

## Invocation

```
/security-research:write-report <audit_dir> <vuln_identifier>
```

`<vuln_identifier>` accepts:
- A VULN-NNN ID (e.g., `VULN-003`)
- A natural language description (e.g., `redis oob write`) — skill matches to closest confirmed finding by title
- A chain description (e.g., `chain: VULN-001 + VULN-003`) — generates one combined report for a multi-step exploitation chain

## Output Structure

```
{audit_dir}/reports/<short_name>/
├── report.md          ← Standalone advisory report
├── setup.sh           ← Docker Compose environment setup
├── docker-compose.yml ← Vulnerable target definition (if needed)
└── poc.py             ← Cleaned, self-contained PoC script
```

**Short name derivation:** lowercase, hyphens, max 40 chars, derived from vuln title (e.g., `redistimeseries-oob-write-rce`). If ambiguous, the skill asks the user to confirm.

## First-Action Sequence

Execute in this order:
1. Identify the target finding(s) — match `<vuln_identifier>` to `{audit_dir}/findings/VULN-*/VULN-*.md`
2. Check for custom template: `{PROJECT_DIR}/REPORT.md` (set during `claude-init`)
3. Read all identified finding files (VULN-NNN.md)
4. Read all PoC artifacts: `findings/VULN-NNN/poc/exploit.py`, `execution-output.txt`, `request.txt`, `response.txt`
5. Check for existing Docker artifacts from `setup-target` skill in the audit dir
6. Derive short name from vuln title — confirm with user if ambiguous
7. Generate all output files into `{audit_dir}/reports/<short_name>/`

## report.md

### Template Priority
1. **If `{PROJECT_DIR}/REPORT.md` exists** (custom template from claude-init): use its structure, sections, and ordering. Fill with finding data. Do not add or remove sections.
2. **If no custom template**: use the advisory format below.

### Default Advisory Format

```markdown
# Advisory: [Vuln Title — descriptive, no VULN-ID]

## Advisory Details
**Title:** [Full descriptive title with CWE references if applicable]

## Summary
[3-4 sentences: what the bug is, how it's triggered, what impact it achieves, what an attacker needs]

## Details

### Root Cause: [Issue] (CWE-XXX)
**File:** `path/to/file.c`
**Function:** `FunctionName()` (line ~NNN)

[Vulnerable code block with inline comments explaining the bug]

**Root Cause:** [Explanation of WHY this is vulnerable]
**Primitive:** [One line: what exploitation primitive this provides]

### Exploitation Chain
1. **[Step Name]:** [Description of what the attacker does and what it achieves]
2. ...

### Binary Hardening
| Binary | PIE | NX | Canary | RELRO |
|--------|-----|----|--------|-------|
| ...    | ... | ...| ...    | ...   |

## PoC

- **`poc.py`** — [description of what the script does]

Expected output:
[code block with verified output]

### Prerequisites / Special Conditions
1. [Numbered list of requirements: module versions, config flags, auth level, architecture]

### Reproduction Steps
1. Run `./setup.sh` to start the vulnerable environment
2. Run `python3 poc.py --host 127.0.0.1 --port <port> --cmd "id"`
3. Expected output: [...]

## Impact
[1-2 sentences on business/security impact and who is affected]

## Affected Products
- **Ecosystem:** [...]
- **Package name:** [...]
- **Affected versions:** [...]
- **Patched versions:** [...]

## Severity
**[Critical/High/Medium/Low]**

**CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...** — Score: X.X

- **AV:...** — [justification]
- **AC:...** — [justification]
- **PR:...** — [justification]
- **UI:...** — [justification]
- **S:...** — [justification]
- **C/I/A:...** — [justification]

## Weaknesses
- **CWE-XXX:** [Description] (primary)
- **CWE-YYY:** [Description] (secondary, if applicable)

## Recommended Fix
1. [Specific code fix with code block]
2. [Build hardening or configuration recommendation]
```

### Prohibited Content in report.md
- Any `VULN-` string or `VULN-NNN` pattern
- Any reference to other vulnerabilities in the audit session
- Any audit session metadata (scan dates, orchestrator log references)
- Placeholder text (TBD, TODO, N/A without explanation)

## setup.sh

### Logic
1. Check if `setup-target` skill artifacts exist in the audit dir — if so, copy and adapt them
2. If not, synthesize `docker-compose.yml` + `setup.sh` from the finding's Affected Products info (name, version, required config)

### setup.sh Format
```bash
#!/bin/bash
# Starts the vulnerable target environment for reproduction.
# Requirements: Docker, Docker Compose

set -e

# Start the target
docker compose up -d

# Wait for service to be ready
sleep 3

# Verify it's running
[service-specific health check, e.g.: redis-cli -p 6379 ping]

echo "Environment ready. Run: python3 poc.py --host 127.0.0.1 --port [PORT]"
```

### Prohibited Content in setup.sh
- Any `VULN-` string
- References to other vulnerabilities
- Audit session metadata

## poc.py

### Source
Adapted from the verified `findings/VULN-NNN/poc/exploit.py` already in the audit workspace. Do NOT rewrite the exploit logic — copy and clean it.

**If no PoC exists** (CONFIRMED-THEORETICAL finding or missing poc/): omit `poc.py` from the output folder. Note in `report.md` under the PoC section: "No executable PoC available — vulnerability confirmed via code analysis only."

### Cleaning Rules
- Remove all `VULN-NNN` comments and references
- Remove "Finding #N", "Related to:", "Part of chain with:" comments
- Remove audit session metadata (timestamps, session IDs, orchestrator references)
- Add self-contained usage block at the top:
  ```python
  # Usage: python3 poc.py --host 127.0.0.1 --port PORT --cmd "id"
  # Requirements: pip install pwntools (or relevant deps)
  ```
- Ensure all configuration (host, port, target version) is via argparse or top-level constants
- Preserve all exploit logic exactly as verified

### Prohibited Content in poc.py
- Any `VULN-` string
- References to other vulnerabilities or findings

## Quality Bar

| Check | Requirement |
|-------|-------------|
| `report.md` length | ≥ 50 lines |
| `report.md` VULN-free | Must NOT contain `VULN-` anywhere |
| `report.md` required sections | Summary, Details (root cause + code), Reproduction Steps, Severity (with CVSS string), Recommended Fix |
| `poc.py` VULN-free | Must NOT contain `VULN-` anywhere |
| `poc.py` self-contained | Must include usage comment and at least one network connection or file operation |
| `setup.sh` VULN-free | Must NOT contain `VULN-` anywhere |
| `setup.sh` executable | Must contain `docker compose` invocation |
| Short name | Lowercase, hyphens only, ≤ 40 chars, no VULN-NNN pattern |

## Changes to Existing write-report Skill

The entire `SKILL.md` is replaced. The new skill:
- Removes all aggregate report logic (findings summary table, remediation roadmap across findings, tool inventory)
- Removes pipeline mode / standalone mode detection
- Removes the `report.md` → `{AUDIT_DIR}/report.md` output path
- Adds the per-vuln output to `{audit_dir}/reports/<short_name>/`
- Updates the `argument-hint` to `"<audit_dir> <vuln_identifier>"`
- Updates the `description` frontmatter to reflect the new purpose
