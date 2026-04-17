---
name: write-report
description: >-
  Per-vulnerability standalone report generator. Takes a confirmed finding from
  an audit workspace and produces a self-contained advisory (report.md), Docker
  Compose environment setup script (setup.sh + docker-compose.yml), and sanitized
  PoC script (poc.py) in {audit_dir}/reports/<short_name>/. No VULN-NNN IDs,
  no cross-finding references, no audit session metadata anywhere in the output.
argument-hint: "<audit_dir> <vuln_identifier>"
user-invocable: true
---

# Write Report — Standalone Vulnerability Advisory Generator

## Goal

Generate a fully self-contained, reproducible vulnerability advisory for a single confirmed finding or exploitation chain. The output must be shareable without any audit session context — no VULN-NNN identifiers, no cross-finding references, no internal metadata.

## Invocation

```
/security-research:write-report <audit_dir> <vuln_identifier>
```

`<vuln_identifier>` accepts:
- A VULN-NNN ID (e.g., `VULN-003`) — exact match to finding directory
- A natural language description (e.g., `redis oob write`) — fuzzy match to closest confirmed finding by title
- A chain description (e.g., `chain: VULN-001 + VULN-003`) — generates one combined report covering all named findings as a multi-step chain

## First-Action Sequence

Execute in this order:

1. **Identify target finding(s)**
   ```bash
   ls {audit_dir}/findings/VULN-*/VULN-*.md
   ```
   Match `<vuln_identifier>` to the correct VULN-NNN directory. For fuzzy match, compare against each finding's `Title:` field. For chain, collect all named VULN-NNN entries.

2. **Check for custom report template**
   ```bash
   ls {PROJECT_DIR}/REPORT.md
   ```
   `PROJECT_DIR` is the parent of `audit_dir` (one level up). If the file exists, read it entirely — use its structure for `report.md`.

3. **Read all identified finding files**
   ```bash
   cat {audit_dir}/findings/VULN-NNN/VULN-NNN.md
   ```
   Extract: Title, Severity, CVSS, CWE, Status, root cause description, affected file/line, code snippets, impact, affected product info, reproducibility.

4. **Read all PoC artifacts**
   ```bash
   ls {audit_dir}/findings/VULN-NNN/poc/
   cat {audit_dir}/findings/VULN-NNN/poc/exploit.py   # if exists
   cat {audit_dir}/findings/VULN-NNN/poc/execution-output.txt  # if exists
   cat {audit_dir}/findings/VULN-NNN/poc/request.txt  # if exists
   cat {audit_dir}/findings/VULN-NNN/poc/response.txt # if exists
   ```

5. **Check for existing Docker artifacts**
   ```bash
   find {audit_dir} -name "docker-compose.yml" -o -name "Dockerfile" 2>/dev/null
   ```
   If found, copy and adapt. If not, synthesize from Affected Products info.

6. **Derive short name** from the vuln title: lowercase, replace spaces and special chars with hyphens, max 40 chars, no VULN-NNN pattern. If ambiguous or unclear, ask the user to confirm the short name before proceeding.

7. **Create output directory and generate all files**
   ```bash
   mkdir -p {audit_dir}/reports/<short_name>
   ```

## Output Structure

```
{audit_dir}/reports/<short_name>/
├── report.md          ← Standalone advisory report
├── setup.sh           ← Docker Compose environment setup (executable)
├── docker-compose.yml ← Vulnerable target definition
└── poc.py             ← Cleaned, self-contained PoC script (omit if no PoC exists)
```

## report.md

### Template Priority

1. **If `{PROJECT_DIR}/REPORT.md` exists**: Read it entirely. Use its exact structure, section headings, and ordering. Fill each section with data from the finding. Do not add or remove sections from the template.

2. **If no custom template**: Use the advisory format below.

### Default Advisory Format

```markdown
# Advisory: [Vuln Title — descriptive, no VULN-ID, no finding numbers]

## Advisory Details
**Title:** [Full descriptive title — include affected component, vuln class, and impact]

## Summary
[3-4 sentences: what the bug is, how it's triggered by an attacker, what the impact is, what prerequisites the attacker needs]

## Details

### Root Cause: [Issue description] (CWE-XXX)
**File:** `path/to/file.c`
**Function:** `FunctionName()` (line ~NNN)

[Vulnerable code block with inline comments pointing to the exact bug]

**Root Cause:** [Paragraph explaining WHY this code is vulnerable — the missing check, wrong assumption, or unsafe operation]
**Primitive:** [One line: what exploitation primitive this provides, e.g., "Arbitrary write to adjacent heap memory"]

### Exploitation Chain
1. **[Step Name]:** [What the attacker does and what it achieves — specific commands or operations]
2. **[Step Name]:** [Next step...]
(continue for all steps)

### Binary Hardening
| Binary | PIE | NX | Canary | RELRO |
|--------|-----|----|--------|-------|
| [name] | Yes/No | Yes/No | Yes/No | Full/Partial/None |

## PoC

- **`poc.py`** — [One sentence description of what the script does]

Expected output:
​```
[Paste the exact verified execution output from execution-output.txt]
​```

### Prerequisites / Special Conditions
1. [First requirement — e.g., specific module version, config flag, auth level, OS/arch]
2. [Second requirement...]
(list all from the finding's prerequisites section)

### Reproduction Steps
1. Run `./setup.sh` to start the vulnerable environment
2. Run `python3 poc.py --host 127.0.0.1 --port <PORT> --cmd "id"`
3. Expected output: [paste expected output]

## Impact
[1-2 sentences: concrete business/security impact (RCE, data exfiltration, etc.) and who is affected (authenticated users, network-accessible, etc.)]

## Affected Products
- **Ecosystem:** [e.g., Redis, npm, PyPI]
- **Package name:** [exact package name]
- **Affected versions:** [version range]
- **Patched versions:** [patched version or "Not yet patched"]

## Severity
**[Critical / High / Medium / Low]**

**CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...** — Score: X.X

- **AV:...** — [one-line justification]
- **AC:...** — [one-line justification]
- **PR:...** — [one-line justification]
- **UI:...** — [one-line justification]
- **S:...** — [one-line justification]
- **C/I/A:...** — [one-line justification]

## Weaknesses
- **CWE-XXX:** [Full CWE name] (primary)
- **CWE-YYY:** [Full CWE name] (secondary, if applicable)

## Recommended Fix
1. [Specific code fix — include a code block showing the corrected implementation]
2. [Build hardening or configuration recommendation, if applicable]
```

### Prohibited Content in report.md

Do NOT include any of the following — scan the completed report.md and remove any occurrences:
- Any string matching `VULN-` followed by digits
- References to other vulnerabilities ("see also", "related finding", "in combination with")
- Audit session metadata (scan start/end dates, orchestrator log paths, semgrep run IDs)
- Placeholder text: TBD, TODO, [placeholder], N/A without explanation

## setup.sh

### Logic

1. If Docker artifacts already exist in the audit dir (from `setup-target` skill), copy and adapt them — do not regenerate from scratch.
2. If no Docker artifacts exist, synthesize `docker-compose.yml` + `setup.sh` from the finding's Affected Products section (package name, version, required configuration flags noted in prerequisites).

### setup.sh Content

```bash
#!/bin/bash
# Starts the vulnerable target environment.
# Requirements: Docker, Docker Compose v2

set -e

echo "Starting vulnerable environment..."
docker compose up -d

# Wait for service to be ready
sleep 3

# Service health check (adapt to target service)
# Example for Redis: redis-cli -p 6379 ping
# Example for HTTP: curl -s http://localhost:PORT/health

echo "Environment ready."
echo "Run: python3 poc.py --host 127.0.0.1 --port <PORT> --cmd 'id'"
```

The docker-compose.yml must pin the exact vulnerable version from Affected Products and include any required config flags noted in Prerequisites (e.g., `enable-debug-command yes` for Redis).

### Prohibited Content in setup.sh
- Any `VULN-` string or finding number reference
- References to other vulnerabilities
- Audit session metadata (dates, log paths)

## poc.py

### Source and Cleaning

Copy the verified exploit from `findings/VULN-NNN/poc/exploit.py`. Do NOT rewrite the exploit logic — copy it and clean only the metadata.

**Cleaning rules — apply in order:**
1. Remove any line containing `VULN-` (comments, variable names, print statements)
2. Remove any comment containing "Finding #", "Related to:", "Part of chain with:", "See also:"
3. Remove any comment containing audit session dates, session IDs, or orchestrator references
4. Add this header block at the very top of the file (before any imports):
   ```python
   #!/usr/bin/env python3
   # Usage: python3 poc.py --host 127.0.0.1 --port PORT --cmd "id"
   # Requirements: pip install pwntools
   # Target: [Affected Product name and version from finding]
   ```
5. Ensure all target configuration (host, port, command) is via argparse or clearly labeled top-level constants — not hardcoded mid-script
6. Preserve all exploit logic, functions, and output formatting exactly as verified

**If no PoC exists** (Status is CONFIRMED-THEORETICAL, or `poc/` directory is empty or missing `exploit.py`):
- Omit `poc.py` from the output folder entirely
- In `report.md` under the PoC section, write: "No executable PoC available — vulnerability confirmed via code analysis only."

### Prohibited Content in poc.py
- Any `VULN-` string anywhere in the file
- Any comment referencing other findings or vulnerabilities
- Hardcoded host/port/command that can't be overridden by the user

## Quality Bar

Run these checks on all generated files before declaring the task complete:

```bash
# No VULN- references in any output file
grep -r "VULN-" {audit_dir}/reports/<short_name>/ && echo "FAIL: VULN refs found" || echo "PASS"

# report.md length
wc -l {audit_dir}/reports/<short_name>/report.md
# Must be >= 50 lines

# Required sections in report.md
grep -l "## Summary" {audit_dir}/reports/<short_name>/report.md
grep -l "## Details" {audit_dir}/reports/<short_name>/report.md
grep -l "Reproduction Steps" {audit_dir}/reports/<short_name>/report.md
grep -l "## Severity" {audit_dir}/reports/<short_name>/report.md
grep -l "CVSS:3.1" {audit_dir}/reports/<short_name>/report.md
grep -l "## Recommended Fix" {audit_dir}/reports/<short_name>/report.md

# setup.sh contains docker compose
grep "docker compose" {audit_dir}/reports/<short_name>/setup.sh || echo "FAIL: no docker compose"

# Short name validity
echo "<short_name>" | grep -E '^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$' && echo "PASS" || echo "FAIL: invalid short name"
```

If any check fails, fix the output file before finishing.

## Writing Guidelines

- **No VULN-NNN anywhere** — this is the primary rule. The report must make sense to a reader who has never seen the audit workspace.
- **Exact code references** — use `file:line` format for all code citations in report.md
- **Verified output only** — paste the actual `execution-output.txt` content, not approximations
- **Complete reproduction steps** — a reader with no prior context must be able to follow setup.sh + poc.py to reproduce the finding
- **Self-contained PoC** — poc.py must run with only pip dependencies, no local file imports or hardcoded paths from the audit workspace
