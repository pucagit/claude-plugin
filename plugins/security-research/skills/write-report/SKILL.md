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

Produce a self-contained advisory a maintainer can read in under a minute and act on. Lead with the bug, the impact, and the fix. Skip throat-clearing, leading paragraphs, restating the title, and explanations of obvious things. The reader is a maintainer, not a manager.

No VULN-NNN identifiers, no cross-finding references, no audit session metadata anywhere in the output.

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
   Extract: Title, Severity, CVSS, CWE, Status, root cause, affected file/line, code snippets, impact, affected product info, reproducibility.

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

1. **If `{PROJECT_DIR}/REPORT.md` exists**: read it entirely. Use its exact structure, section headings, and ordering. Fill each section with data from the finding. Do not add or remove sections.

2. **If no custom template**: use the lean format below.

### Default Advisory Format

A maintainer must understand the vuln and its impact within 30 seconds. Lead with the bug, what it does, where it is, and how to fix it. Cut every section that has nothing concrete to say.

````markdown
# [Vuln Title — what + where, e.g., "Heap OOB write in FooModule.parse()"]

**Severity:** [Critical/High/Medium/Low] — CVSS 3.1: X.X (`CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...`)
**CWE:** CWE-XXX [name] (+ CWE-YYY if secondary)
**Affected:** [Package] [version range] — fixed in [version or "unfixed"]

## Impact
[One sentence: what an attacker achieves (RCE / data read / auth bypass / DoS) and the precondition (network reachable, authenticated user, specific config flag).]

## Root Cause
**File:** `path/to/file.c:NNN` — `FunctionName()`

```c
// only the relevant lines, with ONE inline comment marking the exact bug
```

[One sentence naming the missing check or wrong assumption. No filler.]

## Exploitation
[Numbered steps. Each step = one action + what it achieves. No prose between steps. Omit this section if the bug is single-step.]

1. **[Action]:** [Result]
2. **[Action]:** [Result]

(Include `### Binary Hardening` table only if the target is a native binary and hardening is load-bearing for the chain.)

## PoC

Run:
```
./setup.sh
python3 poc.py --host 127.0.0.1 --port <PORT> --cmd "id"
```

Expected output (verified):
```
[Paste exact execution-output.txt content]
```

Prerequisites: [comma-separated, only if non-trivial — e.g., "module loaded with `enable-debug yes`, x86_64 glibc target". Omit the line entirely if there are none beyond running the setup.]

## Fix
```diff
- vulnerable line
+ corrected line
```

[One sentence on the fix only if a non-obvious tradeoff exists. Otherwise nothing.]
````

### Format Rules

- **One header block, not five.** Severity, CWE, and Affected go in the top metadata block. No separate "Advisory Details", "Summary", "Weaknesses", or "Affected Products" sections.
- **No Summary section.** Title + Impact already summarize.
- **No CVSS metric-by-metric justification.** The vector string is self-documenting. Add a one-line note only if a metric is non-obvious (e.g., explain `S:C` scope change).
- **Drop empty sections.** No exploitation chain → drop "Exploitation". No hardening relevance → drop the table. No PoC → see "no-PoC fallback" below.
- **No leading paragraphs.** Don't open a section with "This vulnerability allows…" — the title and Impact line have already established that. Get to the technical content immediately.
- **Code blocks contain code, not prose.** Inline comments in code are fine; full-sentence narration above the block is usually redundant.

### Prohibited Content in report.md

Do NOT include any of the following — scan the completed report.md and remove any occurrences:
- Any string matching `VULN-` followed by digits
- References to other vulnerabilities ("see also", "related finding", "in combination with")
- Audit session metadata (scan start/end dates, orchestrator log paths, semgrep run IDs)
- Placeholder text: TBD, TODO, [placeholder], N/A without explanation
- Filler phrasing: "It is important to note that…", "This vulnerability is significant because…", "In conclusion…", marketing-style severity adjectives ("devastating", "critical implications")

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
- In `report.md` under the PoC section, write only: `No executable PoC — confirmed via code analysis.`

### Prohibited Content in poc.py
- Any `VULN-` string anywhere in the file
- Any comment referencing other findings or vulnerabilities
- Hardcoded host/port/command that can't be overridden by the user
- Tutorial-style narration comments ("Now we will send the payload to trigger…")

## Quality Bar

Run these checks on all generated files before declaring the task complete:

```bash
# No VULN- references in any output file
grep -r "VULN-" {audit_dir}/reports/<short_name>/ && echo "FAIL: VULN refs found" || echo "PASS"

# Required content in report.md
grep -l "## Impact" {audit_dir}/reports/<short_name>/report.md
grep -l "## Root Cause" {audit_dir}/reports/<short_name>/report.md
grep -l "## Fix" {audit_dir}/reports/<short_name>/report.md
grep -l "CVSS:3.1" {audit_dir}/reports/<short_name>/report.md
grep -l "CWE-" {audit_dir}/reports/<short_name>/report.md

# Filler-phrase scan (should return nothing)
grep -iE "it is important to note|in conclusion|this vulnerability is significant|devastating impact" \
  {audit_dir}/reports/<short_name>/report.md && echo "FAIL: filler phrasing" || echo "PASS"

# setup.sh contains docker compose
grep "docker compose" {audit_dir}/reports/<short_name>/setup.sh || echo "FAIL: no docker compose"

# Short name validity
echo "<short_name>" | grep -E '^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$' && echo "PASS" || echo "FAIL: invalid short name"
```

If any check fails, fix the output file before finishing.

## Writing Style

- **Lead with the bug.** First line of every section is the technical fact, not a setup sentence.
- **One sentence per claim.** If a section is more than three short sentences plus a code block, you are over-explaining.
- **Active voice, present tense.** "The function reads N bytes without checking the buffer size" — not "A vulnerability was identified where the buffer size was not being checked".
- **Code over prose.** A diff or annotated snippet beats two paragraphs of explanation.
- **No marketing language.** No "critical", "devastating", "severe security implications" outside the Severity field. The CVSS score conveys severity.
- **Exact code references** — `file:line` format for every code citation.
- **Verified output only** — paste actual `execution-output.txt`, not approximations.
- **Self-contained PoC** — `poc.py` runs with only pip dependencies, no local imports or audit-workspace paths.
