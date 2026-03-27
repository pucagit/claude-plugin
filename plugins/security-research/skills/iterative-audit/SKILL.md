---
name: iterative-audit
description: Run additional security audit passes that build on previous work. Reads all existing findings, attack surfaces, and coverage data to identify gaps, generate new hunting hypotheses, and focus on unexplored areas. Maintains a coverage tracker across runs for stateful optimization. Use after an initial audit to find vulnerabilities missed in earlier passes.
argument-hint: "[audit_dir]"
user-invocable: true
---

# Iterative Security Audit — Multi-Pass Vulnerability Hunter

## Goal

Not every vulnerability can be found in a single audit pass. This skill runs additional focused passes that build on previous work — covering remaining attack surfaces, discovering new ones from confirmed findings, and hunting for vulnerabilities that require different perspectives or deeper analysis.

## Prerequisites

- A completed initial audit (via the security-orchestrator)
- CLAUDE.md exists in the project directory
- `security_audit/recon/` has intelligence.md, architecture.md, attack-surface.md
- `security_audit/findings/` may contain existing VULN-NNN/ directories

## Step 1: Read Previous State

Read ALL existing audit artifacts to understand what's been done:

```bash
# Read workspace config
cat ${PROJECT_DIR}/CLAUDE.md

# Read recon artifacts
cat ${AUDIT_DIR}/recon/intelligence.md
cat ${AUDIT_DIR}/recon/architecture.md
cat ${AUDIT_DIR}/recon/attack-surface.md
cat ${AUDIT_DIR}/recon/variant-analysis.md 2>/dev/null
cat ${AUDIT_DIR}/recon/web_intelligence.md 2>/dev/null

# Read existing findings
ls ${AUDIT_DIR}/findings/VULN-*/VULN-*.md 2>/dev/null
# Read each finding's metadata (Status, Severity, CWE, Location)

# Read false positives
cat ${AUDIT_DIR}/false-positives.md 2>/dev/null

# Read scan candidates
cat ${AUDIT_DIR}/logs/scan-candidates.md 2>/dev/null

# Read coverage tracker if exists (from previous iterative runs)
cat ${AUDIT_DIR}/recon/coverage-tracker.md 2>/dev/null

# Read learned techniques (new since last run)
for skill in detect-injection detect-auth detect-logic detect-config deep-dive variant-analysis; do
  cat skills/${skill}/references/cool_techniques.md 2>/dev/null
done
```

## Step 2: Initialize or Update Coverage Tracker

If `{AUDIT_DIR}/recon/coverage-tracker.md` doesn't exist, create it by analyzing the current state:

```markdown
# Audit Coverage Tracker

## Run History
| Run | Date | Findings | New Attack Surfaces | Focus Areas |
|-----|------|----------|-------------------|-------------|
| 1 (initial) | {date from orchestrator.log} | {count from findings/} | {count from attack-surface.md} | Full audit |

## Explored Modules
| Module | Run # | Findings | Technique Used | Notes |
|--------|-------|----------|----------------|-------|
[Populate from existing findings — which files were analyzed, what was found]

## Unexplored Modules
| Module | Priority | Reason for Priority |
|--------|----------|-------------------|
[Identify modules from architecture.md NOT appearing in any finding or deep-dive]

## Hunting Hypotheses (Status)
[Copy hypotheses from attack-surface.md, mark each as tested/untested based on findings]
- [x] {hypothesis} — tested in run 1, result: {VULN-NNN / no finding}
- [ ] {hypothesis} — NOT tested yet
```

If coverage-tracker.md already exists, read it and proceed to Step 3.

## Step 3: Gap Analysis

Identify what was missed or underexplored:

### 3a: Module Coverage Gaps
Compare `architecture.md` endpoint inventory and `attack-surface.md` Critical Module Ranking against `findings/` and coverage-tracker.md:
- Which high-priority modules were never deep-dived?
- Which endpoints have no findings AND no false-positive entries (never tested)?
- Are there modules added since the last run (check git log for recent commits)?

### 3b: Hypothesis Coverage Gaps
Review Hunting Hypotheses from attack-surface.md:
- Which hypotheses were never tested?
- Which scan-candidates from Phase 2A were triaged as INVESTIGATE but never deep-dived?

### 3c: Variant Expansion Opportunities
For each CONFIRMED finding from previous runs:
- Was variant expansion performed? (Check if variants exist)
- Can the vulnerable pattern be generalized and searched more broadly?
- Does the finding suggest a systemic issue (e.g., all endpoints in a module lack auth)?

### 3d: New Attack Surfaces from Findings
Previous findings may reveal NEW attack surfaces not in the original recon:
- A confirmed SSRF reveals new internal endpoints to probe
- A confirmed auth bypass reveals new privilege levels to test
- A confirmed injection in one module suggests similar modules are vulnerable
- Cross-module chains: does combining findings A and B create a higher-impact chain?

### 3e: Technique Coverage Gaps
- Were any new techniques added to `references/cool_techniques.md` since the last run?
- Apply new techniques to previously-explored modules (may find what was missed)
- Consider different analysis angles:
  - Previous run focused on injection? This run focus on logic/auth.
  - Previous run traced forward (source→sink)? This run trace backward (sink→source).
  - Previous run analyzed individual modules? This run analyze cross-module interactions.

## Step 4: Generate Run Plan

Create a focused plan for this run:

```
ITERATIVE AUDIT — RUN #{N}
══════════════════════════════════════════
Previous runs: {N-1}
Previous findings: {count} ({confirmed}C, {fp}FP)
Coverage: {explored}/{total} high-priority modules

This run will focus on:

1. UNEXPLORED MODULES ({count}):
   - {module_path} — Priority: HIGH — Reason: {why}
   - {module_path} — Priority: MEDIUM — Reason: {why}

2. UNTESTED HYPOTHESES ({count}):
   - {hypothesis} — from attack-surface.md
   - {hypothesis} — from scan-candidates.md

3. VARIANT EXPANSION ({count}):
   - Expand VULN-{NNN} pattern to {N} candidate files
   - Cross-module chain: VULN-{A} + VULN-{B}

4. NEW TECHNIQUES TO APPLY ({count}):
   - {technique} on {module} — learned {date}

5. FRESH PERSPECTIVE:
   - {new angle not tried in previous runs}

Estimated new findings: {low}-{high}
══════════════════════════════════════════

Approve this plan to begin, or tell me what to change.
```

> **HARD GATE — Do NOT proceed until the user approves.**

## Step 5: Execute Focused Hunting

For each item in the approved plan:

### Unexplored modules:
- Invoke skill="deep-dive" args="<module_path>"
- Apply all relevant detect-* skills
- Write findings immediately using the MANDATORY FINDING STRUCTURE from the orchestrator

### Untested hypotheses:
- Read the specific hypothesis from attack-surface.md
- Trace the suspected vulnerability path
- Confirm or dismiss with evidence
- Update hypothesis status in coverage-tracker.md

### Variant expansion:
- Extract pattern from confirmed finding
- Grep for pattern across codebase
- Deep-dive each candidate match
- Create VULN-NNN entries for confirmed variants

### New techniques:
- Read the technique from the relevant cool_techniques.md
- Apply to previously-explored modules that match the technique's trigger conditions
- Document what was found (or not found)

### Cross-module analysis:
- Trace data flows that span multiple modules
- Query gitnexus for cross-file call chains
- Look for chains: Finding A enables Finding B for higher impact

For each finding, self-verify inline: invoke skill="verify-finding" before writing.

## Step 6: Update Coverage Tracker

After completing the run, update `{AUDIT_DIR}/recon/coverage-tracker.md`:

1. Add new row to **Run History** table
2. Move modules from **Unexplored** to **Explored** (with findings and notes)
3. Update **Hunting Hypotheses** checkboxes
4. Add any NEW hypotheses discovered during this run
5. Add any NEW unexplored modules discovered

## Step 7: Display Results

```
ITERATIVE AUDIT — RUN #{N} COMPLETE
══════════════════════════════════════════
New findings this run:    {count}
  By severity:            {critical}C / {high}H / {medium}M / {low}L
  Variants expanded:      {count}
  Chains discovered:      {count}

Cumulative totals:
  Total findings:         {total}
  Total confirmed:        {confirmed}
  Total false positives:  {fp}

Coverage update:
  Modules explored:       {explored}/{total} ({percentage}%)
  Hypotheses tested:      {tested}/{total} ({percentage}%)
  Remaining high-priority gaps: {count}

Recommendation:
  {CONTINUE — {N} high-priority gaps remain, estimated {M} more findings}
  or
  {WRAP UP — coverage is comprehensive, diminishing returns expected}

Next steps:
  - /security-research:iterative-audit  → Run another pass
  - /security-research:verify-finding   → Re-verify or execute PoCs
  - /security-research:write-report     → Generate report with all findings
  - /security-research:capture-technique → Capture successful techniques
══════════════════════════════════════════
```

## Termination Guidance

Recommend wrapping up when:
- All high-priority modules have been explored
- All hunting hypotheses have been tested
- No new attack surfaces discovered in the last run
- Variant expansion yields no new confirmed findings
- Coverage exceeds 80% of critical modules

Recommend continuing when:
- High-priority modules remain unexplored
- Untested hypotheses exist for HIGH/CRITICAL vulnerability classes
- New techniques were recently learned that haven't been applied
- Previous run discovered new attack surfaces not yet explored
- Confirmed findings suggest systemic patterns worth expanding
