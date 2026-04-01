---
name: write-report
description: Report generation methodology for security audits. Handles mode detection (pipeline vs standalone), custom template support, and produces a professional report with executive summary, findings table, vulnerability chains, and remediation roadmap.
argument-hint: "<audit_dir> [--project-dir <project_dir>]"
---

# Write Report — Security Assessment Report Generation

## Goal

Transform security findings into a polished, professional report suitable for both technical teams and executive stakeholders. Handles two modes: pipeline (from a completed audit workspace) and standalone (from user-supplied findings).

## Mode Detection

### Pipeline Mode
**Triggered when**: `AUDIT_DIR` exists with `findings/VULN-*/VULN-*.md` files.

### Standalone Mode
**Triggered when**: User provides finding descriptions directly (pasted text, file paths, verbal descriptions) without a full audit workspace.

For standalone mode:
1. Create `{AUDIT_DIR}/findings/` if needed
2. For each user-supplied finding, create standard directory structure:
   - `findings/VULN-NNN/VULN-NNN.md` — formatted using standard template
   - `findings/VULN-NNN/poc/` — write any PoC code, requests, responses provided
3. Then proceed to report generation

## First-Action Sequence

Execute in this order:
1. Read `{AUDIT_DIR}/logs/scope_brief.md` (if exists)
2. Check for custom template: `ls {PROJECT_DIR}/REPORT.md`
3. List all confirmed findings: `ls {AUDIT_DIR}/findings/VULN-*/VULN-*.md`
4. Read each finding file
5. Read recon artifacts (if they exist): `recon/intelligence.md`, `recon/architecture.md`, `recon/attack-surface.md`

## Custom Template Handling

**If `{PROJECT_DIR}/REPORT.md` exists**: Read it entirely. Use its structure, sections, headings, and formatting as the template. Fill each section with data from findings. If a template section has no applicable data, include it with "N/A" or "No findings in this category." Preserve the template's ordering and style.

**If no `REPORT.md`**: Use the default format below.

## Program Requirements

If `scope_brief.md` exists and has `report_requirements`:
- Include all mandatory fields (version, screenshots, repro steps)
- State exact affected version
- If video/screenshots required: add `Warning: Program requires video/screenshots before submission`
- Redact PII, credentials, secrets from the report
- Exclude findings matching `non_qualifying_vulns` or `out_of_scope`

## Default Report Template

Write to `{AUDIT_DIR}/report.md`:

```markdown
# Security Assessment Report

## Executive Summary

[For non-technical executives. Business impact — financial, regulatory, operational. No jargon.]

### Engagement Overview
- **Target**: [system name and type]
- **Assessment Period**: [dates]
- **Scope**: [what was tested]
- **Methodology**: Semantic code analysis, automated scanning (Semgrep), manual code review, [live testing if applicable]

### Risk Summary
| Severity | Count | Key Findings |
|---|---|---|
| Critical | N | [brief description] |
| High | N | [brief description] |
| Medium | N | |
| Low | N | |

### Top Recommendations
1. [Most urgent action]
2. [Second priority]
3. [Third priority]

### Positive Observations
[Security controls that were well-implemented]

---

## Findings Summary

| ID | Title | Severity | CVSS | CWE | Status |
|---|---|---|---|---|---|
| [VULN-NNN](findings/VULN-NNN/VULN-NNN.md) | Title | CRITICAL | 9.8 | CWE-89 | CONFIRMED |

> Full finding details in each linked file. PoC scripts and evidence in each finding's `poc/` subdirectory.

---

## Vulnerability Chains

[Multi-step attack chains. For each: steps, combined impact, prerequisites.
If none identified, state "No multi-step vulnerability chains identified."]

---

## Scope & Methodology

- **Standards Referenced**: OWASP Testing Guide v4.2, OWASP Top 10 2021, CWE/SANS Top 25, CVSS v3.1
- **Tools Used**: Semgrep (SAST), manual semantic code review, [others]
- **Assessment Approach**: Skills-driven analysis — reconnaissance, variant analysis, deep semantic code review, automated pattern detection, adversarial verification
- **Limitations**: [any scope exclusions, time constraints, or access limitations]

---

## Remediation Roadmap

### Priority 1 — Immediate (Critical/High)
| Finding | Action | Effort | Risk if Unpatched |
|---|---|---|---|

### Priority 2 — Short-term (Medium)
| Finding | Action | Effort |
|---|---|---|

### Priority 3 — Hardening (Low/Informational)
| Finding | Action |
|---|---|

### Architectural Recommendations
[Systemic improvements beyond individual fixes]

---

## Appendix: Tool Inventory
| Tool | Purpose | Findings Attributed |
|---|---|---|
```

## Writing Guidelines

- **Reference actual code** with `file:line` — never use vague references
- **Never inflate severity** — report what was verified, not what might theoretically be possible
- **Executive summary first** — lead with business impact, not technical details
- **Actionable remediation** — each finding's fix should be specific enough for a developer to implement
- **Link findings by ID** — use `VULN-NNN` identifiers consistently throughout
- **Positive observations** — acknowledge good security practices to build credibility and guide future development

## Quality Bar

- `report.md` MUST be >= 50 lines
- MUST include an `## Executive Summary` heading
- Every VULN-NNN must be referenced by ID in the findings table
- MUST include a `## Remediation Roadmap` section
- No placeholder text — if a section has no data, state that explicitly
- Severity distribution must match the actual findings (don't omit severity levels)
