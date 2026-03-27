---
name: capture-technique
description: Self-improvement skill. When a high-quality vulnerability is found, this skill analyzes what worked well and stores the technique in the appropriate detection skill's references/cool_techniques.md file for future audits. User-invoked only.
argument-hint: "[finding_id] [target_skill]"
user-invocable: true
---

# Capture Technique — Store Successful Approaches for Future Audits

## Goal

When you find a vulnerability through a novel or effective technique, capture what worked so future audits benefit from that knowledge. Techniques are stored in the **specific detection skill's** `references/cool_techniques.md` file so each skill only sees techniques relevant to its domain.

## When to Use

This skill is **user-invoked only**. The user will call it when:
- They see a good finding and want to capture the methodology
- They explicitly ask: "capture what you just did as a technique" or "remember this approach"
- After a confirmed HIGH/CRITICAL finding that used a non-obvious technique

## Procedure

### Step 1: Identify the Success

- What finding or approach is being captured?
- Which file/module was involved?
- What vulnerability class was discovered?
- Was this a finding that the automated detect-* patterns would have caught, or did it require deeper reasoning?

If the automated patterns would have caught it, **skip** — only capture genuinely novel insights.

### Step 2: Analyze the Methodology

What specific technique led to the discovery?

| Technique Type | Example |
|---|---|
| Deep-dive reasoning chain | Found UAF by tracing object lifecycle through 5 functions |
| Variant analysis hit | Found unfixed sibling of a patched CVE |
| Algorithm understanding | Found overflow by understanding compression boundary conditions |
| Cross-module data flow | Traced input through 4 modules to find unvalidated sink |
| State machine analysis | Found auth bypass by identifying unexpected state transition |
| Edge case reasoning | Found injection via Unicode null byte that bypassed filter |
| Git history insight | Identified that a "fix" was incomplete by reading the original patch |

### Step 3: Extract the Insight

Formulate a concise, reusable technique:
- **When to apply it** — what conditions or code patterns should trigger this technique?
- **What to look for** — the specific thing to examine or question to ask
- **Why it works** — the underlying principle that makes this effective
- **Concrete example** — from the current audit, anonymized if needed

### Step 4: Determine Target Skill

Which skill should this technique be stored in?

| Discovery Method | Target Skill | File |
|---|---|---|
| Novel injection pattern | `detect-injection` | `detect-injection/references/cool_techniques.md` |
| Auth/access control insight | `detect-auth` | `detect-auth/references/cool_techniques.md` |
| Business logic/timing flaw | `detect-logic` | `detect-logic/references/cool_techniques.md` |
| Config/crypto weakness | `detect-config` | `detect-config/references/cool_techniques.md` |
| Deep code reasoning insight | `deep-dive` | `deep-dive/references/cool_techniques.md` |
| Git history/variant technique | `variant-analysis` | `variant-analysis/references/cool_techniques.md` |

### Step 5: Store the Technique

1. Read the target skill's `references/cool_techniques.md`
2. Append the new technique in this format:

```markdown
### [Technique Name] (learned [YYYY-MM-DD])
**When to apply**: [conditions — language, framework, vuln class, code pattern]
**Technique**: [what to do — the specific approach that worked]
**Example**: [concrete example from the audit where this was discovered, anonymized]
```

3. Write the updated file

### Step 6: Log

If an `AUDIT_DIR` is available (check CLAUDE.md), append to `{AUDIT_DIR}/logs/learned-techniques.log`:

```
[YYYY-MM-DD HH:MM] Technique: [name] | Target skill: [skill name] | Finding: [VULN-NNN or description]
```

## Guard Rails

- **Only genuinely novel insights** — if the technique is already covered by the skill's existing patterns or methodology, skip. Don't add "check for SQL injection in query builders" to detect-injection — that's already there.
- **Never modify core methodology sections** — only append to `references/cool_techniques.md`.
- **Keep techniques concise** — each should be 3-5 lines. If it takes a paragraph to explain, it's too complex for a quick reference.
- **Anonymize examples** — don't include target-specific details (company names, internal URLs, credentials) in technique files that persist across audits.
- **Check for duplicates** — read the existing cool_techniques.md before adding. Don't store the same technique twice.
