---
name: capture-technique
description: Self-improvement skill. When a high-quality vulnerability is found and the user gives positive feedback, this skill analyzes what worked well and updates the relevant skill file to encode that knowledge for future audits.
argument-hint: "[finding_id] [target_skill]"
user-invokable: true
---

# Capture Technique — Encode Successful Approaches for Future Audits

## Goal

When you find a vulnerability through a novel or effective technique, and the user confirms it's a good find, capture what worked so future audits benefit from that knowledge.

## Triggers

- User gives positive feedback: "great find", "exactly right", "this is what I was looking for", "nice", "perfect"
- User explicitly asks: "capture what you just did as a technique" or "remember this approach"
- Orchestrator invokes after a confirmed HIGH/CRITICAL finding that used a non-obvious technique

## Procedure

### Step 1: Identify the Success

- What finding or approach did the user praise?
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

Which skill should this technique improve?

| Discovery Method | Target Skill |
|---|---|
| Novel injection pattern | `detect-injection` |
| Auth/access control insight | `detect-auth` |
| Business logic/timing flaw | `detect-logic` |
| Config/crypto weakness | `detect-config` |
| Deep code reasoning insight | `deep-dive` |
| Git history/variant technique | `variant-analysis` |
| Verification technique | `verify-finding` |

### Step 5: Update the Skill

1. Read the target skill's `SKILL.md`
2. Check for a `## Learned Techniques` section at the end — create it if it doesn't exist
3. Count existing techniques — if already at **5 techniques**, ask the user which older one to replace
4. Append the new technique:

```markdown
### [Technique Name] (learned [YYYY-MM-DD])
**When to apply**: [conditions — language, framework, vuln class, code pattern]
**Technique**: [what to do — the specific approach that worked]
**Example**: [concrete example from the audit where this was discovered]
```

### Step 6: Log

Append to `{AUDIT_DIR}/logs/learned-techniques.log`:

```
[YYYY-MM-DD HH:MM] Technique: [name] | Target skill: [skill name] | Finding: [VULN-NNN or description]
```

## Guard Rails

- **Maximum 5 learned techniques per skill file** — prevents bloat. If at capacity, ask which to replace.
- **Only genuinely novel insights** — if the technique is already covered by the skill's existing patterns or methodology, skip. Don't add "check for SQL injection in query builders" to detect-injection — that's already there.
- **Never modify core methodology sections** — only append to `## Learned Techniques` at the end of the skill file.
- **Keep techniques concise** — each should be 3-5 lines. If it takes a paragraph to explain, it's too complex for a quick reference.
- **Anonymize examples** — don't include target-specific details (company names, internal URLs, credentials) in skill files that persist across audits.
