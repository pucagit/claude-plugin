---
name: variant-analysis
description: Analyze git history for security-related commits, scan dependency manifests for known CVEs, and search the codebase for unfixed variant patterns. Produces variant-analysis.md with security commits, dependency CVEs, and variant candidates.
argument-hint: "<target_source> <audit_dir>"
user-invocable: false
---

# Variant Analysis — Git History, Dependency CVEs & Pattern Variants

## Goal

Find vulnerabilities by analyzing what was *already found and fixed* — in this codebase's git history and in public CVE databases for its dependencies — then search for unfixed siblings of those patterns.

This is one of the highest-value techniques in security research. If a pattern was dangerous enough to fix once, the same pattern likely exists elsewhere in the codebase unfixed.

## Learned Techniques
Before analysis, read [references/cool_techniques.md](references/cool_techniques.md) for applicable variant analysis techniques learned from previous audits. Apply any relevant techniques during your analysis.

## Inputs

- `TARGET_SOURCE`: Path to the target source code (must be a git repository for Steps 1-2)
- `AUDIT_DIR`: Path to the audit workspace

## Step 1: Git Security History

Search the git log for security-relevant commits:

```bash
git -C ${TARGET_SOURCE} log --all --oneline --grep="CVE\|cve-\|security\|vuln\|exploit\|injection\|overflow\|bypass\|sanitiz\|escap\|xss\|csrf\|ssrf\|traversal\|deserialization\|privilege\|authz\|authn\|patch\|hotfix\|fix.*bug\|use.after.free\|double.free\|race.condition\|buffer\|heap\|stack\|rce\|idor\|bola" -i --since="3 years ago" 2>/dev/null || echo "Not a git repo or no matches"
```

For each matching commit (up to 30 most recent):

```bash
git -C ${TARGET_SOURCE} show --stat <commit_hash>
git -C ${TARGET_SOURCE} show <commit_hash> -- '*.py' '*.js' '*.ts' '*.java' '*.go' '*.rb' '*.php' '*.rs' '*.c' '*.cpp'
```

Read each diff carefully. Understand:
- What was the vulnerability?
- What was the fix?
- What pattern made it dangerous?

## Step 2: Pattern Extraction

For each security commit, extract a structured record:

| Field | Value |
|---|---|
| Commit | `<hash>` — `<subject line>` |
| CWE | CWE-XXX (classify the vulnerability) |
| Dangerous Pattern | Description of the code pattern that was vulnerable |
| Fix Applied | Description of what the fix changed |
| Grep Signature | A regex that would match similar unfixed code |
| Files Changed | List of files modified in the fix |

Focus on extracting **grep-able signatures** — the unfixed form of the pattern. For example:
- If the fix added parameterized queries → signature matches string-concatenated queries
- If the fix added input validation → signature matches the unvalidated sink call
- If the fix added authentication → signature matches the unprotected endpoint pattern

## Step 3: Dependency CVE Scan

Read dependency manifests to identify libraries and versions:

```bash
# Find all dependency manifests
find ${TARGET_SOURCE} -maxdepth 3 \( \
  -name "package.json" -o -name "package-lock.json" -o \
  -name "requirements.txt" -o -name "Pipfile.lock" -o -name "poetry.lock" -o \
  -name "go.mod" -o -name "go.sum" -o \
  -name "pom.xml" -o -name "build.gradle" -o \
  -name "Cargo.toml" -o -name "Cargo.lock" -o \
  -name "Gemfile" -o -name "Gemfile.lock" -o \
  -name "composer.json" -o -name "composer.lock" \
\) -not -path "*/node_modules/*" -not -path "*/vendor/*" 2>/dev/null
```

For each manifest:
1. Read it and extract library names + pinned versions
2. For the top 10 most security-relevant libraries (web frameworks, auth libs, crypto libs, serialization libs, database drivers), search for known CVEs:
   - Web search: `"<library> <version>" CVE vulnerability`
   - Web search: `site:nvd.nist.gov "<library>"` or `site:github.com/advisories "<library>"`
3. For each CVE found: read the advisory to understand the vulnerable code path and whether it affects the version in use

Record each finding:

| Library | Version | CVE | Severity | Affected Versions | Summary |
|---|---|---|---|---|---|

## Step 4: Variant Search

For each dangerous pattern from Step 2 (git history):
1. Run the extracted grep signature against `TARGET_SOURCE`
2. For each match, read the surrounding code (20+ lines of context)
3. Determine: is this the same dangerous pattern, unfixed?
4. If yes: record as a **variant candidate** with file:line and reasoning

For each dependency CVE from Step 3:
1. Search for usage of the vulnerable API/function in the codebase
2. Determine: does the code use the library in the way described by the CVE?
3. If yes: record as a **dependency vulnerability** with file:line and usage context

## Step 5: Output

Write `{AUDIT_DIR}/recon/variant-analysis.md`:

```markdown
# Variant Analysis

## Security Commits Analyzed

[For each commit from Step 2 — table format with all extracted fields]

## Dependency CVEs

[For each CVE from Step 3 — table format]
[Note: "No dependency manifests found" or "No CVEs found" if applicable]

## Variant Candidates

### From Git History Patterns

[For each variant hit from Step 4]
- **Pattern**: [description of the dangerous pattern]
- **Original fix**: [commit hash]
- **Unfixed location**: `file:line`
- **Reasoning**: [why this is the same dangerous pattern]
- **Confidence**: HIGH / MEDIUM / LOW

### From Dependency CVEs

[For each dependency usage hit]
- **CVE**: [CVE-YYYY-NNNNN]
- **Library**: [name@version]
- **Usage location**: `file:line`
- **Reasoning**: [how the code uses the vulnerable API]
- **Confidence**: HIGH / MEDIUM / LOW

## Summary

- Security commits analyzed: N
- Dependency CVEs found: N
- Variant candidates (git patterns): N
- Variant candidates (dependency CVEs): N
- High-confidence variants requiring immediate investigation: N
```

## Quality Bar

- Every variant candidate must include `file:line` and reasoning for why it matches the dangerous pattern
- Do not list grep hits that are clearly false positives (e.g., test files, comments, safe usage patterns)
- If the target is not a git repository, skip Steps 1-2 and note this in the output
- If no dependency manifests are found, skip Step 3 and note this
- An empty result is acceptable — write "No variants found" with a brief explanation of what was searched
