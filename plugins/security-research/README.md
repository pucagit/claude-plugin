# Security Research Plugin for Claude Code

A skills-primary offensive security research framework. Claude performs semantic code analysis — reading and understanding code deeply — to find vulnerabilities that pattern matching misses. Skills provide methodology; the orchestrator does the work itself, maintaining continuous context throughout the audit.

## Setup

### 1. Add marketplace and install the plugin
Open Claude Code and type in:

```bash
/plugin marketplace add https://github.com/pucagit/claude-plugin.git
/plugin install security-research@pucaplugin
/reload-plugins
```

### 2. Install Semgrep (required)

Semgrep is the SAST engine used for automated scanning. The orchestrator will attempt to install it automatically, but pre-installing is recommended:

```bash
pip install semgrep
```

### 3. Install LSP servers (install only what you need)

The plugin bundles configs for 12 language servers. LSP servers provide type analysis used to reduce false positives, confirm code reachability, and validate PoC scripts. **You only need to install the ones matching your target's language.**

| Language | Install Command | Binary |
|----------|----------------|--------|
| **Python** | `npm install -g pyright` or `pip install pyright` | `pyright-langserver` |
| **TypeScript / JavaScript** | `npm install -g typescript-language-server typescript` | `typescript-language-server` |
| **Go** | `go install golang.org/x/tools/gopls@latest` | `gopls` |
| **C / C++** | `sudo apt install clangd` | `clangd` |
| **Rust** | `rustup component add rust-analyzer` | `rust-analyzer` |
| **Java** | `brew install jdtls` or [manual install](https://download.eclipse.org/jdtls/snapshots/) | `jdtls` (requires JDK 17+) |
| **Ruby** | `gem install ruby-lsp` | `ruby-lsp` (requires Ruby 3.0+) |
| **PHP** | `npm install -g intelephense` | `intelephense` |
| **Kotlin** | `brew install JetBrains/utils/kotlin-lsp` | `kotlin-lsp` |
| **C#** | `dotnet tool install --global csharp-ls` | `csharp-ls` (requires .NET SDK 6.0+) |
| **Lua** | `sudo apt install lua-language-server` | `lua-language-server` |
| **Swift** | Included with Xcode / `brew install swift` | `sourcekit-lsp` |

LSP servers activate automatically when the plugin detects files matching their configured extensions. Missing binaries are silently skipped — analysis falls back to grep-based patterns.

### Verify your setup

```bash
# Check which LSP binaries are available
for cmd in pyright-langserver typescript-language-server gopls clangd rust-analyzer ruby-lsp jdtls intelephense lua-language-server sourcekit-lsp csharp-ls kotlin-lsp; do
  command -v $cmd &>/dev/null && echo "$cmd: OK" || echo "$cmd: not installed"
done

# Check Semgrep
semgrep --version
```

---

## How It Works

### The Key Insight

Traditional SAST tools match patterns. This plugin has Claude **read and understand** code — tracing data flows through function calls, understanding algorithm invariants, analyzing object lifecycles, and reasoning about edge cases. This finds the complex, novel vulnerabilities that pattern matching misses.

The approach is inspired by Anthropic's research that found 22 Firefox vulnerabilities in 2 weeks through semantic code reasoning, git history variant analysis, and algorithmic understanding.

### Skills-Primary Architecture

All methodology lives in **skills**. The orchestrator invokes skills as needed based on what it's finding — no rigid pipeline. This means:

- **Continuous context**: Claude builds understanding of the codebase and keeps it throughout the audit, instead of losing it at every agent handoff
- **Adaptive workflow**: If reconnaissance reveals a suspicious module, Claude can deep-dive immediately instead of waiting for "Phase 2"
- **Self-verification**: Findings are verified inline during hunting, with adversarial disproval for high-severity issues
- **Self-improvement**: When a technique works well, it can be captured and encoded into skills for future audits

---

## End-to-End Workflow

### Start an Audit

```
Run a security audit on /path/to/project/source-code
```

The orchestrator's first message is always an intake prompt:

```
I'll plan this security audit. First, I need some information:

REQUIRED:
  - Source code path: where is the target source code?

OPTIONAL (provide any that apply):
  - Working directory: where should audit outputs go? (defaults to parent of source path)
  - Target IP:PORT — live instance for dynamic testing?
  - Credentials — test credentials?
  - Bug bounty rules — paste or URL
  - Report format — paste a custom template
  - Existing threat model — paste or file path

Let me know what applies, or say 'skip' to proceed with defaults.
```

### The Audit Flow

After approval, the orchestrator works through four phases, invoking skills as needed:

```
Phase 1: RECONNAISSANCE
┌─────────────────────────────────────────────────────────┐
│  Orchestrator invokes skills:                            │
│    code-review (routes, sources, sinks)                  │
│    semgrep (secrets scan)                                │
│    variant-analysis (git history + dependency CVEs)       │
│    target-recon (OSINT if public)                        │
│                                                          │
│  Writes: intelligence.md, architecture.md,               │
│          attack-surface.md (with Critical Module Ranking  │
│          and Hunting Hypotheses)                         │
└──────────────────────────┬──────────────────────────────┘
                           ▼
Phase 2: VULNERABILITY HUNTING
┌─────────────────────────────────────────────────────────┐
│  Stage A — Automated Scan (fast, broad):                 │
│    semgrep sweep, detect-injection, detect-auth,         │
│    detect-logic, detect-config                           │
│    → scan-candidates.md                                  │
│                                                          │
│  Stage B — Deep Hypothesis Hunting (THE MAIN EVENT):     │
│    For each high-priority target:                        │
│      deep-dive → semantic analysis                       │
│      verify-finding → inline self-verification           │
│      → VULN-NNN/ with poc/ artifacts                     │
│    Spawns subagents only for parallel independent modules │
└──────────────────────────┬──────────────────────────────┘
                           ▼
Phase 3: FINAL VERIFICATION
┌─────────────────────────────────────────────────────────┐
│  For unverified findings:                                │
│    verify-finding (adversarial disproval for HIGH/CRIT)  │
│    → CONFIRMED / DOWNGRADED / FALSE_POSITIVE verdicts    │
│    → CVSS 3.1 strings, variant expansion                 │
│  Writes: false-positives.md                              │
└──────────────────────────┬──────────────────────────────┘
                           ▼
Phase 4: REPORTING
┌─────────────────────────────────────────────────────────┐
│  write-report skill → report.md                          │
│    Executive summary, findings table, vuln chains,       │
│    remediation roadmap                                   │
│  Custom REPORT.md template supported                     │
└─────────────────────────────────────────────────────────┘
```

### Completion

```
AUDIT COMPLETE
══════════════════════════════════════════
Target:        /path/to/source-code
System Type:   Web API

Results:
  Findings:    8 total
  Confirmed:   5
  False Pos:   3
  By Severity: 1C / 2H / 2M / 0L

Output Files:
  Report:      security_audit/report.md
  Findings:    security_audit/findings/VULN-*/
  Recon:       security_audit/recon/
  FP Log:      security_audit/false-positives.md
══════════════════════════════════════════
```

---

## Standalone Reporting

The reporter works independently — use it to write professional reports for your own findings:

```
Write a report for my finding: I found an SSRF in /api/webhook. The 'url' parameter
is not validated and I can reach the AWS metadata endpoint at 169.254.169.254.
Here's my curl command: curl -X POST ... and the response showed IAM credentials.
```

### Custom Report Templates

Create a `REPORT.md` file in the project root with your desired report structure. The reporter follows this template instead of the built-in default. This works in both pipeline and standalone mode.

---

## Architecture

### Agents (2)

| Agent | Role |
|-------|------|
| **security-orchestrator** | Conducts the entire audit by invoking skills. Builds and maintains deep codebase understanding. Spawns subagents only for parallel deep-dives. |
| **reporter** | Standalone report generation from user-supplied findings. In pipeline mode, the orchestrator writes the report itself via the write-report skill. |

### Skills (13)

| Skill | Type | Purpose |
|-------|------|---------|
| `claude-init` | Setup | Tech fingerprinting, CLAUDE.md generation, workspace creation |
| `code-review` | Reference | Framework-specific route patterns, source/sink taxonomy |
| `semgrep` | Tool | SAST scanning with registry rules and custom taint analysis |
| `target-recon` | OSINT | Gather public intelligence about the target |
| `variant-analysis` | **Recon** | Git history security analysis, dependency CVE scanning, variant pattern search |
| `deep-dive` | **Hunting** | Exhaustive semantic analysis of a single file/module — the core methodology |
| `detect-injection` | Detection | SQLi, CMDi, SSRF, XSS, deserialization, file handling, memory + semantic analysis |
| `detect-auth` | Detection | IDOR/BOLA, BFLA, JWT, session, OAuth, mass assignment + semantic analysis |
| `detect-logic` | Detection | Race conditions, workflow bypass, cache attacks, rate limiting + semantic analysis |
| `detect-config` | Detection | Debug mode, CORS, weak crypto, exposed endpoints, containers + semantic analysis |
| `verify-finding` | **Verification** | Adversarial disproval, CVSS 3.1 calibration, variant expansion |
| `write-report` | **Reporting** | Report methodology, template handling, quality requirements |
| `capture-technique` | **Learning** | Encodes successful techniques into skill files for future audits |

### Quality Requirements

| Phase | Requirements |
|-------|-------------|
| **Recon** | intelligence.md, architecture.md, attack-surface.md each >20 lines; endpoint table has auth column; source→sink matrix; Critical Module Ranking |
| **Hunting** | Every VULN-NNN.md has: file:line, source→sink chain, CVSS string; every poc/ has exploit.py, request.txt, response.txt |
| **Verification** | Every finding has verdict ≠ UNVERIFIED; every non-FP has full CVSS 3.1 string; false-positives.md exists |
| **Reporting** | report.md ≥50 lines; Executive Summary heading; every VULN-NNN referenced; Remediation Roadmap section |

### LSP Integration

The plugin bundles configs for 12 language servers. They activate automatically based on file extensions when the binary is in PATH. Used to:

- Confirm whether vulnerable code paths are reachable (not dead code)
- Check type constraints that prevent exploitation
- Validate PoC scripts for correctness
- Resolve function calls and imports that grep-based analysis misses

Missing LSP binaries are silently skipped — analysis falls back to grep-based patterns.

---

## Workspace Layout

```
project-directory/
├── source-code/                   ← Target (read-only during audit)
├── CLAUDE.md                      ← Generated by claude-init
├── RULES.md                       ← Bug bounty rules (if provided)
├── REPORT.md                      ← Custom report template (if provided)
└── security_audit/
    ├── recon/
    │   ├── intelligence.md        ← Tech stack, CVEs, config issues
    │   ├── architecture.md        ← Endpoints, auth flows, framework protections
    │   ├── attack-surface.md      ← Source→sink matrix, threat model, Critical Module Ranking
    │   ├── variant-analysis.md    ← Git history patterns, dependency CVEs, variant candidates
    │   ├── threat-model-input.md  ← User-provided threat model (if provided)
    │   └── swagger.json           ← OpenAPI spec (REST APIs only)
    ├── findings/
    │   ├── VULN-001/
    │   │   ├── VULN-001.md        ← Writeup: CWE, CVSS, code, chain, verdict, mitigation
    │   │   └── poc/
    │   │       ├── exploit.py     ← Runnable PoC script
    │   │       ├── request.txt    ← Raw HTTP request
    │   │       ├── response.txt   ← Captured response / expected output
    │   │       └── ...            ← Payloads, helpers, screenshots
    │   └── ...
    ├── report.md                  ← Final report
    ├── false-positives.md         ← Rejected findings with reason codes
    └── logs/
        ├── scope_brief.md
        ├── scan-candidates.md     ← Stage A automated scan hits
        ├── semgrep-results.json
        └── learned-techniques.log ← Captured techniques for skill improvement
```

---

## Bug Bounty Integration

Provide bug bounty rules during intake or create `RULES.md` manually:

```markdown
# Bug Bounty Program Rules

## In-Scope Components
- Web application v3.x at app.example.com

## Out of Scope
- Marketing site, mobile apps, third-party integrations

## Qualifying Vulnerabilities
- RCE, SQLi, Auth Bypass, IDOR, SSRF, Stored XSS

## Non-Qualifying Vulnerabilities
- Self-XSS, user enumeration, missing headers without exploit

## Testing Constraints
- No DoS, own test accounts only, redact PII

## Report Requirements
- Affected version required, step-by-step reproduction
```

---

## Tips

- **One command to start** — just tell Claude to run an audit. The orchestrator handles everything.
- **Provide a threat model** — sharing existing security knowledge saves recon time.
- **Custom report templates** — create `REPORT.md` once for your organization and reuse across audits.
- **Large codebases** — the orchestrator writes findings as it goes. Partial results are saved even if context runs out.
- **Focused audits** — ask the orchestrator to focus on specific modules or vulnerability classes.
- **Pre-placed documents** — drop architecture docs, API specs, or prior reports into `security_audit/recon/` before starting.
- **Standalone reports** — use the reporter directly for your own findings without running the full pipeline.
- **Self-improvement** — after a successful audit, the capture-technique skill can encode what worked for future audits.
