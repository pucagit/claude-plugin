# Security Research Plugin for Claude Code

A structured offensive security audit framework that coordinates specialized AI agents through a complete vulnerability research lifecycle — from planning through verified findings with production-grade reports.

## Setup

### 1. Install the plugin
Open Claude Code and type in:

```bash
/plugin marketplace add https://github.com/pucagit/claude-plugin.git
```

### 2. Install Semgrep (required)

Semgrep is the SAST engine used across all phases. The orchestrator will attempt to install it automatically, but pre-installing is recommended:

```bash
pip install semgrep
```

### 3. Install LSP servers (install only what you need)

The plugin bundles configs for 12 language servers. LSP servers provide type analysis that agents use to reduce false positives, confirm code reachability, and validate PoC scripts. **You only need to install the ones matching your target's language.**

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

LSP servers activate automatically when the plugin detects files matching their configured extensions. Missing binaries are silently skipped — agents fall back to grep-based analysis.

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

## End-to-End Workflow

### Step 1: Plan the audit

```
Run a security audit on /path/to/target-source
```

The **Security Orchestrator** takes over. It starts in **plan mode** and will:

1. **Ask for required info:**
   - Source code path (required — will validate it exists)

2. **Ask for optional info (all at once):**

   | Input | What happens |
   |-------|--------------|
   | **Target IP:PORT** | Enables live testing and dynamic PoC verification |
   | **Credentials** | Enables authenticated testing |
   | **Bug bounty rules** | Paste program rules → orchestrator writes `RULES.md` |
   | **Report format** | Paste template → orchestrator writes `REPORT.md` |
   | **Existing threat model** | Paste or provide path → saved for the recon agent |

3. **Automatically initialize the workspace:**
   - Validate the target path and estimate codebase size
   - Fingerprint the tech stack (languages, frameworks, dependencies)
   - Classify the system type (Web API, Auth Service, CMS, etc.)
   - Install Semgrep if needed
   - Create `security_audit/` directory structure
   - Generate `CLAUDE.md` configuration
   - Write `RULES.md`, `REPORT.md`, `threat-model-input.md` from your inputs

4. **Present an audit plan** showing target summary, focus areas, scope constraints

5. **Wait for your approval** before executing

### Step 2: Execute the audit

After you approve the plan, the orchestrator runs all 4 phases automatically:

1. **Phase 1: Reconnaissance** — `recon-agent` maps the codebase, endpoints, auth flows, attack surface
2. **Phase 2: Vulnerability Hunting** — `vuln-hunter` finds vulnerabilities and writes PoC exploits
3. **Phase 3: Verification** — `verifier` eliminates false positives and calibrates severity
4. **Phase 4: Reporting** — `reporter` generates the final report (following `REPORT.md` if provided)

You can also run phases individually after planning:

```
# Phase 1 only
Run recon on /path/to/target-source

# Phase 2 only
Hunt for vulnerabilities in /path/to/target-source

# Phase 3 only
Verify the findings in /path/to/target-source/security_audit

# Phase 4 only
Generate a report from /path/to/target-source/security_audit
```

### Step 3: Review results

```
project-root/
├── CLAUDE.md                      # Generated during plan mode
├── RULES.md                       # Bug bounty rules (if provided)
├── REPORT.md                      # Custom report template (if provided)
└── security_audit/
    ├── recon/
    │   ├── intelligence.md        # System overview, tech stack, config issues
    │   ├── architecture.md        # Endpoints, auth flows, framework protections
    │   ├── attack-surface.md      # Source-sink matrix, threat model, top risks
    │   ├── threat-model-input.md  # User-provided threat model (if provided)
    │   └── swagger.json           # OpenAPI spec (REST APIs only)
    ├── findings/
    │   ├── VULN-001/
    │   │   ├── VULN-001.md        # Finding writeup
    │   │   └── poc/
    │   │       ├── exploit.py     # Runnable PoC script
    │   │       ├── request.txt    # Raw HTTP request
    │   │       ├── response.txt   # Captured response / evidence
    │   │       └── ...            # Payloads, helpers, screenshots
    │   ├── VULN-002/
    │   │   ├── VULN-002.md
    │   │   └── poc/
    │   └── ...
    ├── report.md                  # Final report (follows REPORT.md template if provided)
    ├── false-positives.md         # Ruled-out candidates with reasoning
    └── logs/
        ├── orchestrator.log
        ├── scope_brief.md
        └── semgrep-results.json
```

Each `findings/VULN-NNN/` directory contains:
- **`VULN-NNN.md`** — Finding writeup with vulnerability description, CWE, exact vulnerable code with `file:line`, source-to-sink chain, framework protection analysis, impact, verification notes, and mitigation
- **`poc/exploit.py`** — Complete, runnable PoC script with usage instructions
- **`poc/request.txt`** — Raw HTTP request that triggers the vulnerability
- **`poc/response.txt`** — Captured response proving exploitation
- **`poc/[artifacts]`** — Any additional files: malicious payloads, helper scripts, screenshots

---

## Standalone Reporting

The reporter agent works independently — you don't need to run the full pipeline. Use it to write professional reports for your own findings:

```
Write a report for my finding: I found an SSRF in /api/webhook. The 'url' parameter
is not validated and I can reach the AWS metadata endpoint at 169.254.169.254.
Here's my curl command: curl -X POST ... and the response showed IAM credentials.
```

The reporter will:
1. Structure your finding into the standard format (`findings/VULN-NNN/`)
2. Create PoC artifacts from your evidence (`poc/exploit.py`, `request.txt`, `response.txt`)
3. Check for `REPORT.md` in the project directory for custom formatting
4. Generate a professional `report.md`

### Custom Report Templates

Create a `REPORT.md` file in the project root with your desired report structure. The reporter follows this template instead of the built-in default. This works in both pipeline and standalone mode.

If no `REPORT.md` exists, the reporter uses its built-in template with executive summary, findings table, vulnerability chains, remediation roadmap, and appendices.

---

## Architecture

### Agents (5)

| Agent | Phase | Role | Outputs |
|-------|-------|------|---------|
| **security-orchestrator** | Plan + All | Collects inputs, initializes workspace, writes CLAUDE/RULES/REPORT.md, coordinates all phases | `CLAUDE.md`, `RULES.md`, `REPORT.md`, `logs/orchestrator.log` |
| **recon-agent** | 1 | Reconnaissance + deep code architecture review | `recon/intelligence.md`, `recon/architecture.md`, `recon/attack-surface.md` |
| **vuln-hunter** | 2 | Finds vulnerabilities AND writes PoC exploits | `findings/VULN-NNN/` directories |
| **verifier** | 3 | Eliminates false positives, calibrates severity | Updates findings, writes `false-positives.md` |
| **reporter** | 4 / Standalone | Generates reports from pipeline or user-supplied findings | `report.md` |

### Skills (8)

| Skill | Type | Used By | Purpose |
|-------|------|---------|---------|
| `claude-init` | Setup | orchestrator | Tech fingerprinting templates, CLAUDE.md generation, priority focus |
| `code-review` | Reference | recon-agent | Framework-specific route patterns, source/sink taxonomy |
| `semgrep` | Tool | recon-agent, vuln-hunter | SAST scanning with registry rules and custom taint analysis |
| `target-recon` | OSINT | recon-agent | Gather public intelligence about the target |
| `detect-injection` | Detection | vuln-hunter | SQLi, CMDi, SSRF, XSS, deserialization, file handling, memory |
| `detect-auth` | Detection | vuln-hunter | IDOR/BOLA, BFLA, JWT, session, OAuth, mass assignment |
| `detect-logic` | Detection | vuln-hunter | Race conditions, workflow bypass, cache attacks, rate limiting |
| `detect-config` | Detection | vuln-hunter | Debug mode, CORS, weak crypto, exposed endpoints, containers |

### LSP Integration

The plugin bundles configs for 12 language servers (Python, TypeScript/JS, Go, C/C++, Rust, Java, Ruby, PHP, Kotlin, C#, Lua, Swift). They activate automatically based on file extensions when the binary is in PATH. Agents use `mcp__ide__getDiagnostics` to:

- Confirm whether vulnerable code paths are reachable (not dead code)
- Check type constraints that prevent exploitation (e.g., `int` params can't be injected)
- Validate PoC scripts for correctness before marking them ready
- Resolve function calls and imports that grep-based analysis misses

Missing LSP binaries are silently skipped — agents fall back to grep-based analysis with no errors.

---

## Audit Workflow Diagram

```
PLAN (mandatory — includes workspace initialization)
┌──────────────────────────────────────────────────────────────┐
│  security-orchestrator (plan mode)                           │
│                                                              │
│  Ask:   source path, IP:PORT, creds, rules, format, model    │
│  Init:  validate target, fingerprint tech, install semgrep   │
│  Write: CLAUDE.md, RULES.md, REPORT.md, threat-model-input   │
│  Show:  audit plan with target classification                │
│  Gate:  user approval required                               │
└──────────────────────────┬───────────────────────────────────┘
                           ▼
Phase 1: RECON                       Phase 2: HUNT
┌─────────────────────────┐           ┌────────────────────────┐
│  recon-agent            │           │  vuln-hunter           │
│                         │           │                        │
│  Read threat model input│           │  Read recon artifacts  │
│  Tech fingerprint       ├──────────►│  Run Semgrep           │
│  Map endpoints          │           │  4 detect-* skills     │
│  Trace auth flows       │           │  Write PoC per finding │
│  Catalog protections    │           │  Analyze chains        │
│  Build attack surface   │           │                        │
│                         │           │  ► VULN-NNN/ dirs      │
│  ► intelligence.md      │           │    with poc/ artifacts │
│  ► architecture.md      │           │                        │
│  ► attack-surface.md    │           │                        │
└─────────────────────────┘           └────────────────────────┘
                                               │
                                               ▼
Phase 4: REPORT                      Phase 3: VERIFY
┌─────────────────────────┐           ┌────────────────────────┐
│  reporter               │           │  verifier              │
│                         │           │                        │
│  Read REPORT.md template│           │  Re-read source code   │
│  Read confirmed findings│ ◄─────────│  Trace chains indep.   │
│  Executive summary      │           │  Check protections     │
│  Technical details      │           │  Validate PoCs (LSP)   │
│  Remediation roadmap    │           │  Calibrate severity    │
│                         │           │                        │
│  ► report.md            │           │  ► Update findings     │
│                         │           │  ► false-positives.md  │
└─────────────────────────┘           └────────────────────────┘
```

---

## Bug Bounty Integration

Provide bug bounty rules during the **plan mode** intake when the orchestrator asks. Paste the program rules directly — the orchestrator structures them into `RULES.md`.

Alternatively, create `RULES.md` manually before running the audit:

```markdown
# Bug Bounty Program Rules

## In-Scope Components
- Web application v3.x at app.example.com
- REST API at api.example.com/v2/

## Out of Scope
- Marketing site, mobile apps, third-party integrations

## Qualifying Vulnerabilities
- RCE, SQLi, Auth Bypass, IDOR, SSRF, Stored XSS

## Non-Qualifying Vulnerabilities
- Self-XSS, user enumeration, missing headers without exploit

## Testing Constraints
- No DoS, own test accounts only, redact PII

## Report Requirements
- Affected version required
- Step-by-step reproduction
- Video/screenshots demonstrating exploitation
```

The orchestrator detects existing `RULES.md` during plan mode and asks whether to use it as-is or update it.

---

## Tips

- **One command to start** — just tell Claude to an audit. The orchestrator handles everything: workspace setup, tech fingerprinting, Semgrep installation, CLAUDE.md generation, and plan presentation.

- **Provide a threat model** — if you have existing security knowledge about the target, sharing it during plan mode saves significant recon time.

- **Custom report templates** — create `REPORT.md` once for your organization and reuse it across audits.

- **Large codebases** — agents use write-as-you-go protocol. Partial results are saved even if context runs out. The orchestrator retries failed phases up to 2 times.

- **Focused audits** — after planning, run individual phases:
  ```
  Use the vuln-hunter to check /path/to/specific/module for SSRF vulnerabilities
  ```

- **Pre-placed documents** — drop architecture docs, API specs, or prior reports into `security_audit/recon/` before Phase 1. The recon-agent reads them first.

- **Standalone reports** — use the reporter directly for your own findings without running the full pipeline.
