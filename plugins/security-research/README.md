# Security Research Plugin for Claude Code

A modular offensive security research framework. Claude performs semantic code analysis — reading and understanding code deeply — to find vulnerabilities that pattern matching misses. Each skill is independently invocable, giving you full control over the audit workflow.

Inspired by Anthropic's research that found 500+ zero-day vulnerabilities through semantic code reasoning, git history variant analysis, and algorithmic understanding.

## Setup

### 1. Add marketplace and install the plugin
Open Claude Code and type in:

```bash
/plugin marketplace add https://github.com/pucagit/claude-plugin.git
/plugin install security-research@pucaplugin
/reload-plugins
```

### 2. Install LSP servers (install only what you need)

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
```

> **Note:** Semgrep and gitnexus are installed automatically during workspace initialization (`/security-research:claude-init`). No manual setup required.

---

## How It Works

### The Key Insight

Traditional SAST tools match patterns. This plugin has Claude **read and understand** code — tracing data flows through function calls, understanding algorithm invariants, analyzing object lifecycles, and reasoning about edge cases. This finds the complex, novel vulnerabilities that pattern matching misses.

### Modular Architecture

The workflow is split into independent, user-invoked skills. **You drive the workflow** — choosing what to run and when. This is more reliable than a monolithic orchestrator and matches how security professionals actually work.

---

## Quick Start

### Step 1: Initialize the workspace

```
/security-research:claude-init
```

The init skill asks you questions one at a time:
- Where is the source code? (required)
- Where should outputs go?
- Is there a live target?
- Do you have credentials?
- Any bug bounty rules, report templates, or threat models?

It then runs a setup script that:
- Detects the tech stack
- Installs semgrep (if missing)
- Installs gitnexus and indexes the codebase for source-to-sink flow queries
- Creates the audit workspace
- Generates CLAUDE.md with audit rules and target info

### Step 1.5 (Optional): Set up a live testing environment

```
/security-research:setup-target
```

Creates a Docker Compose environment from the target source code — using existing Dockerfiles, public Docker images, or building from source. Seeds test accounts at each privilege level and sample data for IDOR testing. Auto-updates CLAUDE.md with live target info.

You can also pass custom configs: `/security-research:setup-target` with "debug mode enabled, weak CORS, no CSRF" to test specific attack surfaces.

This step is optional — the orchestrator works with static analysis alone. But having a live target enables PoC execution during verification.

### Step 2: Run the security audit

```
Run a full security audit using the security-research plugin
```

The orchestrator reads the workspace created by claude-init, presents an audit plan for your approval, then executes three phases:

```
Phase 1: RECONNAISSANCE
┌──────────────────────────────────────────────────────────┐
│  code-review (routes, sources, sinks)                     │
│  semgrep (secrets scan)                                   │
│  variant-analysis (git history + dependency CVEs)          │
│  target-recon (OSINT + PoC-in-GitHub lookups)             │
│  gitnexus (source-to-sink flow mapping)                   │
│  Algorithm inventory, state machine extraction,            │
│  git variant seeding, PoC cross-reference                 │
│                                                           │
│  → intelligence.md, architecture.md, attack-surface.md    │
│    (with Critical Module Ranking + Hunting Hypotheses)    │
└────────────────────────┬──────────────────────────────────┘
                         ▼
Phase 2: VULNERABILITY HUNTING
┌──────────────────────────────────────────────────────────┐
│  Stage A — Automated Scan (fast, broad):                  │
│    semgrep sweep, detect-injection, detect-auth,          │
│    detect-logic, detect-config                            │
│    → scan-candidates.md                                   │
│                                                           │
│  Stage B — Deep Hypothesis Hunting (THE MAIN EVENT):      │
│    For each high-priority target:                         │
│      deep-dive → semantic analysis                        │
│      verify-finding → inline self-verification            │
│      → VULN-NNN/ with poc/ artifacts                      │
│    Spawns subagents only for parallel independent modules  │
└────────────────────────┬──────────────────────────────────┘
                         ▼
Phase 3: FINAL VERIFICATION
┌──────────────────────────────────────────────────────────┐
│  For unverified findings:                                 │
│    verify-finding (adversarial disproval for HIGH/CRIT)   │
│    → CONFIRMED / DOWNGRADED / FALSE_POSITIVE verdicts     │
│    → CVSS 3.1 strings, variant expansion                  │
│  → false-positives.md                                     │
└──────────────────────────────────────────────────────────┘
```

### Step 3: Post-audit actions (as needed)

After the orchestrator completes, you have several options:

#### Spin up a testing environment (if not done in Step 1.5)
```
/security-research:setup-target
```
Creates a Docker Compose environment from the source code to test theoretical findings. Supports custom security configs (debug mode, weak CORS, specific DB versions) for targeted testing. Auto-updates CLAUDE.md so verify-finding can execute PoCs immediately.

#### Re-verify findings or execute PoCs against a live target
```
/security-research:verify-finding
```
Re-verifies specific findings with adversarial disproval. If a live target is configured (via setup-target or manually), **actually executes the PoC script**, captures output, checks reproducibility, and updates the finding with execution evidence.

#### Generate a report
```
/security-research:write-report
```
Or use the **reporter agent** directly for standalone report generation from your own findings:
```
Write a report for my finding: I found an SSRF in /api/webhook...
```

#### Run another audit pass
```
/security-research:iterative-audit
```
Reads all previous findings, attack surfaces, and a coverage tracker to identify what was missed. Generates new hunting hypotheses from unexplored modules, untested hypotheses, variant expansion, and new techniques. Presents a focused plan for your approval, then hunts the gaps. Tracks coverage across runs and recommends when to stop.

#### Capture a successful technique
```
/security-research:capture-technique
```
When you find a great vulnerability through a novel approach, capture it for future audits. The technique is stored in the specific detection skill's `references/cool_techniques.md` file (e.g., injection techniques go to `detect-injection/references/cool_techniques.md`). Each skill reads its own techniques before hunting.

---

## Full Workflow Diagram

```
┌─────────────────────────────────────────────────────────┐
│  YOU: /security-research:claude-init                     │
│  → Interactive questions → setup-workspace.sh            │
│  → Workspace ready, tools installed, codebase indexed    │
└────────────────────────┬────────────────────────────────┘
                         ▼
              ┌─────────────────────┐
              │  (OPTIONAL)          │
              │  setup-target        │
              │  → Docker Compose    │
              │  → Live target ready │
              └──────────┬──────────┘
                         ▼
┌─────────────────────────────────────────────────────────┐
│  YOU: /security-research:security-orchestrator           │
│  → Phase 1: Recon (enhanced with gitnexus + PoC lookup) │
│  → Phase 2: Hunting (detect-* + deep-dive)              │
│  → Phase 3: Verification (adversarial disproval)         │
│  → Summary + next steps                                  │
└────────────────────────┬────────────────────────────────┘
                         ▼
   ┌─────────────┬───────┼───────┬──────────────┐
   ▼             ▼       ▼       ▼              ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│ setup- │ │verify- │ │ write- │ │iterate │ │capture │
│ target │ │finding │ │ report │ │ audit  │ │  tech  │
│        │ │        │ │        │ │        │ │        │
│ Spin up│ │Execute │ │Report  │ │Another │ │Save    │
│ target │ │PoCs    │ │        │ │pass    │ │what    │
│        │ │        │ │        │ │        │ │worked  │
└────────┘ └────────┘ └────────┘ └────────┘ └────────┘
```

---

## Architecture

### Agents (2)

| Agent | Role |
|-------|------|
| **security-orchestrator** | Conducts the audit (Phases 1-3) by invoking skills. Builds and maintains deep codebase understanding. Reads workspace from claude-init. |
| **reporter** | Standalone report generation from user-supplied findings. |

### Skills (15)

| Skill | User-Invocable | Purpose |
|-------|:-:|---------|
| `claude-init` | **Yes** | Interactive workspace setup — asks questions, runs setup script, installs tools, indexes codebase |
| `setup-target` | **Yes** | Docker Compose testing environment — builds from source/public images, seeds test data, auto-configures CLAUDE.md |
| `code-review` | No | Framework-specific route patterns, source/sink taxonomy, LSP-enhanced endpoint mapping |
| `semgrep` | No | SAST scanning with registry rules and custom taint analysis |
| `target-recon` | No | OSINT gathering + PoC-in-GitHub database lookup for known CVE exploits |
| `variant-analysis` | No | Git history security analysis, dependency CVE scanning, variant pattern search |
| `deep-dive` | No | Exhaustive semantic analysis of a single file/module — LSP-enhanced, the core methodology |
| `detect-injection` | No | SQLi, CMDi, SSRF, XSS, deserialization, file handling, memory + LSP + semantic analysis |
| `detect-auth` | No | IDOR/BOLA, BFLA, JWT, session, OAuth, mass assignment + LSP + semantic analysis |
| `detect-logic` | No | Race conditions, workflow bypass, cache attacks, rate limiting + LSP + semantic analysis |
| `detect-config` | No | Debug mode, CORS, weak crypto, exposed endpoints, containers + LSP + semantic analysis |
| `verify-finding` | **Yes** | Adversarial disproval, CVSS 3.1 calibration, **PoC execution against live targets**, variant expansion |
| `write-report` | No | Report methodology, template handling, quality requirements (used by reporter agent) |
| `capture-technique` | **Yes** | Stores successful techniques in per-skill `references/cool_techniques.md` for future audits |
| `iterative-audit` | **Yes** | Stateful multi-pass auditing with coverage tracking across runs |

### Scripts (3)

| Script | Location | Purpose |
|--------|----------|---------|
| `setup-workspace.sh` | `skills/claude-init/` | Deterministic workspace setup — tech detection, tool installation, gitnexus indexing, CLAUDE.md generation |
| `lookup-poc.sh` | `skills/target-recon/` | PoC-in-GitHub database lookup — clones/updates repo, finds CVE PoCs, sorts by GitHub stars |
| `deploy-target.sh` | `skills/setup-target/` | Docker Compose lifecycle — build, start, health check, seed, extract access info, cleanup |

### Quality Requirements

| Phase | Requirements |
|-------|-------------|
| **Recon** | intelligence.md, architecture.md, attack-surface.md each >20 lines; endpoint table has auth column; source→sink matrix; Critical Module Ranking; Algorithm Inventory |
| **Hunting** | Every VULN-NNN.md has: file:line, source→sink chain, CVSS string; every poc/ has exploit.py, request.txt, response.txt |
| **Verification** | Every finding has verdict ≠ UNVERIFIED; every non-FP has full CVSS 3.1 string; false-positives.md exists |

### LSP Integration

The plugin bundles configs for 12 language servers in `plugin.json`. They activate automatically based on file extensions when the binary is in PATH. Used across skills for:

- **Code-review**: Find all references to auth decorators, discover endpoints missing auth
- **Detection skills**: Confirm type constraints, trace call hierarchies for sinks, validate custom sanitizers
- **Deep-dive**: Go-to-definition for every function call, build call trees, check types at each data flow step
- **Verify-finding**: `mcp__ide__getDiagnostics` to confirm reachability, type constraints, PoC correctness

Missing LSP binaries are silently skipped — analysis falls back to grep-based patterns.

### Code Intelligence (gitnexus)

[gitnexus](https://github.com/abhigyanpatwari/GitNexus) is installed during `claude-init` and configured as an MCP server. It provides graph-powered code intelligence:

- **Source-to-sink mapping**: Query all data flows from external inputs to dangerous operations
- **Call graphs**: Trace function calls across files and modules
- **Symbol references**: Find all usages of a function, variable, or type
- Particularly valuable for cross-module flows that grep-based analysis misses

### PoC-in-GitHub Database

The `lookup-poc.sh` script integrates with [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) — a database of 8,500+ CVEs with links to GitHub PoC repositories. During target-recon:

1. For each dependency CVE found, the script looks up available PoCs
2. Results are sorted by GitHub stars (most popular/reliable first)
3. Claude fetches the top PoC repositories and reads their READMEs
4. Assesses applicability to the target (version match, config requirements)
5. Documents findings in `web_intelligence.md`

The database is auto-cloned on first use (`~/cve/PoC-in-GitHub`) and updated via `git pull` on each lookup.

---

## Workspace Layout

```
project-directory/
├── source-code/                   ← Target (read-only during audit)
├── CLAUDE.md                      ← Generated by claude-init
├── .mcp.json                      ← gitnexus MCP server config
├── RULES.md                       ← Bug bounty rules (if provided)
├── REPORT.md                      ← Custom report template (if provided)
└── security_audit/
    ├── recon/
    │   ├── intelligence.md        ← Tech stack, CVEs, PoC availability, config issues
    │   ├── architecture.md        ← Endpoints, auth flows, framework protections, state machines
    │   ├── attack-surface.md      ← Source→sink matrix, algorithm inventory, Critical Module Ranking
    │   ├── web_intelligence.md    ← OSINT findings + enriched CVE/PoC data
    │   ├── variant-analysis.md    ← Git history patterns, dependency CVEs, variant candidates
    │   ├── coverage-tracker.md    ← Iterative audit coverage tracking (created by iterative-audit)
    │   ├── threat-model-input.md  ← User-provided threat model (if provided)
    │   └── swagger.json           ← OpenAPI spec (REST APIs only)
    ├── findings/
    │   ├── VULN-001/
    │   │   ├── VULN-001.md        ← Writeup: CWE, CVSS, code, chain, verdict, mitigation
    │   │   └── poc/
    │   │       ├── exploit.py     ← Runnable PoC script
    │   │       ├── request.txt    ← Raw HTTP request
    │   │       ├── response.txt   ← Captured response / expected output
    │   │       ├── execution-output.txt  ← Actual PoC execution output (if executed)
    │   │       └── ...            ← Payloads, helpers, screenshots
    │   └── ...
    ├── target-env/                ← Docker testing environment (created by setup-target)
    │   ├── Dockerfile             ← Generated or copied from source
    │   ├── docker-compose.yml     ← App + services (DB, cache, queue)
    │   ├── .env                   ← Environment vars, credentials, custom configs
    │   └── seed.sh                ← Database seeding script
    ├── false-positives.md         ← Rejected findings with reason codes
    └── logs/
        ├── orchestrator.log       ← Initialization log
        ├── scope_brief.md         ← Scope constraints from RULES.md
        ├── scan-candidates.md     ← Stage A automated scan hits
        ├── semgrep-results.json   ← Semgrep output
        ├── poc-execution.log      ← PoC execution history (if verify-finding executed PoCs)
        └── learned-techniques.log ← Captured techniques for skill improvement
```

---

## Bug Bounty Integration

Provide bug bounty rules during `claude-init` or create `RULES.md` manually:

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

- **Two commands to start** — `claude-init` sets up the workspace, `security-orchestrator` runs the audit. That's it.
- **Provide a threat model** — sharing existing security knowledge during init saves recon time.
- **Custom report templates** — create `REPORT.md` once for your organization and reuse across audits.
- **Large codebases** — the orchestrator writes findings as it goes. Partial results are saved even if context runs out.
- **Focused audits** — ask the orchestrator to focus on specific modules or vulnerability classes.
- **Pre-placed documents** — drop architecture docs, API specs, or prior reports into `security_audit/recon/` before starting.
- **Iterate** — run `iterative-audit` after the initial pass. Not every vulnerability is found in one run. The coverage tracker shows what's been explored and what hasn't.
- **Capture what works** — after a great find, run `capture-technique` to save the methodology for future audits. Techniques accumulate in each skill's references folder.
- **PoC execution** — if you have a live target, `verify-finding` will actually run your PoC scripts and capture output. Safety checks prevent destructive operations.
- **Standalone reports** — use the reporter agent directly for your own findings without running the full audit.
