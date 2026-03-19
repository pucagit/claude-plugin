---
name: claude-init
description:  Initialize a security audit workspace for a target codebase. Provides templates and reference data used by the security-orchestrator during plan mode (CLAUDE.md template, priority focus by system type). Can also be invoked standalone to set up a workspace manually without running the full orchestrator.
argument-hint: "<target_source_path> [--ip HOST] [--port PORT] [--creds user:pass]"
---

# Security Audit Initialization

Initialize a full security audit workspace for the target at `$ARGUMENTS`.

Parse the arguments: the first positional argument is the target source path. Optional flags:
- `--ip` or second positional: live target IP/hostname
- `--port` or third positional: live target port
- `--creds`: authentication credentials (user:pass format)

## Step 1: Validate Target

```bash
ls -la $0
```

Verify:
- The path exists and is a directory with source files
- Estimate codebase size with `find $0 -type f | wc -l`
- Identify the primary language(s) by file extension counts

If the target is invalid, tell the user and stop.

## Step 2: Technology Fingerprint

Identify by examining actual files:

- **Languages**: Count files by extension (`*.py`, `*.js`, `*.go`, `*.java`, `*.php`, `*.rb`, `*.rs`, `*.c`)
- **Frameworks**: Check for `package.json`, `pom.xml`, `requirements.txt`, `go.mod`, `Cargo.toml`, `composer.json`, `Gemfile`
- **Build system**: Check for `Makefile`, `Dockerfile`, `docker-compose.yml`
- **Config files**: Check for `.env`, `config.*`, `settings.*`, `application.yml`

Read the primary manifest file (e.g., `package.json`, `requirements.txt`) to get exact versions.

## Step 3: Install Semgrep

```bash
source /home/kali/.venv/bin/activate
if ! command -v semgrep &> /dev/null; then
    pip3 install semgrep
fi
semgrep --version
```

## Step 4: Create Audit Workspace

Create the folder structure. Replace `TARGET` with the actual target path:

```bash
TARGET="$0"
AUDIT="${TARGET}/security_audit"
mkdir -p "${AUDIT}"/{recon,findings,logs}
```

## Step 5: Generate CLAUDE.md

Generate `${TARGET}/CLAUDE.md` using the [claude-md-template.md](claude-md-template.md) as a base. Fill in:

- `{target_source}` → actual target path
- `{target_ip}`, `{target_port}`, `{credentials}` → from arguments or "N/A"
- `{detected_language}` → from fingerprinting
- `{detected_framework}` → from fingerprinting
- `{classified_type}` → system classification (see below)
- `{priority_section}` → from [priority-focus.md](priority-focus.md) based on system type

### System Classification

Classify based on what you found:

| Indicators | Classification |
|---|---|
| Admin panels, user management, CRUD dashboards | Management System |
| REST/GraphQL endpoints, token auth, versioned routes | Web API |
| Login flows, OAuth/OIDC, session management | Auth Service |
| Upload handlers, parsers, converters | File Processing |
| CMS features, content rendering, templates | CMS |
| C/C++/Rust, pointer arithmetic, buffer ops | Native Application |
| Multiple services, docker-compose, gRPC | Microservice |

## Step 6: Write Initialization Log

Write to `${AUDIT}/logs/orchestrator.log`:

```
[TIMESTAMP] INIT: Security audit initialized
[TIMESTAMP] TARGET: {path}
[TIMESTAMP] LIVE_TARGET: {ip}:{port} or N/A
[TIMESTAMP] DETECTED: Language={lang}, Framework={framework}, Type={type}
[TIMESTAMP] WORKSPACE: {audit_path}
[TIMESTAMP] SEMGREP: {version}
[TIMESTAMP] STATUS: Ready for Stage 1 (Reconnaissance)
```

## Step 7: Display Summary

Print a clear summary:

```
SECURITY AUDIT INITIALIZED
═══════════════════════════
Target:     {path}
Language:   {lang}
Framework:  {framework}
Type:       {classification}
Live:       {ip}:{port} or N/A
Workspace:  {audit_path}
Semgrep:    {version}

Priority Focus:
  1. {top vuln class}
  2. {second vuln class}
  3. {third vuln class}

Next:
- Plan the audit — "Plan a security audit" (REQUIRED before execution)
- The orchestrator will ask for scope, rules, report format, and other details before starting
```

## Error Handling

- Target path doesn't exist → clear error, stop
- Target is empty → warn user, allow override
- Workspace already exists → ask: overwrite or resume?
- Live target unreachable → warn, continue static-only
- Language undetectable → ask user to specify
- Semgrep install fails → warn, continue without (manual analysis only)

## Supporting Files

- [claude-md-template.md](claude-md-template.md) — CLAUDE.md template with all rules and standards
- [priority-focus.md](priority-focus.md) — vulnerability priority by system type
