---
name: claude-init
description: Initialize a security audit workspace interactively. Asks the user for target information one question at a time, then runs a deterministic setup script that installs tools (semgrep, gitnexus), indexes the codebase, and creates the audit workspace. Invoke this BEFORE running the security-orchestrator.
user-invocable: true
---

# Security Audit Initialization

Interactive workspace setup for security audits. This skill drives the conversation — asking questions one at a time — then delegates all deterministic setup to `setup-workspace.sh`.

## CRITICAL FIRST-ACTION RULE

**Your FIRST action is to ask the user questions.** Do NOT run any tools until you have collected the required information. Ask one question at a time.

---

## Step 1: Interactive Intake

Ask these questions **one at a time**, waiting for the user's response before asking the next:

### Question 1 (REQUIRED)
```
Where is the target source code?
(Provide the full path to the source code directory, e.g. /home/user/projects/webapp)
```
**STOP and wait.** Do not proceed until the user provides a path.

### Question 2
```
Where should audit outputs go?
(Default: parent directory of the source code. Press Enter or say "default" to accept.)
```

### Question 3
```
Is there a live target instance for dynamic testing?
  a) Yes — I'll provide IP:PORT
  b) No — static analysis only
```
If yes, ask for `IP:PORT` (e.g., `192.168.1.50:8080`).

### Question 4 (only if live target exists)
```
Do you have test credentials for the live target?
  a) Yes — I'll provide them (format: user:pass)
  b) No credentials
```

### Question 5
```
Do you have any of these? (skip any that don't apply)
  a) Bug bounty rules file (path to rules document)
  b) Custom report template (path to template file)
  c) Existing threat model (path or paste)
  d) None of the above
```

---

## Step 2: Run Setup Script

Once all information is collected, construct the command and run the setup script:

```bash
SCRIPT_DIR="$(dirname "$(readlink -f "$0")" 2>/dev/null || echo "SKILL_DIR")"
# The script is co-located with this skill file
bash SKILL_DIR/setup-workspace.sh \
  --source <SOURCE_PATH> \
  --project-dir <PROJECT_DIR> \
  [--ip <IP>] \
  [--port <PORT>] \
  [--creds <USER:PASS>] \
  [--rules <RULES_FILE>] \
  [--report-template <TEMPLATE_FILE>] \
  [--threat-model <THREAT_MODEL_FILE>]
```

The script path is: the same directory as this SKILL.md file. Find it with:
```bash
# The setup script is at:
# skills/claude-init/setup-workspace.sh (relative to plugin root)
```

When invoking, use the absolute path based on the plugin location.

**IMPORTANT**: The script outputs JSON to stdout. Parse the JSON to verify success and extract key information.

---

## Step 3: Verify Setup

After the script completes, verify:

```bash
[ -f "${PROJECT_DIR}/CLAUDE.md" ] && echo "CLAUDE.md OK" || echo "CLAUDE.md MISSING"
[ -d "${AUDIT_DIR}/recon" ] && echo "recon/ OK" || echo "recon/ MISSING"
[ -d "${AUDIT_DIR}/findings" ] && echo "findings/ OK" || echo "findings/ MISSING"
[ -d "${AUDIT_DIR}/logs" ] && echo "logs/ OK" || echo "logs/ MISSING"
[ -f "${PROJECT_DIR}/.mcp.json" ] && echo ".mcp.json OK" || echo ".mcp.json MISSING"
```

If any are missing, report the error to the user.

---

## Step 4: Display Summary

Parse the JSON output from the script and present:

```
SECURITY AUDIT WORKSPACE INITIALIZED
═══════════════════════════════════════════
Source:      {source}
Project:     {project_dir}
Language:    {detected_language}
Frameworks:  {detected_frameworks}
Type:        {classified_type}
Files:       {total_files}
Live Target: {target_ip}:{target_port} or N/A
Semgrep:     {semgrep_version}
GitNexus:    {gitnexus_status} (index: {gitnexus_index})
Workspace:   {audit_dir}

Next Steps:
  0. /setup-target: (Optional) Invoke this skill to set up a live target for testing
  1. Prompt: "Run a full security audit using the security-research plugin"
  2. The orchestrator will present an audit plan for your approval
═══════════════════════════════════════════
```

---

## Error Handling

| Condition | Action |
|---|---|
| Source path doesn't exist | Script exits with error JSON — show to user, ask for correct path |
| Workspace already exists | Ask user: overwrite or resume? If resume, skip setup-workspace.sh |
| semgrep install fails | Warn user, continue (manual analysis only) |
| gitnexus install fails | Warn user, continue (grep-based tracing instead of graph queries) |
| gitnexus indexing fails | Warn user, continue (MCP server configured but may not work) |
| Live target unreachable | Warn, continue with static analysis only |

---

## Supporting Files

- [setup-workspace.sh](setup-workspace.sh) — Deterministic setup script (installs tools, creates workspace, generates CLAUDE.md)
- [claude-md-template.md](claude-md-template.md) — CLAUDE.md template with audit rules and standards
- [priority-focus.md](priority-focus.md) — Vulnerability priority by system type
