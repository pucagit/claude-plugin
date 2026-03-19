---
name: target-recon
description: Gather open-source intelligence about a target project by searching official documentation, GitHub repositories, API references, deployment guides, and public security advisories. Use during Phase 1 reconnaissance to build project understanding before source code analysis. Outputs a structured web_intelligence.md file to the audit workspace.
argument-hint: "<target_name> [official_url_or_github] [audit_dir]"
---

# Target Web Intelligence Gathering

Gather OSINT for: `$ARGUMENTS`

Parse the arguments:
- **TARGET_NAME**: first token (e.g., `frappe`, `keycloak`, `zabbix`)
- **TARGET_URL**: second token if provided — official site or GitHub URL (e.g., `https://frappeframework.com` or `https://github.com/frappe/frappe`)
- **AUDIT_DIR**: third token if provided — write output there; otherwise write to `./recon/web_intelligence.md`

Output file: `{AUDIT_DIR}/recon/web_intelligence.md`

---

## Step 1: Locate Official Resources

Search for the project's canonical sources:

```
WebSearch: "{TARGET_NAME} official documentation site"
WebSearch: "{TARGET_NAME} github repository"
WebSearch: "{TARGET_NAME} architecture overview"
```

From the results, identify and record:
- Official documentation URL
- GitHub repository URL (owner/repo)
- Primary language and framework
- Project type (web app, library, platform, auth service, etc.)

---

## Step 2: Fetch GitHub Intelligence

If a GitHub repo is found (`https://github.com/{owner}/{repo}`), fetch these in order:

| URL | Purpose |
|---|---|
| `https://raw.githubusercontent.com/{owner}/{repo}/main/README.md` | Project overview, setup, key features |
| `https://raw.githubusercontent.com/{owner}/{repo}/main/SECURITY.md` | Security policy, reporting contacts, supported versions |
| `https://raw.githubusercontent.com/{owner}/{repo}/main/CHANGELOG.md` (or `CHANGES.md`, `HISTORY.md`) | Recent changes, security fixes |
| `https://api.github.com/repos/{owner}/{repo}/releases?per_page=5` | Latest releases and release notes |
| `https://github.com/{owner}/{repo}/security/advisories` | Published security advisories (fetch page) |

Also search:
```
WebSearch: "site:github.com/{owner}/{repo} security advisory"
WebSearch: "{TARGET_NAME} CVE site:cve.mitre.org OR site:nvd.nist.gov"
WebSearch: "{TARGET_NAME} vulnerability disclosed site:hackerone.com OR site:bugcrowd.com"
```

Extract from GitHub results:
- Architecture description from README
- Supported/maintained versions (for scope validation)
- Any experimental/preview features (may be out of scope)
- Recent security fixes in CHANGELOG
- Contributor security contacts

---

## Step 3: Fetch Architecture & Design Documentation

Search and fetch the most relevant architecture docs:

```
WebSearch: "{TARGET_NAME} architecture documentation"
WebSearch: "{TARGET_NAME} system design components"
WebSearch: "{TARGET_NAME} technical overview how it works"
```

Fetch the top 2–3 most relevant pages. Extract:
- Component diagram or description (what modules/services exist)
- Request lifecycle (how a request flows through the system)
- Data storage model (what databases, caches, queues are used)
- Inter-service communication patterns
- Plugin/extension architecture (if any)

---

## Step 4: Fetch API Documentation

```
WebSearch: "{TARGET_NAME} REST API documentation"
WebSearch: "{TARGET_NAME} API reference endpoints"
WebSearch: "{TARGET_NAME} OpenAPI swagger spec"
```

Fetch the top result. Extract:
- Authentication methods (API keys, OAuth, JWT, sessions)
- Base URL patterns
- Notable endpoint categories (admin, user, public)
- Rate limiting information
- API versioning scheme
- Any publicly documented sensitive endpoints

---

## Step 5: Fetch Deployment & Configuration Documentation

```
WebSearch: "{TARGET_NAME} deployment guide installation"
WebSearch: "{TARGET_NAME} configuration reference security settings"
WebSearch: "{TARGET_NAME} production hardening"
```

Fetch top 1–2 results. Extract:
- Default credentials or setup patterns
- Required/optional environment variables with security impact
- Exposed ports and services
- Security-relevant default settings (debug flags, CORS, TLS, headers)
- Common misconfiguration warnings from official docs
- Docker/Kubernetes deployment patterns (attack surface from container config)

---

## Step 6: Fetch Authentication & Authorization Documentation

```
WebSearch: "{TARGET_NAME} authentication authorization documentation"
WebSearch: "{TARGET_NAME} user roles permissions"
WebSearch: "{TARGET_NAME} SSO OAuth SAML integration"
```

Fetch top 1–2 results. Extract:
- Auth mechanisms supported (session, token, OAuth, SAML, etc.)
- Role/permission model (RBAC, ABAC, custom)
- Privilege levels and what each can do
- Known auth bypass concerns from official docs
- Multi-tenancy isolation model (if applicable)

---

## Step 7: Fetch Known Vulnerabilities & Public Disclosures

```
WebSearch: "{TARGET_NAME} CVE security vulnerability 2023 2024 2025"
WebSearch: "{TARGET_NAME} security advisory patch"
WebSearch: "{TARGET_NAME} bug bounty report disclosed"
```

Fetch top CVE or advisory pages. Extract:
- CVE IDs with CVSS scores and affected versions
- Vulnerability classes that have historically affected this project
- Patch commits (useful for locating the vulnerable code patterns)
- Any recurring vulnerability classes (e.g., "Frappe has had multiple SSTI issues")

---

## Step 8: Write Output

Write `{AUDIT_DIR}/recon/web_intelligence.md` with this structure:

```markdown
# Web Intelligence: {TARGET_NAME}

> Generated from open-source research. All claims cite their source URL.

## Project Overview

- **Type**: [web app / auth service / framework / platform / etc.]
- **Language**: [primary language(s)]
- **GitHub**: [url]
- **Official Docs**: [url]
- **License**: [license]
- **Latest Stable Version**: [version] (released [date])
- **Actively Maintained**: [yes/no — basis for assessment]

## Architecture Summary

[Component description: what the major modules/services are and how they relate.
Describe the request lifecycle if documented.]

| Component | Role | Notes |
|---|---|---|
| [component] | [what it does] | [security notes] |

## API Surface

- **Auth mechanism**: [how APIs are authenticated]
- **Base path**: [e.g., `/api/v1/`]
- **Notable endpoint categories**: [admin, public, webhooks, etc.]
- **OpenAPI/Swagger available**: [yes/no + URL if yes]
- **Rate limiting**: [present/absent/unknown]

## Deployment & Configuration

| Setting | Default | Security Impact |
|---|---|---|
| [env var / config key] | [default value] | [what happens if misconfigured] |

**Default credentials**: [any defaults noted in docs — CRITICAL if exists]
**Debug flags**: [any debug/dev mode settings with security implications]
**Exposed services**: [ports, admin interfaces]

## Authentication & Authorization Model

- **Auth type**: [session / JWT / API key / OAuth / etc.]
- **Role model**: [RBAC / ABAC / custom]
- **Privilege levels**: [list with what each can do]
- **Multi-tenancy**: [how tenant isolation works, if applicable]
- **Notable auth behaviors**: [anything unusual or security-relevant]

## Known Vulnerabilities

| CVE | Severity | Affected Versions | Vuln Class | Patched |
|---|---|---|---|---|
| [CVE-XXXX-XXXXX] | [HIGH] | [≤ X.Y.Z] | [SSTI / SQLi / etc.] | [yes/no] |

**Recurring vulnerability classes**: [patterns that appear multiple times in history]

**Public disclosures**: [any notable bug bounty reports or advisories]

## Security-Relevant Observations

[Anything from the documentation that stands out as security-relevant:
- Features that handle user-controlled templates, file uploads, webhooks, etc.
- Admin interfaces or debug endpoints
- Experimental features that may have weaker security guarantees
- Integration points with external systems]

## Sources

| Source | URL | Retrieved |
|---|---|---|
| Official Docs | [url] | [today's date] |
| GitHub README | [url] | [today's date] |
| CVE Reference | [url] | [today's date] |
```

Confirm: "Wrote web_intelligence.md ({N} lines). Key findings: {2–3 line summary of most important security-relevant facts}."
