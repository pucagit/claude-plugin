---
name: detect-ssrf
description: Detect Server-Side Request Forgery (SSRF) vulnerabilities: user-controlled URL fetch, webhook/callback URL abuse, cloud metadata endpoint access, DNS rebinding bypass, open redirect chaining, and SSRF via file upload or document rendering engines. Use during Phase 3 vulnerability detection.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# SSRF Vulnerability Detection

## Goal
Find all places where user-controlled input reaches an outbound HTTP request or file fetch — enabling access to internal services, cloud metadata endpoints, or arbitrary URLs.

## Sub-Types Covered
- **Direct URL fetch** — User supplies a URL that the server fetches
- **Webhook/callback abuse** — User registers a URL the server calls on events
- **Cloud metadata access** — SSRF to `169.254.169.254` (AWS), `100.100.100.200` (Alibaba), `metadata.google.internal`
- **Internal service pivoting** — SSRF reaching internal APIs, admin panels, DBs
- **DNS rebinding bypass** — Hostname validated once, then resolves to internal IP
- **Open redirect chaining** — Open redirect on same domain used to pivot SSRF filter
- **Protocol smuggling** — `gopher://`, `file://`, `dict://`, `ftp://` in URL parameter
- **SSRF via file upload** — Processing uploaded files that contain URLs (SVG, XML, HTML)
- **SSRF via document rendering** — wkhtmltopdf, Ghostscript, ImageMagick fetching URLs from documents

## Grep Patterns

### Direct URL Fetch (All Languages)
```bash
grep -rn "requests\.get(\|requests\.post(\|requests\.put(\|urllib\.request\.\|urllib\.urlopen(\|httpx\.get(\|httpx\.post(\|fetch(\|axios\.get(\|axios\.post(\|http\.Get(\|http\.Post(\|curl_exec(\|curl_setopt(\|HttpClient\.\|WebClient\.\|HttpURLConnection\|RestTemplate\.\|OkHttpClient\|Faraday\.get(\|Net::HTTP" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" --include="*.cs" \
  ${TARGET_SOURCE}
```

### Webhook / Callback URL Registration
```bash
grep -rn "webhook\|callback_url\|hook_url\|notify_url\|redirect_uri\|return_url\|ping_url\|target_url\|destination_url" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -i "request\.\|req\.\|params\.\|body\.\|form\.\|input"
```

### URL Validation (Check for Weak Allowlists)
```bash
grep -rn "urlparse\|urllib\.parse\|new URL(\|URL\.parse(\|parse_url(\|hostname\|netloc\|startswith.*http\|startswith.*https\|allowlist\|whitelist\|blacklist\|blocklist" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.go" \
  ${TARGET_SOURCE}
```

### PDF / Image Rendering Engines
```bash
grep -rn "wkhtmltopdf\|pdfkit\|weasyprint\|puppeteer\|playwright\|phantomjs\|ImageMagick\|convert.*http\|Ghostscript\|gs.*http\|html2pdf\|pdf.*url\|screenshot.*url" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" \
  ${TARGET_SOURCE}
```

### SVG / XML Processing (Potential SSRF via XXE)
```bash
grep -rn "\.svg\|xml\.etree\|lxml\|ElementTree\|SAXParser\|DocumentBuilder\|simplexml\|Nokogiri::XML\|libxml\|xmllint" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" \
  ${TARGET_SOURCE}
```

## Detection Process

1. Run grep patterns to find all outbound HTTP call sites
2. For each hit, trace backwards: is the URL parameter user-controlled?
   - Direct: `requests.get(request.args.get('url'))` → HIGH
   - Indirect: `requests.get(webhook.url)` where webhook.url comes from user input → HIGH
3. Examine any URL validation present:
   - No validation → HIGH
   - Hostname-only check (`hostname == 'allowed.com'`) → MEDIUM (DNS rebinding)
   - Schema + hostname allowlist → MEDIUM (check for `@`, `#`, path traversal in URL)
   - Blocklist of `127.0.0.1/localhost` → MEDIUM (IPv6 `::1`, decimal, octal bypass)
4. Check if cloud metadata endpoints are accessible from the server's network context
5. For rendering engines (wkhtmltopdf, Ghostscript): check if user-supplied content reaches renderer

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `requests.get(user_url)` with no validation | CRITICAL |
| `requests.get(user_url)` with `if 'internal' not in user_url` blocklist | HIGH — trivial bypass |
| `requests.get(user_url)` with allowlist of approved domains | MEDIUM — check bypass techniques |
| Webhook URL stored in DB, fetched server-side | HIGH — need to trace who can register webhook |
| `wkhtmltopdf` rendering user HTML | HIGH — HTML can contain `<iframe src="http://169.254.169.254/">` |
| URL validated by hostname only | MEDIUM — DNS rebinding bypass |

## SSRF Filter Bypass Techniques

Reference `references/payloads.md` for complete bypass list. Key bypasses:
- `http://127.0.0.1/` → try `http://0.0.0.0/`, `http://[::1]/`, `http://2130706433/` (decimal), `http://017700000001/` (octal)
- `http://169.254.169.254/` → try via DNS rebinding or redirect
- Domain allowlist → try `http://allowed.com@internal.host/` or `http://allowed.com#@internal.host/`

## Reference Files

- [Vulnerable SSRF patterns by language and framework](references/patterns.md)
- [SSRF bypass payloads: IP encoding, protocol smuggling, filter bypasses](references/payloads.md)
- [Exploitation guide: metadata exfiltration, internal service scanning, gopher payloads](references/exploitation.md)
