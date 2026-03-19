# Pre-Built Taint Rules for Security Auditing

Ready-to-use taint analysis rules. Copy into `${AUDIT_DIR}/logs/semgrep-rules/` and customize sources/sinks for the target framework.

## SQL Injection (Python)

```yaml
rules:
  - id: custom-sqli-taint
    mode: taint
    message: >-
      User input flows to SQL query without parameterization.
      Use parameterized queries instead of string formatting.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-89
      owasp: "A03:2021"
      confidence: HIGH
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
      - pattern: request.form[...]
      - pattern: request.json
      - pattern: request.data
      - pattern: request.values[...]
      - pattern: request.headers.get(...)
      - pattern: request.cookies.get(...)
    pattern-sanitizers:
      - pattern: int($X)
      - pattern: float($X)
      - pattern: bool($X)
    pattern-sinks:
      - pattern: $CURSOR.execute($QUERY)
      - pattern: $CURSOR.executemany($QUERY, ...)
      - pattern: $DB.execute($QUERY)
      - pattern: $ENGINE.execute($QUERY)
```

## Command Injection (Python)

```yaml
rules:
  - id: custom-cmdi-taint
    mode: taint
    message: >-
      User input flows to OS command execution.
      Use subprocess with argument arrays instead of shell=True.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-78
      confidence: HIGH
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
      - pattern: request.json
      - pattern: sys.argv[...]
      - pattern: os.environ.get(...)
    pattern-sanitizers:
      - pattern: shlex.quote($X)
      - pattern: shlex.split($X)
      - pattern: pipes.quote($X)
    pattern-sinks:
      - pattern: os.system($CMD)
      - pattern: os.popen($CMD)
      - pattern: subprocess.call($CMD, shell=True)
      - pattern: subprocess.run($CMD, shell=True)
      - pattern: subprocess.Popen($CMD, shell=True)
      - pattern: commands.getoutput($CMD)
```

## SSRF (Python)

```yaml
rules:
  - id: custom-ssrf-taint
    mode: taint
    message: >-
      User-controlled URL flows to HTTP request.
      Validate URLs against an allowlist before making requests.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-918
      confidence: HIGH
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
      - pattern: request.json
    pattern-sanitizers:
      - pattern: validate_url($X)
    pattern-sinks:
      - pattern: requests.get($URL, ...)
      - pattern: requests.post($URL, ...)
      - pattern: requests.request($METHOD, $URL, ...)
      - pattern: urllib.request.urlopen($URL)
      - pattern: httpx.get($URL, ...)
      - pattern: httpx.AsyncClient().get($URL, ...)
```

## Path Traversal (Python)

```yaml
rules:
  - id: custom-path-traversal-taint
    mode: taint
    message: >-
      User input flows to file system operation without path validation.
      Canonicalize the path and verify it stays within the intended directory.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-22
      confidence: HIGH
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
      - pattern: request.json
    pattern-sanitizers:
      - pattern: os.path.basename($X)
      - pattern: secure_filename($X)
    pattern-sinks:
      - pattern: open($PATH, ...)
      - pattern: pathlib.Path($PATH).read_text()
      - pattern: os.path.join($BASE, $PATH)
      - pattern: send_file($PATH, ...)
      - pattern: send_from_directory($DIR, $PATH)
```

## Deserialization (Python)

```yaml
rules:
  - id: custom-deserialization-taint
    mode: taint
    message: >-
      User input flows to unsafe deserialization.
      Use safe alternatives like json.loads() or yaml.safe_load().
    severity: ERROR
    languages: [python]
    metadata:
      cwe: CWE-502
      confidence: HIGH
    pattern-sources:
      - pattern: request.data
      - pattern: request.get_data()
      - pattern: request.stream.read()
    pattern-sinks:
      - pattern: pickle.loads($X)
      - pattern: pickle.load($X)
      - pattern: yaml.load($X)
      - pattern: yaml.load($X, Loader=yaml.FullLoader)
      - pattern: yaml.load($X, Loader=yaml.UnsafeLoader)
      - pattern: marshal.loads($X)
```

## XSS (JavaScript / TypeScript)

```yaml
rules:
  - id: custom-xss-taint-js
    mode: taint
    message: >-
      User input flows to DOM manipulation without sanitization.
      Use textContent instead of innerHTML, or sanitize with DOMPurify.
    severity: ERROR
    languages: [javascript, typescript]
    metadata:
      cwe: CWE-79
      confidence: HIGH
    pattern-sources:
      - pattern: document.location.search
      - pattern: document.location.hash
      - pattern: window.location.search
      - pattern: req.query.$X
      - pattern: req.body.$X
      - pattern: req.params.$X
    pattern-sanitizers:
      - pattern: DOMPurify.sanitize($X)
      - pattern: escape($X)
      - pattern: encodeURIComponent($X)
    pattern-sinks:
      - pattern: $EL.innerHTML = $X
      - pattern: $EL.outerHTML = $X
      - pattern: document.write($X)
      - pattern: document.writeln($X)
      - pattern: $($SEL).html($X)
      - pattern: res.send($X)
      - pattern: res.write($X)
```

## Adapting Rules for Your Target

To customize for a specific framework:

1. **Replace sources** with the target's actual input functions:
   - Flask: `request.args`, `request.form`, `request.json`
   - Django: `request.GET`, `request.POST`, `request.body`
   - Express: `req.query`, `req.body`, `req.params`
   - Frappe: `frappe.form_dict`, `frappe.request.data`
   - Spring: `@RequestParam`, `@RequestBody`, `@PathVariable`

2. **Replace sinks** with the target's actual dangerous operations:
   - ORM raw queries, custom exec wrappers, template renders

3. **Add sanitizers** for the target's actual validation:
   - Framework-provided escaping, custom validators, type casts

4. **Set `languages`** to match the target

5. **Save to** `${AUDIT_DIR}/logs/semgrep-rules/` and validate:
   ```bash
   semgrep --validate --config ${AUDIT_DIR}/logs/semgrep-rules/
   ```
