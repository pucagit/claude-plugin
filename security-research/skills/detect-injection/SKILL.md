---
name: detect-injection
description: Detect injection vulnerabilities in source code: SQLi, NoSQLi, CMDi, path traversal, SSTI, LDAP, XPath, header injection, HTTP request smuggling, and cache poisoning. Use during Phase 3 vulnerability detection to systematically find and trace injection sinks to user-controlled sources.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Injection Vulnerability Detection

## Goal
Find all places where user-controlled data reaches an injection sink without adequate sanitization or parameterization.

## Sub-Types Covered
- **SQLi** — String concatenation or f-string in SQL queries
- **NoSQLi** — MongoDB `$ne`/`$gt`/`$where` operator injection via JSON body
- **OS CMDi** — `os.system()`, `subprocess.call(shell=True)`, `exec()`, `popen()` with user input
- **Argument injection** — Unsafe subprocess array where user controls an argument that changes command behavior
- **Path traversal** — `../` sequences in file path operations
- **Arbitrary file read/write** — `open()`, `fs.readFile()`, `File()` with user-controlled path
- **SSTI** — `render_template_string()`, `Template(input).render()`, SpEL/OGNL expression evaluation
- **LDAP injection** — User input in LDAP filter strings without escaping
- **XPath injection** — User input in XPath query strings
- **Header injection (CRLF)** — `\r\n` in HTTP header values or redirect URLs
- **Log injection** — Newline in log output allowing log forging
- **SMTP injection** — User input in email headers (To/CC/Subject) without sanitization
- **GraphQL injection** — Dynamic query construction with user input
- **SSRF via protocol smuggling** — `gopher://`, `file://`, `dict://` in URL parameters
- **Prototype pollution → RCE** — `Object.assign({}, userInput)` or `merge(obj, userInput)` in Node.js
- **HTTP request smuggling** — Conflicting `Content-Length` / `Transfer-Encoding` headers
- **Cache poisoning** — User-controlled cache key or unkeyed header influencing cached response

## Grep Patterns

### SQL Injection
```bash
grep -rn "cursor\.execute\|\.raw(\|RawSQL(\|db\.query(\|sequelize\.query(\|createNativeQuery\|Statement\.execute\|mysqli_query\|PDO::query\|db\.Exec\|db\.Query\|\.execute(f\"\|\.execute(\".*%\|\.execute(\".*+\|\.execute(\".*format\|\.execute(\".*{" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" --include="*.cs" \
  ${TARGET_SOURCE}
```

### NoSQL Injection (MongoDB)
```bash
grep -rn "\$ne\|\$gt\|\$where\|\$regex\|find({.*req\.\|findOne({.*req\.\|aggregate(\[.*req\." \
  --include="*.js" --include="*.ts" --include="*.py" \
  ${TARGET_SOURCE}
```

### OS Command Injection
```bash
grep -rn "os\.system(\|subprocess\.call(\|subprocess\.run(\|subprocess\.Popen(\|popen(\|exec(\|system(\|shell_exec(\|Runtime\.exec(\|ProcessBuilder(\|child_process\|exec\.Command(\|os\.StartProcess(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Path Traversal / File Operations
```bash
grep -rn "open(\|os\.path\.join(\|send_file(\|render file:\|fs\.readFile(\|fs\.createReadStream(\|new File(\|FileInputStream(\|file_get_contents(\|include(\|require(\|os\.Open(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|vendor\|node_modules"
```

### SSTI (Server-Side Template Injection)
```bash
grep -rn "render_template_string(\|Template(\|\.render(\|Jinja2.*input\|ejs\.render(\|\.template(\|nunjucks\.renderString(\|pebble\.process(\|Velocity\.evaluate(\|freemarker\.template\|ThymeleafTemplateEngine" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  ${TARGET_SOURCE}
```

### Header / CRLF Injection
```bash
grep -rn "header(\|redirect(\|Location:\|set-cookie.*request\.\|response\.setHeader\|HttpServletResponse.*header\|w\.Header()" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Prototype Pollution (Node.js)
```bash
grep -rn "Object\.assign(\|merge(\|extend(\|defaultsDeep(\|_\.merge(\|deepmerge(" \
  --include="*.js" --include="*.ts" \
  ${TARGET_SOURCE} | grep -v "test\|spec"
```

### HTTP Request Smuggling
```bash
grep -rn "Transfer-Encoding\|Content-Length\|chunked\|keep-alive" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" \
  ${TARGET_SOURCE} | grep -i "header\|request\|proxy"
```

## Detection Process

For each grep hit:
1. **Read the handler** at the identified `file:line`
2. **Trace backwards**: Where does the variable come from? Is it from `request.args`, `req.body`, `$_GET`, `request.params`, or similar user-controlled source?
3. **Check sanitization between source and sink**: Is input escaped? Parameterized? Validated against an allowlist?
4. **Check `recon/architecture/framework_protections.md`**: Does the ORM, framework, or middleware already sanitize this?
5. **Test bypass potential**: If sanitization exists, can it be circumvented? (e.g., second-order SQLi, encoding bypass)
6. **Verdict**: Real finding if user-controlled input reaches sink without effective sanitization. False positive if parameterized/ORM-protected throughout.

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `cursor.execute(f"SELECT ... {user_input}")` | HIGH — direct f-string SQLi |
| `cursor.execute("SELECT ... %s", (user_input,))` | FALSE POSITIVE — parameterized |
| `cursor.execute("SELECT ... " + user_input)` | HIGH — string concat SQLi |
| `db.raw(user_input)` | HIGH — raw SQL bypass |
| `os.system(f"cmd {user_input}")` | HIGH — direct CMDi |
| `subprocess.run(["cmd", user_input], shell=False)` | Depends — check if arg changes behavior |
| `subprocess.run(f"cmd {user_input}", shell=True)` | HIGH — shell=True CMDi |
| `open(os.path.join(base, user_path))` | MEDIUM — check for path normalization |
| `Template(user_input).render()` | HIGH — SSTI |
| `render_template("fixed.html", var=user_input)` | FALSE POSITIVE — variable in template, not template source |
| `Object.assign({}, JSON.parse(body))` | MEDIUM — prototype pollution check |

## Reference Files

- [Vulnerable code patterns by language](references/patterns.md)
- [Attack payloads and bypass techniques](references/payloads.md)
- [Exploitation step-by-step guide](references/exploitation.md)
