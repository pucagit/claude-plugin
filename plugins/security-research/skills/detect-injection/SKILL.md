---
name: detect-injection
description: Detect all input-to-sink vulnerabilities — SQLi, NoSQLi, CMDi, path traversal, SSTI, SSRF, XSS, deserialization/XXE, file handling, and memory corruption (C/C++ only). Consolidated detection skill covering all cases where user-controlled data reaches a dangerous operation.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Input-to-Sink Vulnerability Detection

## Goal
Find all places where user-controlled data reaches a dangerous sink without adequate sanitization, parameterization, or validation.

## Coverage

| Category | Sub-Types |
|---|---|
| **SQL/NoSQL Injection** | SQLi (string concat, f-string, raw queries), NoSQLi ($ne/$gt/$where), GraphQL injection |
| **Command Injection** | OS CMDi (system/exec/popen), argument injection, SSTI (template injection), LDAP/XPath injection |
| **Path/File** | Path traversal, arbitrary file read/write, zip slip, unrestricted file upload, MIME bypass, ImageMagick/Ghostscript RCE, temp file race, symlink attack |
| **SSRF** | Direct URL fetch, webhook/callback abuse, cloud metadata (169.254.169.254), DNS rebinding, protocol smuggling (gopher/file/dict), rendering engine SSRF (wkhtmltopdf, puppeteer) |
| **XSS** | Stored, reflected, DOM-based, template auto-escape bypass (|safe, {!!), unsafe markdown, client-side template injection, dangerouslySetInnerHTML, v-html |
| **Deserialization/XXE** | Python pickle/yaml.load, Java ObjectInputStream, .NET BinaryFormatter, PHP unserialize, Ruby Marshal, Node serialize, XXE via DTD, XStream, JSON TypeNameHandling |
| **Header/Protocol** | CRLF injection, log injection, SMTP injection, HTTP request smuggling, cache poisoning, prototype pollution |
| **Memory** | Buffer overflow, use-after-free, double free, format string, integer overflow, OOB access (C/C++/unsafe Rust only) |

## Grep Patterns

### SQL Injection
```bash
grep -rn "cursor\.execute\|\.raw(\|RawSQL(\|db\.query(\|sequelize\.query(\|createNativeQuery\|Statement\.execute\|mysqli_query\|PDO::query\|db\.Exec\|db\.Query\|\.execute(f\"\|\.execute(\".*%\|\.execute(\".*+\|\.execute(\".*format\|\.execute(\".*{" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" --include="*.cs" \
  ${TARGET_SOURCE}
```

### NoSQL Injection
```bash
grep -rn "\$ne\|\$gt\|\$where\|\$regex\|find({.*req\.\|findOne({.*req\.\|aggregate(\[.*req\." \
  --include="*.js" --include="*.ts" --include="*.py" ${TARGET_SOURCE}
```

### OS Command Injection
```bash
grep -rn "os\.system(\|subprocess\.call(\|subprocess\.run(\|subprocess\.Popen(\|popen(\|exec(\|system(\|shell_exec(\|Runtime\.exec(\|ProcessBuilder(\|child_process\|exec\.Command(\|os\.StartProcess(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" ${TARGET_SOURCE}
```

### Path Traversal / File Operations
```bash
grep -rn "open(\|os\.path\.join(\|send_file(\|fs\.readFile(\|fs\.createReadStream(\|new File(\|FileInputStream(\|file_get_contents(\|os\.Open(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|vendor\|node_modules"
```

### SSTI
```bash
grep -rn "render_template_string(\|Template(\|\.render(\|Jinja2.*input\|ejs\.render(\|nunjucks\.renderString(\|Velocity\.evaluate(\|freemarker\.template\|ThymeleafTemplateEngine" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" ${TARGET_SOURCE}
```

### SSRF — URL Fetch
```bash
grep -rn "requests\.get(\|requests\.post(\|urllib\.request\.\|urllib\.urlopen(\|httpx\.get(\|fetch(\|axios\.get(\|http\.Get(\|curl_exec(\|HttpClient\.\|WebClient\.\|RestTemplate\.\|OkHttpClient\|Faraday\.get(\|Net::HTTP" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" --include="*.cs" ${TARGET_SOURCE}
```

### SSRF — Webhooks / Callbacks
```bash
grep -rn "webhook\|callback_url\|hook_url\|notify_url\|redirect_uri\|return_url\|target_url\|destination_url" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -i "request\.\|req\.\|params\.\|body\.\|form\."
```

### SSRF — Rendering Engines
```bash
grep -rn "wkhtmltopdf\|pdfkit\|weasyprint\|puppeteer\|playwright\|phantomjs\|html2pdf\|pdf.*url\|screenshot.*url" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.php" ${TARGET_SOURCE}
```

### XSS — Template Escape Bypass (Server-Side)
```bash
grep -rn "| safe\|{% autoescape off\|{!! \|raw(\|unescape(\|mark_safe(\|Markup(\|SafeString" \
  --include="*.html" --include="*.j2" --include="*.jinja" --include="*.twig" \
  --include="*.blade.php" --include="*.py" ${TARGET_SOURCE}
```

### XSS — DOM Sinks (Client-Side)
```bash
grep -rn "innerHTML\|outerHTML\|document\.write(\|insertAdjacentHTML\|\.html(\|eval(\|location\.href\s*=" \
  --include="*.js" --include="*.ts" --include="*.html" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|node_modules"
```

### XSS — Framework Unsafe Rendering
```bash
grep -rn "dangerouslySetInnerHTML\|v-html=\|ng-bind-html\|bypassSecurityTrustHtml\|trustAsHtml" \
  --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" --include="*.vue" ${TARGET_SOURCE}
```

### Deserialization — Python/Ruby
```bash
grep -rn "pickle\.loads(\|pickle\.load(\|yaml\.load(\|marshal\.loads(\|shelve\.open(\|Marshal\.load(\|YAML\.load(" \
  --include="*.py" --include="*.rb" ${TARGET_SOURCE}
```

### Deserialization — Java/.NET
```bash
grep -rn "ObjectInputStream\|readObject()\|XMLDecoder\|XStream\|BinaryFormatter\|SoapFormatter\|NetDataContractSerializer\|TypeNameHandling" \
  --include="*.java" --include="*.cs" ${TARGET_SOURCE}
```

### XXE — XML Parsers
```bash
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLReader\|lxml\.etree\|xml\.etree\|simplexml_load\|Nokogiri::XML\|DOMParser\|XMLInputFactory" \
  --include="*.java" --include="*.py" --include="*.php" --include="*.rb" --include="*.cs" ${TARGET_SOURCE}
```

### File Upload
```bash
grep -rn "request\.FILES\|request\.files\|file\.save(\|upload\.\|uploaded_file\|multipart\|IFormFile\|MultipartFile" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" --include="*.cs" ${TARGET_SOURCE}
```

### Archive Extraction (Zip Slip)
```bash
grep -rn "zipfile\.extractall\|zipfile\.extract\|tarfile\.extractall\|ZipFile(\|TarFile(\|shutil\.unpack_archive\|ZipArchive\|ZipEntry" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" ${TARGET_SOURCE}
```

### Header / CRLF Injection
```bash
grep -rn "header(\|redirect(\|Location:\|response\.setHeader\|w\.Header()" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.go" ${TARGET_SOURCE}
```

### Prototype Pollution (Node.js)
```bash
grep -rn "Object\.assign(\|merge(\|extend(\|defaultsDeep(\|_\.merge(\|deepmerge(" \
  --include="*.js" --include="*.ts" ${TARGET_SOURCE} | grep -v "test\|spec"
```

### Memory Corruption (C/C++ only — skip if not applicable)
```bash
grep -rn "strcpy(\|strcat(\|gets(\|sprintf(\|vsprintf(" --include="*.c" --include="*.cpp" --include="*.h" ${TARGET_SOURCE}
grep -rn "printf(\|fprintf(\|syslog(" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
grep -rn "\bfree(\b\|delete \b" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
grep -rn "unsafe {" --include="*.rs" ${TARGET_SOURCE}
```

## Detection Process

For each grep hit:
1. **Read the handler** at the identified `file:line`
2. **Trace backwards**: Where does the variable come from? Is it user-controlled (`request.args`, `req.body`, `$_GET`, etc.)?
3. **Check sanitization**: Is input escaped, parameterized, validated against allowlist between source and sink?
4. **Check `recon/architecture.md` Section 3 (Framework Protections)**: Does the ORM/framework already mitigate this?
5. **Test bypass potential**: If sanitization exists, can it be circumvented?
6. **Verdict**: Real if user input reaches sink without effective protection

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `cursor.execute(f"SELECT ... {user_input}")` | HIGH — f-string SQLi |
| `cursor.execute("SELECT ... %s", (user_input,))` | FALSE POSITIVE — parameterized |
| `os.system(f"cmd {user_input}")` | HIGH — CMDi |
| `subprocess.run(["cmd", user_input], shell=False)` | MEDIUM — check arg behavior |
| `Template(user_input).render()` | HIGH — SSTI |
| `render_template("fixed.html", var=user_input)` | FALSE POSITIVE |
| `requests.get(user_url)` no validation | CRITICAL — SSRF |
| `requests.get(user_url)` weak blocklist | HIGH — SSRF bypass |
| `{{ user_input \| safe }}` in Jinja2 | HIGH — XSS |
| `dangerouslySetInnerHTML={{ __html: userInput }}` | HIGH — XSS |
| `element.innerHTML = location.hash` | CRITICAL — DOM XSS |
| `element.textContent = user_input` | FALSE POSITIVE |
| `pickle.loads(user_input)` | CRITICAL — RCE |
| `yaml.safe_load(data)` | FALSE POSITIVE |
| `ObjectInputStream` with commons-collections | CRITICAL — RCE |
| `zipfile.extractall(dest)` no path check | CRITICAL — zip slip |
| `tarfile.extractall(filter='data')` | FALSE POSITIVE |
| SVG upload served same-origin | HIGH — stored XSS |
| `wkhtmltopdf` rendering user HTML | HIGH — SSRF |
| `strcpy(fixed_buf, user_str)` | CRITICAL — buffer overflow |
| `printf(user_format)` | HIGH — format string |
| `free(ptr); *ptr = val` | HIGH — UAF |
| `Object.assign({}, JSON.parse(body))` | MEDIUM — prototype pollution |

## Beyond Pattern Matching — Semantic Analysis

The grep patterns above catch known vulnerability shapes. After completing the pattern scan,
perform semantic analysis on the code you've read:

1. **For each handler/endpoint**: Read the full function. Ask: "What security assumption
   does this code make? Can that assumption be violated?"

2. **For custom abstractions**: If the codebase has custom sanitization functions, query builders,
   ORM extensions, or input processing utilities — read their implementations. Are they correct?
   Do they handle edge cases (null, empty, unicode, concurrent calls)?

3. **Cross-module flows**: If a variable passes through 3+ functions before reaching a sink,
   follow it through every hop. One missed encoding step in the middle = vulnerability.

4. **Injection-specific deep analysis**:
   - **Custom query builders**: Any function that constructs SQL, NoSQL, or LDAP queries from parts — read the implementation. Does it parameterize correctly for all input types (arrays, nested objects, nulls)?
   - **ORM extensions**: Raw query methods, custom managers, query annotations — these bypass ORM protections. Find every `.raw()`, `.extra()`, `RawSQL()` call.
   - **Middleware mutations**: Does middleware modify `request.body` or `request.params` before the handler runs? A sanitizer on the handler is useless if middleware decoded the payload first.
   - **Second-order injection**: Data stored safely but retrieved and used unsafely later. Trace database writes → reads → sinks. The write may be parameterized, but if the read's output is concatenated into a query elsewhere, that's injection.
   - **Template engine context**: Even with auto-escaping, check what's passed as template context. If user input becomes a template variable name (not value), auto-escaping doesn't help.

## Reference Files

- [Vulnerable code patterns by category](references/patterns.md)
- [Attack payloads and bypass techniques](references/payloads.md)
- [Exploitation step-by-step guide](references/exploitation.md)
