---
name: code-review
description: Reference guide for Phase 2 source code security review. Provides framework-specific route and auth annotation patterns, input source taxonomy, and sink catalog with grep commands for building source-to-sink chains. Use during endpoint mapping, auth gap analysis, and attack surface construction.
argument-hint: "<routes|sources|sinks>"
---

# Code Review Reference Guide

Parse `$ARGUMENTS` to determine mode: `routes`, `sources`, or `sinks`.

---

## LSP Integration

Use LSP to enhance code review accuracy:

- **Find references**: For auth decorators/middleware, find ALL usages to discover endpoints missing auth
- **Go-to-definition**: For custom auth functions, verify they actually enforce the check
- **Call hierarchy**: For route handlers, build the call tree to understand what sinks they reach
- **Workspace symbols**: Find all controller/handler classes to ensure complete endpoint inventory

## Mode: `routes`

Find all route declarations and map auth decorators alongside each one.

**Route + auth annotation table:**

| Framework | Route patterns | Auth / access-control patterns |
|---|---|---|
| Flask | `@app.route(`, `@bp.route(`, `add_url_rule(` | `@login_required`, `@jwt_required`, custom decorators before handler |
| FastAPI | `@app.get(`, `@router.post(`, `add_api_route(` | `Depends(get_current_user)`, `Security(`, `HTTPBearer` |
| Django/DRF | `path(` / `re_path(` in `urls.py`; `@api_view(`; `ViewSet` | `@login_required`, `IsAuthenticated`, `permission_classes` |
| Frappe | `@frappe.whitelist(` | `allow_guest=True` → unauthenticated; absence = session required |
| Express | `app.get(`, `router.post(`, `router.use(` | middleware chain before handler; `passport.`, `express-jwt` |
| NestJS | `@Controller(`, `@Get(`, `@Post(` | `@UseGuards(`, `@Roles(`, `@Public(` (marks unauth endpoints) |
| Spring Boot | `@GetMapping`, `@PostMapping`, `@RequestMapping`, `@RestController` | `@PreAuthorize(`, `@Secured(`, `@PermitAll`, `@AllowAnonymous` |
| Rails | `routes.rb`: `resources :`, `get '`, `namespace`, `scope` | `before_action :authenticate_user!`, Pundit / CanCanCan policy calls |
| Laravel | `Route::get(`, `Route::resource(`, `Route::apiResource(` | `->middleware('auth')`, `$this->middleware(`, `Gate::allows(` |
| ASP.NET Core | `[HttpGet]`, `[HttpPost]`, `app.MapGet(`, `[ApiController]` | `[Authorize]`, `[AllowAnonymous]`, `[Authorize(Roles=` |
| Go (Gin/Chi) | `r.GET(`, `r.POST(`, `r.Group(`, `http.HandleFunc(` | auth middleware passed to `r.Use(` or `r.Group(` |
| GraphQL | `@Query(`, `@Mutation(`, resolver map entries | field-level auth middleware; missing resolver guard = unauth field |

**Bootstrap grep** (adapt to framework(s) detected in recon):

```bash
grep -rn "@app\.route\|@router\.\|@api_view\|@frappe\.whitelist\|@GetMapping\|@PostMapping\|Route::\|r\.GET\|r\.POST\|@Controller\|app\.MapGet\|http\.HandleFunc" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" --include="*.cs" \
  ${TARGET_SOURCE} | head -300
```

For each route found: record URL pattern, HTTP method, handler `file:line`, middleware chain, and whether an auth decorator is present or absent.

---

## Mode: `sources`

Catalog every place external data enters the application.

**Input source taxonomy:**

- **HTTP direct**: query params (`request.args`, `req.query`, `$_GET`), path params, request body (`request.json`, `req.body`, `$_POST`), form data, multipart / file uploads, cookies, HTTP request headers (including custom headers like `X-Forwarded-For`, `X-Real-IP`)
- **WebSocket / SSE**: message payloads, event data, connection parameters, channel subscriptions
- **Indirect / async**: message queue payloads (Celery tasks, RabbitMQ consumers, Kafka consumers, SQS handlers), webhook / OAuth / SAML callbacks, scheduled job arguments, DB query results re-used in program logic without re-validation, external API responses used without schema validation

---

## Mode: `sinks`

Grep for dangerous operations and catalog them as sink candidates for chain construction.

### Table A — Python / JS/TS / Java / PHP / Go

| Sink | Python | JS/TS | Java | PHP | Go |
|---|---|---|---|---|---|
| **SQLi** | `cursor.execute(`, `.raw(`, `RawSQL(` | `db.query(`, `sequelize.query(` | `createQuery(`, `Statement.execute(` | `mysqli_query(`, `PDO::query(` | `db.Exec(` / `db.Query(` + `%s` or `+` |
| **OS cmd** | `os.system(`, `subprocess.`, `popen(` | `exec(`, `spawn(`, `child_process` | `Runtime.exec(`, `ProcessBuilder(` | `system(`, `shell_exec(` | `exec.Command(` |
| **File ops** | `open(`, `send_file(`, `os.path.join(` + user input | `fs.readFile(`, `path.join(` + user input | `new File(`, `FileInputStream(` | `file_get_contents(`, `include(` | `os.Open(` |
| **SSRF** | `requests.get(`, `urllib.`, `httpx.` | `fetch(`, `axios.`, `http.request(` | `new URL(`, `HttpClient` | `curl_exec(` | `http.Get(`, `http.Post(` |
| **SSTI** | `render_template_string(`, `Template(s).render(` | `ejs.render(`, `_.template(` | Velocity / Freemarker template string | `Twig::render(` | `template.Execute(` |
| **Deserial** | `pickle.loads(`, `yaml.load(` (not safe_load) | `node-serialize` | `ObjectInputStream(`, `XStream` | `unserialize(` | `gob.Decode(` untrusted |
| **XXE** | `lxml.etree.parse(`, `xml.etree.` | `libxmljs`, `DOMParser` | `DocumentBuilderFactory`, `SAXParser` | `simplexml_load_string(` | `encoding/xml` untrusted |
| **Open redirect** | `redirect(` + user param | `res.redirect(`, `window.location` | `sendRedirect(` | `header('Location:` | `http.Redirect(` |
| **Code eval** | `eval(`, `exec(` | `eval(`, `Function(`, `vm.runInContext(` | reflection + user input | `eval(`, `preg_replace('/e'` | dynamic plugin load |

**Bootstrap grep — Table A:**

```bash
grep -rn "cursor\.execute\|os\.system\|subprocess\.\|pickle\.loads\|yaml\.load\|requests\.get\|render_template_string\|unserialize\|shell_exec\|Runtime\.exec\|ProcessBuilder\|ObjectInputStream\|child_process\|eval(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.php" \
  ${TARGET_SOURCE}
```

---

### Table B — Ruby / C# / C/C++ / Rust

| Sink | Ruby | C# (.NET) | C/C++ | Rust |
|---|---|---|---|---|
| **SQLi** | `.where("#{user}")`, `find_by_sql(`, `connection.execute(` | `SqlCommand(` + concat, `FromSqlRaw(`, `ExecuteSqlRaw(` | `sqlite3_exec(`, `mysql_query(` + `sprintf` | `sqlx::query(` + `format!()`, `diesel::sql_query(` |
| **OS cmd** | `system(`, `exec(`, `` `cmd` ``, `%x{cmd}`, `IO.popen(` | `Process.Start(`, `ProcessStartInfo(` | `system(`, `popen(`, `exec(`, `execve(`, `ShellExecute(` | `Command::new(` + user input |
| **File ops** | `File.open(`, `IO.read(`, `send_file(`, `render file:` | `File.ReadAllText(`, `File.Open(`, `Path.Combine(` + user input | `fopen(`, `open(`, path via `sprintf(` | `fs::File::open(` + user input |
| **SSRF** | `Net::HTTP.get(`, `open(url)` (open-uri), `RestClient.get(`, `Faraday.get(` | `HttpClient.GetAsync(`, `WebClient.DownloadString(`, `WebRequest.Create(` | `curl_easy_perform(`, custom socket code with user URL | `reqwest::get(`, `hyper::Client` + user URL |
| **SSTI** | `ERB.new(str).result(`, `Liquid::Template.parse(` | Razor view injection, `Engine.Razor.RunCompile(` | template lib-specific | `tera::Tera::one_off(` + user input |
| **Deserial** | `Marshal.load(`, `YAML.load(` (not safe_load) | `BinaryFormatter.Deserialize(`, `JsonConvert.DeserializeObject(` with `TypeNameHandling` | custom binary parsers, protobuf without validation | `serde` from_str on dynamic/untrusted type |
| **XXE** | `Nokogiri::XML(` without options, `REXML::Document.new(` | `XmlDocument` without `ProhibitDtd`, `XmlReader` without `DtdProcessing.Prohibit` | `libxml2` / `expat` without entity disabling | `roxmltree` / `quick-xml` with external entity enabled |
| **Open redirect** | `redirect_to(params[:url])` | `Response.Redirect(`, `RedirectToAction(` + user input | framework-specific | `Redirect::to(` + user input |
| **Code eval** | `eval(`, `instance_eval(`, `class_eval(` | `CSharpScript.EvaluateAsync(`, dynamic `Assembly.Load(` | `dlopen(` + user path, `system(` | `unsafe` + raw function pointer from user input |

**Bootstrap grep — Table B:**

```bash
grep -rn "Marshal\.load\|ERB\.new\|Nokogiri::XML\|redirect_to\|SqlCommand\|Process\.Start\|BinaryFormatter\|XmlDocument\|system(\|popen(\|exec(\|gets(\|strcpy(\|strcat(\|sprintf(\|printf(\|dlopen(\|curl_easy\|Command::new" \
  --include="*.rb" --include="*.cs" --include="*.c" --include="*.cpp" --include="*.h" --include="*.rs" \
  ${TARGET_SOURCE}
```

---

### C/C++ — Additional Sink Categories

These sink classes are unique to C/C++ and do not map cleanly to managed languages:

| Sink | Patterns to grep |
|---|---|
| **Buffer overflow** | `strcpy(`, `strcat(`, `gets(`, `scanf("%s"`, `sprintf(buf,` without size limit, `memcpy(` without bounds check |
| **Format string** | `printf(user_input)`, `fprintf(f, user_input)`, `syslog(priority, user_input)` — user input used directly as format argument |
| **Integer overflow → heap** | `malloc(user_size)`, `alloc(n * user_val)` without overflow check before allocation |
| **Use-after-free / double-free** | `free(ptr)` followed by dereference, multiple `free(ptr)` paths on same pointer |

---

### Chain Construction Format

For each sink hit, trace backwards to an input source:

```
Source: file:line (param_name)
  → [transformation 1: file:line]
  → [sanitization? YES/NO — what check, file:line]
  → Sink: file:line (dangerous operation)
Viability: HIGH / MEDIUM / LOW
Auth required: none / user / admin
```

- **HIGH**: user-reachable, no sanitization between source and sink
- **MEDIUM**: partial controls present (type check, partial validation, authenticated)
- **LOW**: heavily constrained, admin-only, or multiple independent controls
