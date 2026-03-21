# Security Commit Patterns Reference

## Security Keyword Catalog

### Vulnerability Type Keywords
| Category | Keywords |
|---|---|
| **Injection** | sql injection, sqli, command injection, cmdi, ssti, template injection, ldap injection, xpath injection, nosql injection |
| **XSS** | xss, cross-site scripting, script injection, html injection, dom xss, stored xss, reflected xss |
| **Auth** | auth bypass, authentication, authorization, privilege escalation, idor, bola, bfla, access control, permission |
| **SSRF** | ssrf, server-side request, url validation, redirect, open redirect |
| **Traversal** | path traversal, directory traversal, lfi, rfi, file inclusion, zip slip |
| **Crypto** | weak hash, md5, sha1, insecure random, predictable token, timing attack, ecb mode |
| **Memory** | buffer overflow, use-after-free, double free, heap overflow, stack overflow, oob, out of bounds, format string |
| **Deserialization** | deserialization, pickle, marshal, unserialize, yaml.load, object injection |
| **Race** | race condition, toctou, time-of-check, double spend, concurrent, atomic |
| **Config** | debug mode, cors, csrf, hardcoded secret, default credential, exposed endpoint |

### Fix Action Keywords
| Category | Keywords |
|---|---|
| **Sanitization** | sanitize, escape, encode, filter, validate, whitelist, allowlist, parameterize |
| **Auth fixes** | require auth, add permission, check owner, verify token, add decorator |
| **General** | security fix, security patch, hotfix, vulnerability, CVE-, cve- |

## Common Fix Patterns — Reverse Engineering the Vulnerability

| Fix Pattern | Original Vulnerability | Grep for Unfixed |
|---|---|---|
| Added parameterized query | String-concatenated SQL | `execute(f"\|execute(".*%\|execute(".*+\|execute(".*format` |
| Added `shlex.quote()` or `shell=False` | Command injection | `os.system(\|subprocess.*shell=True\|Popen(.*shell` |
| Added path validation / `os.path.realpath` | Path traversal | `open(.*request\|os.path.join(.*request\|send_file(.*request` |
| Added URL allowlist / IP blocklist | SSRF | `requests.get(.*user\|fetch(.*user\|urllib.*user` |
| Added `| escape` or removed `| safe` | XSS | `\| safe\|mark_safe\|dangerouslySetInnerHTML\|v-html` |
| Added `yaml.safe_load` | Deserialization RCE | `yaml.load(\|pickle.loads(\|Marshal.load(` |
| Added ownership check to query | IDOR/BOLA | `get(id=\|findById(\|findOne(` without user scope |
| Added auth decorator | Missing authentication | endpoint definitions without auth decorator |
| Added `select_for_update()` / transaction | Race condition | read-modify-write without lock/transaction |
| Added `secrets.token_urlsafe()` | Predictable tokens | `random.randint\|random.choice\|Math.random` for tokens |
| Added `hmac.compare_digest()` | Timing attack | `== .*signature\|signature.* ==\|token.* ==` |
| Added input length/type validation | Various injection | sink calls without prior validation |

## Dependency Manifest Locations

| Ecosystem | Manifests | Lock Files |
|---|---|---|
| **Python** | `requirements.txt`, `setup.py`, `setup.cfg`, `pyproject.toml`, `Pipfile` | `Pipfile.lock`, `poetry.lock`, `requirements.lock` |
| **JavaScript/Node** | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| **Go** | `go.mod` | `go.sum` |
| **Java** | `pom.xml`, `build.gradle`, `build.gradle.kts` | `gradle.lockfile` |
| **Rust** | `Cargo.toml` | `Cargo.lock` |
| **Ruby** | `Gemfile`, `*.gemspec` | `Gemfile.lock` |
| **PHP** | `composer.json` | `composer.lock` |
| **C#/.NET** | `*.csproj`, `packages.config` | `packages.lock.json` |

## High-Risk Dependency Categories

Prioritize CVE searches for these library types:
1. **Web frameworks** — Express, Flask, Django, Spring, Rails, Laravel, FastAPI
2. **Auth libraries** — passport, django-allauth, Spring Security, devise, JWT libraries
3. **Serialization** — Jackson, Gson, pickle, yaml, MessagePack, protobuf
4. **Database drivers/ORMs** — SQLAlchemy, Sequelize, GORM, ActiveRecord, Hibernate
5. **Crypto libraries** — OpenSSL bindings, bcrypt, jose, cryptography
6. **HTTP clients** — requests, axios, okhttp, Faraday
7. **Template engines** — Jinja2, EJS, Handlebars, Thymeleaf, Blade
8. **File processing** — Pillow, ImageMagick bindings, pdf generators, archive handlers
