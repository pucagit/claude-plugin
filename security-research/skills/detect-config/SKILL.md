---
name: detect-config
description: Detect configuration and deployment vulnerabilities: debug mode in production, verbose error messages, CORS wildcard with credentials, missing security headers, exposed admin/debug endpoints, default credentials, open cloud storage, exposed .git files, directory listing, and insecure container configuration. Use during Phase 3 vulnerability detection.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Configuration & Deployment Vulnerability Detection

## Goal
Find insecure configuration settings that expose functionality, credentials, or sensitive data to attackers without requiring application logic exploitation.

## Sub-Types Covered
- **Debug mode enabled** — `DEBUG=True`, stack traces exposed to users
- **Verbose error messages** — Full stack traces in production responses
- **CORS wildcard + credentials** — `Access-Control-Allow-Origin: *` with credentials enabled
- **Missing security headers** — No CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Exposed admin/debug endpoints** — Admin panel, debug toolbar, profiler without auth
- **Default credentials** — admin:admin, admin:password, test:test in production config
- **Open cloud storage** — Public S3/GCS/Azure bucket containing sensitive files
- **Exposed .git** — `/.git/HEAD` accessible, enabling source code extraction
- **Exposed backup files** — `.bak`, `.sql`, `config.php.old` accessible via HTTP
- **Directory listing** — Web server indexes directories, exposing file structure
- **Insecure container** — Privileged container, host network, missing seccomp/AppArmor
- **Insecure Kubernetes** — Default service account with cluster-admin, exposed dashboard

## Grep Patterns

### Debug Mode / Stack Traces
```bash
grep -rn "DEBUG\s*=\s*True\|debug\s*=\s*true\|DEBUG\s*=\s*1\|app\.debug\s*=\s*True\|development\s*=\s*true\|\"debug\":\s*true" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.env" --include="*.conf" --include="*.ini" --include="*.yaml" \
  --include="*.yml" --include="*.json" --include="*.toml" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|False\|false\|0"

# Check if debug settings are env-conditional (safer)
grep -rn "if.*DEBUG\|os\.environ.*DEBUG\|process\.env.*DEBUG\|getenv.*DEBUG" \
  --include="*.py" --include="*.js" --include="*.ts" \
  ${TARGET_SOURCE}
```

### CORS Misconfiguration
```bash
grep -rn "Access-Control-Allow-Origin.*\*\|allow_origins.*\*\|CORS.*origins.*\*\|cors.*origin.*\*\|AllowAllOrigins\|AllowOriginFunc.*true\|allow_all_origins" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" --include="*.php" --include="*.cs" \
  ${TARGET_SOURCE}

grep -rn "Access-Control-Allow-Credentials.*true\|allow_credentials.*true\|AllowCredentials.*true\|supports_credentials.*True" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" \
  ${TARGET_SOURCE}
```

### Default / Hardcoded Credentials in Config
```bash
grep -rn "password.*admin\|password.*password\|password.*secret\|password.*12345\|password.*changeme\|DB_PASSWORD.*root\|MYSQL_ROOT_PASSWORD.*test\|POSTGRES_PASSWORD.*test\|admin.*:.*admin" \
  --include="*.env" --include="*.yml" --include="*.yaml" --include="*.json" \
  --include="*.conf" --include="*.ini" --include="*.toml" --include="*.xml" \
  ${TARGET_SOURCE} | grep -v "example\|sample\|template\|\.example\|placeholder"
```

### Missing Security Headers
```bash
# Look for where headers ARE set (to identify absence)
grep -rn "X-Frame-Options\|X-Content-Type-Options\|Strict-Transport-Security\|Content-Security-Policy\|X-XSS-Protection\|Referrer-Policy\|Permissions-Policy" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" --include="*.php" --include="*.conf" \
  ${TARGET_SOURCE}

# If NONE found → missing security headers across the board (LOW unless XSS also found)
```

### Exposed Admin / Debug Routes
```bash
grep -rn "django_debug_toolbar\|debugbar\|flask_debugtoolbar\|/admin/\|/debug/\|/__debug__/\|/internal/\|/actuator/\|/swagger-ui\|/api-docs/\|/graphiql\|/redoc" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.php" \
  ${TARGET_SOURCE}

# Check auth requirements on those routes
grep -rn "path.*admin.*\|url.*admin.*\|router.*admin\|route.*admin" \
  --include="*.py" --include="*.js" --include="*.ts" \
  ${TARGET_SOURCE}
```

### Insecure Docker / Container Config
```bash
grep -rn "privileged.*true\|--privileged\|network.*host\|pid.*host\|cap_add.*ALL\|securityContext.*privileged\|hostPath\|allowPrivilegeEscalation.*true\|runAsRoot.*true" \
  --include="*.yml" --include="*.yaml" --include="Dockerfile" --include="docker-compose*" \
  ${TARGET_SOURCE}
```

### Insecure Kubernetes RBAC
```bash
grep -rn "cluster-admin\|clusterrole.*cluster-admin\|verbs.*\*\|resources.*\*\|serviceAccountName.*default\|automountServiceAccountToken.*true" \
  --include="*.yml" --include="*.yaml" \
  ${TARGET_SOURCE}
```

### Spring Boot Actuator Endpoints
```bash
grep -rn "management\.endpoints\|actuator\|include.*\*\|endpoints\.web\.exposure\|health\.show-details\|env\.enabled\|heapdump\|threaddump" \
  --include="*.yml" --include="*.yaml" --include="*.properties" \
  ${TARGET_SOURCE}
```

## Detection Process

1. **Debug mode**: Check configuration files for debug flags — verify whether conditional on environment variable. `DEBUG=True` in a committed settings file that could reach production = HIGH.

2. **CORS**: Check CORS config: wildcard origin + credentials = CRITICAL; wildcard without credentials = LOW. Also check for reflect-origin configs (`allow_origins_regex`, `AllowOriginFunc` returning true for everything).

3. **Security headers**: Are they set globally in middleware? Which are missing? Missing HSTS alone is LOW. Missing CSP combined with a found XSS sink = escalate the XSS severity.

4. **Exposed admin routes**: Check auth requirements against `endpoint_inventory.md`. Django admin at `/admin/` with `is_staff` check is fine. Debug toolbar mounted without auth check = MEDIUM.

5. **Docker/Kubernetes**: Scan Docker/Kubernetes configs for privileged containers, host namespaces, wildcard RBAC verbs. `privileged: true` in a pod spec = HIGH container escape vector.

6. **Spring Boot Actuator**: `management.endpoints.web.exposure.include=*` with no security config = CRITICAL (exposes `/actuator/env`, `/actuator/heapdump`, etc.).

7. **Default credentials**: Check docker-compose.yml, .env.example, CI config files for credentials that could be copied into production.

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `DEBUG = True` in production settings file (not env-guarded) | HIGH |
| `DEBUG = os.environ.get('DEBUG', False)` | MEDIUM (flag — verify deployment) |
| CORS wildcard + `Allow-Credentials: true` | CRITICAL |
| CORS reflect-origin (AllowOriginFunc returns true for all) + credentials | CRITICAL |
| CORS wildcard without credentials | LOW |
| Missing HSTS header | LOW (needs HTTPS context) |
| Missing CSP header alone | LOW |
| Missing CSP + stored XSS found | Escalate XSS to CRITICAL |
| Default password `admin:admin` in docker-compose (non-example) | HIGH |
| Debug toolbar included in production dependencies without auth guard | MEDIUM |
| `privileged: true` in Kubernetes pod spec | HIGH — container escape |
| `allowPrivilegeEscalation: true` in securityContext | MEDIUM |
| Actuator `include=*` with no security filter | CRITICAL |
| Actuator `include=health` only | FALSE POSITIVE (typically safe) |
| `/swagger-ui` without auth on production | MEDIUM |
| GraphiQL enabled in production without auth | MEDIUM |

## Reference Files

- [Configuration vulnerability patterns: debug flags, CORS, container config](references/patterns.md)
- [Attack techniques: CORS exploitation, exposed .git extraction, metadata endpoints](references/payloads.md)
- [Exploitation guide: CORS credential theft, .git dumping, actuator endpoint abuse](references/exploitation.md)
