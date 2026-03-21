---
name: detect-config
description: Detect configuration, cryptographic, and deployment security vulnerabilities — debug mode, CORS misconfiguration, missing headers, exposed admin endpoints, default credentials, hardcoded secrets, weak password hashing, insecure RNG, ECB mode, TLS bypass, timing attacks, container/Kubernetes misconfig. Consolidated detection skill for all configuration and crypto patterns.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Configuration & Cryptographic Vulnerability Detection

## Goal
Find security misconfigurations, deployment weaknesses, and cryptographic failures that weaken the application's security posture.

## Coverage

| Category | Sub-Types |
|---|---|
| **Debug/Error** | Debug mode in production, verbose error messages, stack traces |
| **CORS** | Wildcard origin + credentials, reflect-origin, missing validation |
| **Headers** | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| **Exposed Endpoints** | Admin panels, debug toolbars, actuators, API docs without auth |
| **Default Creds** | Hardcoded passwords in config, default admin credentials |
| **Secrets** | Hardcoded API keys, private keys, JWT secrets in source |
| **Password Hashing** | MD5/SHA1 for passwords, unsalted hashes, custom crypto |
| **RNG** | `random.random()`/`Math.random()` for security tokens |
| **Encryption** | ECB mode, IV reuse in AES-CBC, fixed/null IVs |
| **TLS** | `verify=False`, `InsecureSkipVerify`, certificate bypass |
| **Timing Attacks** | Non-constant-time signature/token comparison |
| **Key Storage** | Private keys in source, unencrypted secrets at rest |
| **Container** | Privileged containers, host namespaces, wildcard RBAC |

## Grep Patterns

### Debug Mode
```bash
grep -rn "DEBUG\s*=\s*True\|debug\s*=\s*true\|DEBUG\s*=\s*1\|app\.debug\s*=\s*True\|\"debug\":\s*true" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.env" --include="*.conf" --include="*.ini" --include="*.yaml" \
  --include="*.yml" --include="*.json" --include="*.toml" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|False\|false\|0"

# Check if env-conditional (safer)
grep -rn "if.*DEBUG\|os\.environ.*DEBUG\|process\.env.*DEBUG\|getenv.*DEBUG" \
  --include="*.py" --include="*.js" --include="*.ts" ${TARGET_SOURCE}
```

### CORS Misconfiguration
```bash
grep -rn "Access-Control-Allow-Origin.*\*\|allow_origins.*\*\|CORS.*origins.*\*\|AllowAllOrigins\|allow_all_origins" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" --include="*.php" --include="*.cs" ${TARGET_SOURCE}

grep -rn "Access-Control-Allow-Credentials.*true\|allow_credentials.*true\|AllowCredentials.*true\|supports_credentials.*True" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" ${TARGET_SOURCE}
```

### Security Headers
```bash
grep -rn "X-Frame-Options\|X-Content-Type-Options\|Strict-Transport-Security\|Content-Security-Policy\|Referrer-Policy\|Permissions-Policy" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.conf" ${TARGET_SOURCE}
```

### Default / Hardcoded Credentials
```bash
grep -rn "password.*admin\|password.*password\|password.*secret\|password.*12345\|password.*changeme\|DB_PASSWORD.*root\|MYSQL_ROOT_PASSWORD.*test\|POSTGRES_PASSWORD.*test" \
  --include="*.env" --include="*.yml" --include="*.yaml" --include="*.json" \
  --include="*.conf" --include="*.ini" --include="*.toml" --include="*.xml" \
  ${TARGET_SOURCE} | grep -v "example\|sample\|template\|\.example\|placeholder"
```

### Hardcoded Secrets
```bash
grep -rn "SECRET_KEY\s*=\s*['\"][^${\|API_KEY\s*=\s*['\"\|JWT_SECRET\s*=\s*['\"\|-----BEGIN.*PRIVATE\|access_key_id\s*=\s*['\"\|secret_access_key" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" --include="*.env" \
  --include="*.yml" --include="*.yaml" --include="*.json" --include="*.conf" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|example\|sample\|placeholder\|your_"
```

### Exposed Admin / Debug Endpoints
```bash
grep -rn "django_debug_toolbar\|debugbar\|flask_debugtoolbar\|/admin/\|/debug/\|/__debug__/\|/internal/\|/actuator/\|/swagger-ui\|/api-docs/\|/graphiql\|/redoc" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.php" ${TARGET_SOURCE}
```

### Spring Boot Actuator
```bash
grep -rn "management\.endpoints\|actuator\|endpoints\.web\.exposure\|health\.show-details\|heapdump\|threaddump" \
  --include="*.yml" --include="*.yaml" --include="*.properties" ${TARGET_SOURCE}
```

### Weak Password Hashing
```bash
grep -rn "hashlib\.md5\|hashlib\.sha1\|md5(\|sha1(\|MD5\.\|SHA1\.\|MessageDigest.*MD5\|MessageDigest.*SHA.1" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" ${TARGET_SOURCE}
```

### Insecure RNG
```bash
grep -rn "random\.random(\|random\.randint(\|Math\.random(\|rand(\|mt_rand(\|Random()\.\|new Random()" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.go" ${TARGET_SOURCE} | grep -v "test\|spec"
```

### Weak TLS / Certificate Bypass
```bash
grep -rn "verify=False\|ssl\._create_unverified_context\|CERT_NONE\|rejectUnauthorized.*false\|InsecureSkipVerify.*true\|SSLContext.*CERT_NONE" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.go" \
  --include="*.java" --include="*.rb" ${TARGET_SOURCE}
```

### ECB Mode / IV Reuse
```bash
grep -rn "AES\.MODE_ECB\|Cipher\.getInstance.*ECB\|iv\s*=\s*b['\"]\\\\x00\|iv\s*=\s*bytes(16)\|fixed.*iv\|static.*iv" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.php" ${TARGET_SOURCE}
```

### Non-Constant-Time Comparison
```bash
grep -rn "==.*signature\|signature.*==\|hmac.*==\|token.*==" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -v "hmac\.compare_digest\|crypto\.timingSafeEqual\|MessageDigest\.isEqual\|secure_compare"
```

### Insecure Container Config
```bash
grep -rn "privileged.*true\|--privileged\|network.*host\|pid.*host\|cap_add.*ALL\|allowPrivilegeEscalation.*true\|runAsRoot" \
  --include="*.yml" --include="*.yaml" --include="Dockerfile" --include="docker-compose*" ${TARGET_SOURCE}
```

### Insecure Kubernetes RBAC
```bash
grep -rn "cluster-admin\|verbs.*\*\|resources.*\*\|serviceAccountName.*default\|automountServiceAccountToken.*true" \
  --include="*.yml" --include="*.yaml" ${TARGET_SOURCE}
```

## Detection Process

### Debug Mode
1. Check if conditional on environment variable → MEDIUM (safer)
2. Hardcoded `True` in production settings → HIGH

### CORS
1. Wildcard origin + credentials → CRITICAL
2. Reflect-origin (AllowOriginFunc returns true for all) + credentials → CRITICAL
3. Wildcard without credentials → LOW

### Crypto Review
1. Weak hashing for passwords (HIGH) vs file checksums (safe)
2. Insecure RNG for security tokens (HIGH) vs display purposes (safe)
3. TLS bypass in production code paths (HIGH) vs dev/test only (MEDIUM)
4. Non-constant-time comparison for security tokens (HIGH)

### Container/K8s
1. Privileged containers, host namespaces → HIGH
2. Wildcard RBAC verbs/resources → HIGH
3. Default service accounts in production → MEDIUM

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `DEBUG = True` not env-guarded | HIGH |
| `DEBUG = os.environ.get('DEBUG', False)` | MEDIUM |
| CORS wildcard + `Allow-Credentials: true` | CRITICAL |
| CORS wildcard without credentials | LOW |
| Missing HSTS header | LOW |
| Missing CSP + stored XSS found | Escalates XSS |
| Default `admin:admin` in docker-compose | HIGH |
| Actuator `include=*` without auth | CRITICAL |
| `/swagger-ui` without auth | MEDIUM |
| `hashlib.md5(password)` | CRITICAL |
| `hashlib.md5(file_content)` | FALSE POSITIVE |
| `bcrypt.hashpw(password, salt)` | FALSE POSITIVE |
| `random.randint()` for OTP | HIGH |
| `secrets.randbelow()` for OTP | FALSE POSITIVE |
| `verify=False` in production | HIGH |
| `AES.MODE_ECB` | HIGH |
| `AES.MODE_CBC` with random IV | FALSE POSITIVE |
| `signature == hmac_sig` | HIGH timing attack |
| `hmac.compare_digest(s1, s2)` | FALSE POSITIVE |
| Hardcoded `SECRET_KEY = "mysecretkey"` | HIGH |
| `privileged: true` in K8s pod | HIGH |

## Beyond Pattern Matching — Semantic Analysis

The grep patterns above catch known vulnerability shapes. After completing the pattern scan,
perform semantic analysis on the code you've read:

1. **For each handler/endpoint**: Read the full function. Ask: "What security assumption
   does this code make? Can that assumption be violated?"

2. **For custom abstractions**: If the codebase has custom configuration loaders, secret managers,
   or crypto wrappers — read their implementations. Are they correct?
   Do they handle edge cases (null, empty, unicode, concurrent calls)?

3. **Cross-module flows**: If a variable passes through 3+ functions before reaching a sink,
   follow it through every hop. One missed encoding step in the middle = vulnerability.

4. **Config-specific deep analysis**:
   - **Don't just check if headers are set — check if they're set correctly**: A CSP of `default-src *` is present but useless. HSTS without `includeSubDomains` leaves subdomains vulnerable. CORS with a regex origin check may be bypassable (`evil-example.com` matching `example.com`).
   - **Environment-conditional config bypass**: If security settings are gated on `NODE_ENV === 'production'` or `DEBUG = os.environ.get(...)` — can an attacker influence the environment? Check for `.env` files in the repo, environment variable injection via SSRF, or config endpoints that reveal the current environment.
   - **Secret rotation and lifecycle**: Hardcoded secrets are bad, but also check: are secrets rotated? Is there a single master secret whose compromise breaks everything? Are secrets logged, included in error messages, or returned in API responses?
   - **Crypto implementation details**: Don't just flag "uses AES-ECB" — understand *what* is being encrypted and *why* ECB matters for that data. A single-block encryption in ECB is fine; encrypting structured data with repeated patterns is not. Check IV generation, key derivation (PBKDF2 iterations?), and mode-specific requirements.
   - **Deployment configuration drift**: Check if there are separate config files for dev/staging/prod. Are the prod configs actually more restrictive? Look for `docker-compose.override.yml`, `.env.production`, and Kubernetes ConfigMaps/Secrets that might override secure defaults.

## Reference Files

- [Configuration & crypto vulnerable patterns](references/patterns.md)
- [Attack payloads: CORS exploits, crypto attacks, container escapes](references/payloads.md)
- [Exploitation guide: CORS exploitation, timing attacks, container breakout](references/exploitation.md)
