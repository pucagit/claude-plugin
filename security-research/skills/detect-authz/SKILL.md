---
name: detect-authz
description: Detect authentication and authorization vulnerabilities: IDOR, broken access control, privilege escalation, mass assignment, JWT algorithm confusion, session fixation, OAuth misbinding, SAML bypass, and multi-tenant isolation failures. Use during Phase 3 to systematically check every endpoint for missing ownership checks.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Authentication & Authorization Vulnerability Detection

## Goal
Find every place where a user can access or modify resources they don't own, escalate privileges, or bypass authentication/session controls.

## Sub-Types Covered
- **Missing authentication** — Endpoints accessible without any login
- **IDOR** — Resource fetched/modified using user-controlled ID without ownership check
- **Horizontal privilege escalation** — User A accessing User B's resources
- **Vertical privilege escalation** — Non-admin performing admin actions
- **Mass assignment** — Role/admin flags injectable via request body
- **JWT algorithm confusion** — `none` algorithm or HS256/RS256 swap
- **JWT secret brute-force** — Weak or default JWT secrets
- **Account enumeration** — Different responses for valid vs invalid usernames
- **Session fixation** — Session ID not rotated after login
- **Predictable reset tokens** — Password reset tokens using weak RNG
- **MFA bypass** — Step-skipping or response manipulation
- **OAuth misbinding** — `state` parameter missing, token exchange without verification
- **SAML signature bypass** — Signature wrapping, comment injection
- **Multi-tenant isolation failure** — Organization/tenant ID not scoped in queries

## Grep Patterns

### Endpoints Without Auth (Framework-Specific)
```bash
# Frappe
grep -rn "allow_guest=True" --include="*.py" ${TARGET_SOURCE}

# Django — views missing @login_required or permission_classes
grep -rn "@api_view\|class.*APIView\|class.*ViewSet" --include="*.py" ${TARGET_SOURCE}

# Express — routes without auth middleware
grep -rn "app\.get\|app\.post\|router\.get\|router\.post" --include="*.js" --include="*.ts" ${TARGET_SOURCE}

# Spring Boot — @PermitAll or missing @PreAuthorize
grep -rn "@PermitAll\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping" --include="*.java" ${TARGET_SOURCE}
```

### IDOR / Missing Ownership Check
```bash
# Resource ID in path params without ownership scope
grep -rn "request\.GET\.get\|request\.args\.get\|req\.params\.\|req\.query\.\|params\[:id\]\|@PathVariable\|c\.Param(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -i "id\|user_id\|account\|profile\|document\|order\|ticket"
```

### Mass Assignment (Role/Admin Fields)
```bash
grep -rn "fields = '__all__'\|permit_all_parameters\|attr_accessible\|mass_assignment\|\.save(request\.data\|update_attributes(\|bulk_update\|update_or_create(" \
  --include="*.py" --include="*.rb" --include="*.js" --include="*.ts" \
  ${TARGET_SOURCE}

# Check if role/admin/is_staff is in a writable serializer field
grep -rn "role\|admin\|is_staff\|is_superuser\|permissions\|privilege" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.rb" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|comment"
```

### JWT Issues
```bash
grep -rn "jwt\.decode\|jwt\.verify\|verify=False\|algorithms=\[.*none\|algorithm.*none\|HS256\|RS256\|secret\|JWT_SECRET\|decode.*options" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  ${TARGET_SOURCE}
```

### Session Management
```bash
grep -rn "session\[.*\]\|session\.get(\|session_id\|PHPSESSID\|sessionid\|session\.regenerate\|session\.invalidate\|session\.clear()" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.php" \
  --include="*.rb" --include="*.java" \
  ${TARGET_SOURCE}
```

### Password Reset / Token Generation
```bash
grep -rn "reset_token\|password_reset\|forgot_password\|activation_token\|random\.\|uuid\|token.*generate\|generate.*token" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.php" \
  --include="*.rb" \
  ${TARGET_SOURCE}
```

## Detection Process

### IDOR Check (Mandatory — for every endpoint with resource IDs)
1. Load `recon/architecture/endpoint_inventory.md` — find all endpoints with path/query params containing `id`, `user_id`, `account_id`, `org_id`, etc.
2. For each such endpoint, read the handler at `file:line`
3. Find the DB query or object fetch — does it include a user ownership constraint?
   - SAFE: `Model.objects.get(id=id, user=request.user)`
   - SAFE: `WHERE id = ? AND tenant_id = ?`
   - SAFE: `policy.authorize!(resource)`
   - VULNERABLE: `Model.objects.get(id=id)` — no ownership scope
4. Flag if ownership is checked only at session level (user logged in) not object level (user owns object)

### JWT Algorithm Confusion Check
1. Find JWT decode call
2. Check if `algorithms` parameter is hardcoded or accepts any value
3. If `algorithms` accepts user-supplied `alg` header → algorithm confusion attack
4. If using RS256 — check if server also accepts HS256 with public key as secret

### Mass Assignment Check
1. Find create/update endpoints
2. Check serializer or model form — is there an explicit field allowlist?
3. If `fields = '__all__'` or no allowlist → check if `role`/`admin`/`is_staff` are in the model

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `get(id=id)` without user scope | HIGH IDOR if endpoint is user-accessible |
| `get(id=id, user=request.user)` | FALSE POSITIVE |
| `jwt.decode(token, options={'algorithms': ['none']})` | CRITICAL |
| `jwt.decode(token, key, algorithms=['HS256'])` with hardcoded key | MEDIUM |
| `fields = '__all__'` with role/admin in model | HIGH mass assignment |
| `random.randint()` for reset token | HIGH — predictable token |
| `secrets.token_urlsafe()` for reset token | FALSE POSITIVE |
| Session not regenerated after login | MEDIUM session fixation |

## Reference Files

- [Vulnerable patterns by auth mechanism](references/patterns.md)
- [Attack payloads: JWT tampering, IDOR probes, OAuth exploits](references/payloads.md)
- [Exploitation guide: IDOR enumeration, JWT forgery, privilege escalation](references/exploitation.md)
