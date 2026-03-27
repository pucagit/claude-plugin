---
name: detect-auth
description: Detect all authentication, authorization, and access control vulnerabilities — IDOR/BOLA, BFLA, privilege escalation, mass assignment, JWT issues, session management, OAuth/SAML, multi-tenant isolation, GraphQL introspection, and role hierarchy flaws. Consolidated detection skill for all auth/access patterns.
argument-hint: "<target_source> <audit_dir>"
user-invocable: false
---

# Authentication & Access Control Vulnerability Detection

## Goal
Find every place where a user can access or modify resources they don't own, escalate privileges, bypass authentication/session controls, or exploit access control design flaws.

## Learned Techniques
Before hunting, read [references/cool_techniques.md](references/cool_techniques.md) for applicable auth detection techniques learned from previous audits. Apply any relevant techniques during your analysis.

## Coverage

| Category | Sub-Types |
|---|---|
| **Missing Auth** | Endpoints accessible without login, missing auth decorators |
| **IDOR / BOLA** | Resource fetched/modified by ID without ownership check |
| **BFLA** | Admin/privileged functions accessible by lower-privilege users |
| **Privilege Escalation** | Horizontal (User A → B), vertical (user → admin) |
| **Mass Assignment** | Role/admin flags injectable via request body, `fields='__all__'` |
| **JWT Issues** | Algorithm confusion (none/HS256↔RS256), weak secrets, missing validation |
| **Session Management** | Fixation, no rotation after login, predictable session IDs |
| **Token Generation** | Predictable reset tokens, weak RNG for secrets |
| **OAuth/SAML** | Missing `state` param, token exchange bypass, SAML signature wrapping |
| **MFA Bypass** | Step-skipping, response manipulation |
| **Multi-Tenant** | Missing org_id/tenant_id scoping in queries |
| **GraphQL** | Introspection enabled in production, field suggestion enumeration |
| **Role Hierarchy** | Self-promotion, missing "requester outranks target" checks |
| **Client Trust** | `is_admin=true`, `role=admin` accepted from request body |

## Grep Patterns

### Endpoints Without Auth
```bash
# Frappe
grep -rn "allow_guest=True" --include="*.py" ${TARGET_SOURCE}
# Django
grep -rn "@api_view\|class.*APIView\|class.*ViewSet" --include="*.py" ${TARGET_SOURCE}
# Express
grep -rn "app\.get\|app\.post\|router\.get\|router\.post" --include="*.js" --include="*.ts" ${TARGET_SOURCE}
# Spring Boot
grep -rn "@PermitAll\|@GetMapping\|@PostMapping\|@PutMapping\|@DeleteMapping" --include="*.java" ${TARGET_SOURCE}
```

### IDOR / BOLA — Missing Ownership Check
```bash
grep -rn "request\.GET\.get\|request\.args\.get\|req\.params\.\|req\.query\.\|params\[:id\]\|@PathVariable\|c\.Param(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -i "id\|user_id\|account\|profile\|document\|order\|ticket"

# Object fetch patterns (check for ownership constraint)
grep -rn "get_object_or_404\|Model\.objects\.get(\|findById(\|findOne({.*:.*req\.\|getById(\|findByPk(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" ${TARGET_SOURCE}
```

### Mass Assignment / Client-Provided Role Flags
```bash
grep -rn "fields = '__all__'\|permit_all_parameters\|mass_assignment\|\.save(request\.data\|update_attributes(\|bulk_update" \
  --include="*.py" --include="*.rb" --include="*.js" --include="*.ts" ${TARGET_SOURCE}

grep -rn "is_admin\|is_staff\|is_superuser\|role\s*=\s*request\.\|admin\s*=\s*request\.\|privilege\s*=\s*request\.\|permission.*=.*request\." \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.php" ${TARGET_SOURCE}
```

### JWT Issues
```bash
grep -rn "jwt\.decode\|jwt\.verify\|verify=False\|algorithms=\[.*none\|algorithm.*none\|HS256\|RS256\|JWT_SECRET\|decode.*options" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" ${TARGET_SOURCE}
```

### Session Management
```bash
grep -rn "session\[.*\]\|session\.get(\|session_id\|session\.regenerate\|session\.invalidate\|session\.clear()" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.php" \
  --include="*.rb" --include="*.java" ${TARGET_SOURCE}
```

### Password Reset / Token Generation
```bash
grep -rn "reset_token\|password_reset\|forgot_password\|activation_token\|random\.\|token.*generate\|generate.*token" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.php" --include="*.rb" ${TARGET_SOURCE}
```

### GraphQL Introspection
```bash
grep -rn "introspection\|__schema\|__type\|disable.*introspection\|introspection.*false\|IntrospectionQuery\|NoSchemaIntrospectionCustomRule" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" ${TARGET_SOURCE}
```

### Exposed Internal / Admin Endpoints
```bash
grep -rn "/internal/\|/admin/\|/debug/\|/management/\|/_/\|/actuator/\|/health\|/metrics" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.php" ${TARGET_SOURCE}
```

### Role Assignment
```bash
grep -rn "role.*update\|update.*role\|assign.*role\|grant.*permission\|revoke.*permission\|promote\|set.*privilege" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" ${TARGET_SOURCE}
```

## Detection Process

### IDOR/BOLA Systematic Check (Mandatory — for EVERY endpoint with resource IDs)
1. Load `recon/architecture.md` — find all endpoints with path/query params containing `id`, `user_id`, `account_id`, `org_id`
2. For each, read the handler at `file:line`
3. Find the DB query — does it include ownership constraint?
   - SAFE: `Model.objects.get(id=id, user=request.user)` or `WHERE id = ? AND tenant_id = ?`
   - VULNERABLE: `Model.objects.get(id=id)` — no ownership scope
4. Flag if ownership checked only at session level (logged in) not object level (owns object)

### BFLA Systematic Check
1. Find all privileged function endpoints: delete-any, manage-users, access-all-data, billing, exports
2. Check auth decorator: `@admin_required` = SAFE, `@login_required` only = VULNERABLE

### JWT Algorithm Confusion
1. Find JWT decode call — check if `algorithms` is hardcoded or accepts any value
2. If RS256: check if server also accepts HS256 with public key as secret

### Mass Assignment Check
1. Find create/update endpoints — check serializer for explicit field allowlist
2. `fields='__all__'` + `role`/`admin`/`is_staff` in model = CRITICAL

### GraphQL Introspection
1. Find GraphQL setup — check if introspection disabled in production
2. Missing disable = enabled in production

### Role Hierarchy Check
1. Find role assignment endpoints — verify admin auth BEFORE role changes
2. Check: can regular user promote themselves? Can manager grant admin?

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `get(id=id)` without user scope on user-level endpoint | HIGH IDOR/BOLA |
| `get(id=id, user=request.user)` | FALSE POSITIVE |
| `get(id=id, org_id=request.user.org_id)` | FALSE POSITIVE (if org_id server-set) |
| Admin endpoint with `@login_required` only | HIGH BFLA |
| Admin endpoint with `@permission_required('admin')` | FALSE POSITIVE |
| `jwt.decode(token, options={'algorithms': ['none']})` | CRITICAL |
| `jwt.decode(token, key, algorithms=['HS256'])` hardcoded key | MEDIUM |
| `fields='__all__'` with role/admin in model | HIGH mass assignment |
| `read_only_fields = ['is_staff']` | FALSE POSITIVE |
| `random.randint()` for reset token | HIGH — predictable |
| `secrets.token_urlsafe()` for reset token | FALSE POSITIVE |
| Session not regenerated after login | MEDIUM session fixation |
| GraphQL introspection not disabled in production | MEDIUM |
| `role = request.data.get('role')` without admin check | HIGH privesc |
| `is_admin = serializer.validated_data.get('is_admin')` without admin check | CRITICAL |
| Role assignment without privilege level check | HIGH |

## LSP Integration

Use LSP diagnostics to confirm auth/access control issues:

- **`mcp__ide__getDiagnostics`** on auth middleware and decorators — verify they're correctly applied and not bypassed by type errors
- **Find references**: For auth check functions (`@login_required`, `isAuthenticated`, `authorize()`), find ALL call sites to discover endpoints that lack auth
- **Call hierarchy**: For privilege check functions, trace all callers to verify every admin endpoint uses them
- **Go-to-definition**: When custom auth decorators are used, verify the implementation actually enforces the check (not a no-op or incorrectly scoped)
- **Type constraints**: Check if user ID parameters are typed — a strongly-typed UUID prevents simple IDOR via integer manipulation

## Beyond Pattern Matching — Semantic Analysis

The grep patterns above catch known vulnerability shapes. After completing the pattern scan,
perform semantic analysis on the code you've read:

1. **For each handler/endpoint**: Read the full function. Ask: "What security assumption
   does this code make? Can that assumption be violated?"

2. **For custom abstractions**: If the codebase has custom auth decorators, permission
   middleware, or access control wrappers — read their implementations. Are they correct?
   Do they handle edge cases (null, empty, unicode, concurrent calls)?

3. **Cross-module flows**: If a variable passes through 3+ functions before reaching a sink,
   follow it through every hop. One missed encoding step in the middle = vulnerability.

4. **Auth-specific deep analysis**:
   - **Map every privilege boundary**: Draw the complete auth topology — which endpoints require which roles. Look for the *absence* of checks, not just broken checks. An endpoint that was simply forgotten is more common than a bypassed one.
   - **Verify enforcement is at the boundary, not just UI**: If admin buttons are hidden in the frontend but the backend endpoint has no auth check, that's a vulnerability. Check every admin-like endpoint for server-side enforcement.
   - **Alternative routes that bypass auth**: Can the same resource be accessed via a different URL, API version, or content type that doesn't have the auth middleware applied? Check for path aliases, API versioning patterns, and content negotiation.
   - **Object-level auth in bulk operations**: Single-object endpoints may check ownership, but do list/export/batch endpoints filter by the requesting user? Check pagination endpoints, CSV exports, and bulk-action handlers.
   - **Token/session lifecycle gaps**: Is the token validated on every request or just at login? After password change, are existing sessions invalidated? After role downgrade, is the cached permission set refreshed?

## Reference Files

- [Auth/access control vulnerable patterns by framework](references/patterns.md)
- [Attack payloads: JWT tampering, IDOR probes, OAuth exploits, BOLA enumeration](references/payloads.md)
- [Exploitation guide: IDOR enumeration, JWT forgery, privilege escalation, BFLA](references/exploitation.md)
