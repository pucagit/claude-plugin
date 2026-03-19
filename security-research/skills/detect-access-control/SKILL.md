---
name: detect-access-control
description: Detect access control design flaws: broken object-level authorization (BOLA), broken function-level authorization (BFLA), missing ownership validation, exposed internal APIs, GraphQL introspection in production, role hierarchy misconfiguration, and implicit trust in client-provided flags. Use during Phase 3 vulnerability detection.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Access Control Design Flaw Detection

## Goal
Find systematic access control design failures where the authorization model itself is broken — not just missing checks on individual endpoints, but fundamental flaws in how roles, permissions, and object ownership are enforced.

## Sub-Types Covered
- **BOLA (Broken Object-Level Authorization)** — Resource fetched by ID without ownership check
- **BFLA (Broken Function-Level Authorization)** — Admin/privileged function accessible by lower-privilege user
- **Missing ownership validation** — Handler checks role but not "does this user own this resource"
- **Insecure default roles** — New accounts get too-permissive roles by default
- **Exposed internal APIs** — Internal endpoints reachable without authentication
- **GraphQL introspection in production** — Schema fully exposed, enabling targeted attacks
- **Role hierarchy misconfiguration** — User can grant themselves or others elevated roles
- **Implicit trust in client-provided flags** — `is_admin=true`, `role=admin` accepted from request body

## Grep Patterns

### Client-Provided Role/Admin Flags
```bash
grep -rn "is_admin\|is_staff\|is_superuser\|role\s*=\s*request\.\|admin\s*=\s*request\.\|privilege\s*=\s*request\.\|permission.*=.*request\.\|group.*=.*req\." \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.php" \
  ${TARGET_SOURCE}
```

### GraphQL Introspection
```bash
grep -rn "introspection\|__schema\|__type\|disable.*introspection\|introspection.*false\|IntrospectionQuery" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Exposed Internal / Admin Endpoints
```bash
grep -rn "/internal/\|/admin/\|/debug/\|/management/\|/_/\|/actuator/\|/health\|/metrics\|/status" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.php" \
  ${TARGET_SOURCE}
```

### Role Assignment Endpoints
```bash
grep -rn "role.*update\|update.*role\|assign.*role\|grant.*permission\|revoke.*permission\|change.*admin\|promote\|set.*privilege" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### BOLA / Missing Ownership Check
```bash
# Find object fetches using request-supplied ID
grep -rn "get_object_or_404\|Model\.objects\.get(\|findById(\|findOne({.*:.*req\.\|getById(\|findByPk(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

## Detection Process

### BOLA Systematic Check
1. Load `recon/architecture/endpoint_inventory.md`
2. For every endpoint that accepts a resource identifier (path param, query param) AND is accessible at user auth level:
3. Read the handler — trace from ID to DB fetch
4. Check if DB query includes user ownership constraint:
   - SAFE: `obj = Model.objects.get(id=id, owner=request.user)`
   - SAFE: `obj = Model.objects.get(id=id, org_id=request.user.org_id)` (multi-tenant scope)
   - VULNERABLE: `obj = Model.objects.get(id=id)` — fetches any user's object
5. Also check: does the endpoint have an admin path that bypasses ownership?

### BFLA Systematic Check
1. Find all "privileged function" endpoints: delete-any, manage-users, access-all-data, billing, exports
2. For each, check the auth decorator or middleware:
   - SAFE: `@admin_required`, `@permission_required('admin')`, `IsAdminUser`
   - VULNERABLE: `@login_required` only — any logged-in user can call admin function

### GraphQL Introspection Check
1. Find GraphQL endpoint setup
2. Check if introspection is disabled:
   - Django Graphene: `GRAPHENE = {"MIDDLEWARE": [...], "INTROSPECTION": False}`
   - Apollo Server: `introspection: process.env.NODE_ENV === 'production' ? false : true`
   - Missing disable = introspection enabled in production
3. Verify by searching for `NoSchemaIntrospectionCustomRule` or equivalent in middleware chain

### Client-Provided Role Trust
1. Find user update or profile endpoints
2. Trace request body parsing — does handler extract `role`, `is_admin`, `permissions` from request body?
3. If yes and no admin check before accepting those fields: HIGH mass assignment / privilege escalation
4. Also check serializers: Django REST `fields = '__all__'` on a model with `is_staff`/`is_superuser` is critical

### Role Assignment Authorization
1. Find role assignment endpoints (from grep above)
2. Verify the handler requires admin-level auth BEFORE executing role changes
3. Check: can a regular user promote themselves? Can a manager grant themselves admin?
4. Look for missing "requester must outrank target" checks in role hierarchy

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `Model.objects.get(id=id)` on user-level endpoint | HIGH BOLA |
| `Model.objects.get(id=id, owner=request.user)` | FALSE POSITIVE |
| `Model.objects.get(id=id, org_id=request.user.org_id)` | FALSE POSITIVE (if org_id is server-set) |
| Admin endpoint with `@login_required` only | HIGH BFLA |
| Admin endpoint with `@permission_required('admin')` | FALSE POSITIVE |
| GraphQL introspection not disabled in production | MEDIUM |
| `role = request.data.get('role')` in user update without admin check | HIGH mass assignment / privesc |
| `is_admin = serializer.validated_data.get('is_admin')` without admin check | CRITICAL |
| Role assignment endpoint without privilege level check | HIGH |
| `read_only_fields = ['is_staff', 'is_superuser']` in serializer | FALSE POSITIVE |

## Reference Files

- [Access control vulnerable patterns by framework](references/patterns.md)
- [Attack payloads: BOLA enumeration, BFLA probing, GraphQL introspection queries](references/payloads.md)
- [Exploitation guide: BOLA ID enumeration, privilege escalation via role assignment](references/exploitation.md)
