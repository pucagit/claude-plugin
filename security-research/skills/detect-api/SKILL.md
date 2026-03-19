---
name: detect-api
description: Detect API-specific vulnerabilities: GraphQL query depth/batching DoS, mass assignment in REST APIs, missing rate limiting on sensitive endpoints, excessive data exposure, improper pagination limits, insecure webhooks, and webhook signature bypass. Use during Phase 3 vulnerability detection.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# API-Specific Vulnerability Detection

## Goal
Find vulnerabilities specific to REST and GraphQL API design: missing rate controls, data over-exposure, insecure webhook handling, and API-level abuse vectors that do not fit cleanly into classic injection or authz categories.

## Sub-Types Covered
- **GraphQL query depth DoS** — Deeply nested query causes exponential resolver execution
- **GraphQL batching abuse** — Multiple queries in single request bypass rate limiting
- **GraphQL field suggestion** — Error responses suggest valid field names, enabling enumeration
- **Mass assignment in REST** — Extra fields accepted server-side without explicit allowlist
- **Missing rate limiting** — No limit on login, OTP, password reset, payment, or enumeration endpoints
- **Excessive data exposure** — API returns sensitive fields not needed by client (password hash, tokens, PII)
- **Improper pagination limits** — No max page_size limit, enabling large data dumps
- **Insecure webhooks** — SSRF via webhook URL, no signature validation
- **Webhook signature bypass** — Weak signature comparison or algorithm confusion
- **Unauthenticated API introspection** — OpenAPI/Swagger docs exposed without auth

## Grep Patterns

### GraphQL Configuration
```bash
grep -rn "graphene\|graphql\|strawberry\|ariadne\|apollo\|type-graphql\|GraphQLSchema\|GraphQLObjectType\|resolver\|makeExecutableSchema" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}

# Check for depth limiting and complexity controls
grep -rn "depth_limit\|maxDepth\|query_depth\|complexity\|MAX_COMPLEXITY\|depthLimit\|ValidationRule\|cost\|query_cost\|NoSchemaIntrospection" \
  --include="*.py" --include="*.js" --include="*.ts" \
  ${TARGET_SOURCE}
```

### REST API Serializer / Field Exposure
```bash
# Django REST Framework — all fields exposed
grep -rn "fields\s*=\s*'__all__'\|fields\s*=\s*\"__all__\"" \
  --include="*.py" ${TARGET_SOURCE}

# Mongoose / Sequelize — full model returned
grep -rn "res\.json(\|res\.send(\|\.toJSON(\|\.toObject(\|\.lean(\|\.serialize(" \
  --include="*.js" --include="*.ts" ${TARGET_SOURCE}

# Look for sensitive field names in serializer output
grep -rn "password\|password_hash\|hashed_password\|secret\|private_key\|api_key\|ssn\|credit_card\|cvv\|token.*=\|access_token\|refresh_token" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|comment\|#\|//"
```

### Rate Limiting
```bash
grep -rn "rate_limit\|throttle\|RateLimit\|@limit\|slowDown\|express-rate-limit\|flask_limiter\|redis.*incr\|attempt.*limit\|max_attempts\|brute.force\|login.*attempt\|THROTTLE" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}

# Find sensitive endpoints that might lack rate limiting
grep -rn "login\|sign.in\|authenticate\|password.*reset\|forgot.*password\|otp\|verify.*code\|mfa\|two.factor\|payment\|checkout" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Pagination Limits
```bash
grep -rn "page_size\|per_page\|limit\s*=\|offset\|paginate\|Paginator\|\.paginate(\|MAX_PAGE_SIZE\|max_page_size\|page\.size\|pageSize" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Webhook Security
```bash
grep -rn "webhook\|hook_url\|callback_url\|X-Hub-Signature\|verify.*signature\|hmac.*verify\|signature.*valid\|webhook.*secret\|HMAC\|compute.*sig\|check.*sig" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Exposed API Documentation
```bash
grep -rn "swagger\|openapi\|api.docs\|redoc\|spectacle\|apidoc\|api-reference\|/docs\|/api/docs" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.conf" \
  ${TARGET_SOURCE}
```

## Detection Process

### GraphQL Depth/Complexity Check
1. Find GraphQL schema setup file
2. Search for depth limiting middleware — if absent: HIGH DoS potential
   ```python
   # Graphene Django — safe
   from graphene_django.views import GraphQLView
   from graphql_query_cost import add_query_cost_limit
   schema = graphene.Schema(query=Query)
   # If depth_limit_middleware or similar is NOT in MIDDLEWARE → vulnerable
   ```
3. Check if batching is enabled without per-query rate limit (Apollo Server batch by default)
4. Check if `__schema` / `__type` introspection is disabled in production
5. Verify field suggestion: does the server return "Did you mean 'secretField'?" error messages?

### Excessive Data Exposure
1. Find API response serializers / DTOs
2. Check for sensitive fields: `password`, `password_hash`, `hashed_password`, `secret`, `token`, `private_key`, `ssn`, `credit_card`
3. `fields = '__all__'` in Django REST serializer = inspect model definition for sensitive columns
4. For Mongoose: does `.lean()` / `.toObject()` return the full document including `__v`, `password`?
5. Check if `exclude = ['password']` or equivalent is present

### Webhook Security Check
1. Find webhook URL registration endpoint
   - Is the URL validated against a blocklist of internal IPs/ranges? → SSRF potential if not
   - Internal IP blocklist should cover: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`
2. Find webhook dispatch code — is a HMAC-SHA256 signature computed and sent in a header?
3. Find webhook receipt handler — is the HMAC signature verified before processing?
4. Is signature comparison constant-time (`hmac.compare_digest`)? String equality (`==`) is vulnerable to timing attacks
5. Is the raw request body used for HMAC (not parsed JSON re-serialized)?

### Missing Rate Limiting
1. Find login, password reset, OTP verification, and payment endpoints in `endpoint_inventory.md`
2. Check for rate limiting middleware or decorator on those specific routes
3. Check for account lockout logic after N failed attempts
4. Check for CAPTCHA requirements on sensitive forms

### Pagination Abuse Check
1. Find paginated list endpoints
2. Read handler: is `page_size` / `limit` from request capped at a maximum?
   - SAFE: `page_size = min(request.query_params.get('page_size', 20), 100)`
   - VULNERABLE: `page_size = request.query_params.get('page_size', 20)` — no cap, attacker can request millions of records

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| GraphQL without depth limiting or query complexity limit | HIGH — DoS potential |
| GraphQL with `depth_limit(10)` and `max_complexity(1000)` | FALSE POSITIVE |
| GraphQL introspection enabled in production | MEDIUM (escalates to HIGH with sensitive schema) |
| `fields = '__all__'` returning password_hash field | CRITICAL |
| `fields = '__all__'` on model with only safe fields | FALSE POSITIVE — verify model |
| Pagination without max page_size cap | MEDIUM |
| Login endpoint without rate limit or lockout | HIGH |
| OTP/2FA endpoint without rate limit | CRITICAL — enables brute force of 6-digit code |
| Webhook URL not validated against internal IP blocklist | HIGH — SSRF |
| Webhook signature verification missing entirely | HIGH |
| Webhook signature via `signature == computed` (not constant-time) | MEDIUM — timing attack |
| `hmac.compare_digest(sig1, sig2)` | FALSE POSITIVE |
| Swagger UI exposed without auth in production | MEDIUM |

## Reference Files

- [API vulnerability patterns: GraphQL, REST, webhook](references/patterns.md)
- [Attack payloads: GraphQL depth attack, mass assignment bodies, pagination abuse](references/payloads.md)
- [Exploitation guide: GraphQL DoS, REST data exposure, webhook SSRF](references/exploitation.md)
