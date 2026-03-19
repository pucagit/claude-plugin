---
name: detect-logic
description: Detect business logic, concurrency, and API-specific vulnerabilities — race conditions, TOCTOU, double-spend, workflow bypass, price/quantity manipulation, cache poisoning/deception, distributed lock issues, rate limiting gaps, GraphQL DoS, excessive data exposure, and webhook security. Consolidated detection skill for all logic/timing/API patterns.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Business Logic, Concurrency & API Vulnerability Detection

## Goal
Find flaws in application logic, timing, and API design that allow users to violate business rules, exploit race conditions, abuse caching, or exploit API-specific weaknesses.

## Coverage

| Category | Sub-Types |
|---|---|
| **Race Conditions** | TOCTOU, check-then-act without lock, concurrent balance/quota operations |
| **Double-Spend** | Concurrent debit/credit without row lock, missing idempotency |
| **Quantity/Price** | Negative quantity manipulation, client-side price accepted, coupon reuse |
| **Workflow Bypass** | State machine step-skipping, approval process bypass, improper state transitions |
| **Distributed Locks** | Advisory lock not enforced, TTL too short, single-node SETNX |
| **Cache Attacks** | Web cache poisoning (unkeyed header), web cache deception (public on private), stale auth from cached tokens |
| **Rate Limiting** | Missing limits on login/OTP/reset/payment, no account lockout |
| **Replay** | Missing nonce/timestamp, no idempotency key |
| **GraphQL** | Query depth/batching DoS, field suggestion enumeration, excessive data exposure |
| **API Exposure** | `fields='__all__'` returning secrets, missing pagination caps, exposed API docs |
| **Webhooks** | Missing HMAC signature, URL not validated against internal IPs |

## Grep Patterns

### Race Condition / Atomic Operations
```bash
# Check-then-act patterns (absence of transaction is suspicious)
grep -rn "if.*balance.*>=\|if.*credit.*>=\|if.*quota.*>\|if.*limit.*>\|if.*count.*<\|if.*available" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.php" ${TARGET_SOURCE}

# Transaction / locking presence (safe patterns)
grep -rn "transaction\|with_transaction\|@transaction\|BEGIN\|COMMIT\|atomic\|select_for_update\|FOR UPDATE\|LOCK\|Mutex\|sync\.Mutex" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" ${TARGET_SOURCE}
```

### Non-Atomic Shared State
```bash
grep -rn "\.balance\|\.credit\|\.quota\|\.inventory\|\.stock\|\.remaining\|\.usage\|\.count" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -i "update\|decrement\|\-=\|\+=\|save\|commit"
```

### Quantity / Price from Request
```bash
grep -rn "quantity\|amount\|price\|total\|balance\|credit\|debit\|refund\|discount\|coupon" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.php" \
  ${TARGET_SOURCE} | grep -i "request\.\|req\.\|params\.\|body\.\|form\.\|input\."
```

### Workflow / State Machine
```bash
grep -rn "status\|state\|step\|phase\|stage\|workflow\|approval\|pending\|approved\|rejected\|completed" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -i "update\|change\|transition\|set\|request\.\|req\."
```

### Distributed Lock / Redis
```bash
grep -rn "redis\|redlock\|distributed_lock\|acquire_lock\|SETNX\|SET.*NX\|SET.*EX\|RedisLock\|Redlock" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" ${TARGET_SOURCE}
```

### Cache Key Construction
```bash
grep -rn "cache\.get(\|cache\.set(\|redis\.get(\|redis\.set(\|cache_key\|@cache\|@cached\|vary_on_headers" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" ${TARGET_SOURCE}

# User-controllable cache key input
grep -rn "request\.headers\|request\.META\|X-Forwarded\|X-Original\|X-Rewrite\|Host.*cache\|cache.*Host" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.go" ${TARGET_SOURCE}
```

### Cache Response Headers
```bash
grep -rn "Cache-Control\|Vary\|X-Cache\|Surrogate-Key\|CDN-Cache\|max-age\|s-maxage\|public.*cache\|cache.*public" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.go" \
  --include="*.conf" --include="*.yml" ${TARGET_SOURCE}
```

### Auth Token Caching
```bash
grep -rn "cache.*token\|token.*cache\|cache.*session\|session.*cache\|TTL.*auth\|auth.*TTL\|expire.*session\|jwt.*cache" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" ${TARGET_SOURCE}
```

### Rate Limiting
```bash
grep -rn "rate_limit\|ratelimit\|throttle\|RateLimit\|@limit\|slowDown\|express-rate-limit\|flask_limiter\|THROTTLE" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" ${TARGET_SOURCE}
```

### Nonce / Idempotency
```bash
grep -rn "nonce\|timestamp\|idempotency\|Idempotency-Key\|replay\|once\|one_time\|single_use\|dedup" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" ${TARGET_SOURCE}
```

### GraphQL Configuration
```bash
grep -rn "depth_limit\|maxDepth\|query_depth\|complexity\|MAX_COMPLEXITY\|depthLimit\|query_cost\|NoSchemaIntrospection" \
  --include="*.py" --include="*.js" --include="*.ts" ${TARGET_SOURCE}
```

### API Data Exposure
```bash
grep -rn "fields\s*=\s*'__all__'\|fields\s*=\s*\"__all__\"\|res\.json(\|\.toJSON(\|\.lean(" \
  --include="*.py" --include="*.js" --include="*.ts" ${TARGET_SOURCE}

grep -rn "password\|password_hash\|secret\|private_key\|api_key\|ssn\|credit_card\|token\|access_token\|refresh_token" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|comment\|#\|//"
```

### Pagination
```bash
grep -rn "page_size\|per_page\|limit\s*=\|paginate\|Paginator\|MAX_PAGE_SIZE\|pageSize" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" ${TARGET_SOURCE}
```

### Webhook Security
```bash
grep -rn "webhook\|X-Hub-Signature\|verify.*signature\|hmac.*verify\|webhook.*secret\|compute.*sig\|check.*sig" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" ${TARGET_SOURCE}
```

## Detection Process

### Race Conditions
1. Find endpoints modifying shared state (balance, quota, inventory)
2. Read handler: is read-modify-write in a transaction with row lock?
   - SAFE: `with transaction.atomic(): obj = Model.objects.select_for_update().get(id=id); obj.balance -= amount; obj.save()`
   - SAFE: `UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1` (atomic SQL)
   - VULNERABLE: `obj = get(id=id); if obj.balance >= amount: obj.balance -= amount; obj.save()`
3. Can two concurrent requests both pass the check and both deduct?

### Negative Quantities
1. Find order/transfer endpoints accepting quantity/amount
2. Is there server-side `quantity > 0` check?
3. What happens with `quantity = -1`?

### Workflow Bypass
1. Map intended workflow: A → B → C
2. Does step C's endpoint verify step B completed?
3. If it only checks object exists but not current state → bypass

### Cache Poisoning
1. Find cache key construction — any part from user headers?
2. Check if `X-Forwarded-Host` or similar used in response but not in cache key
3. Find responses using `Host` header in link generation

### Cache Deception
1. Find endpoints returning user-specific data with `Cache-Control: public`
2. Check if path extension affects caching

### Rate Limiting
1. Find login, password reset, OTP, payment endpoints
2. Check for rate limiting middleware on those routes
3. Check for account lockout logic

### GraphQL DoS
1. Find GraphQL schema setup — check for `depth_limit` / `complexity` middleware
2. If absent: HIGH DoS via deeply nested queries

### Webhook Security
1. Find webhook URL registration — validated against internal IPs?
2. Find webhook dispatch — HMAC signature computed?
3. Find webhook handler — signature verified with constant-time comparison?

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| Balance deduct outside transaction | HIGH race condition |
| `select_for_update()` in `transaction.atomic()` | FALSE POSITIVE |
| `UPDATE SET balance = balance - $1 WHERE balance >= $1` | FALSE POSITIVE (atomic) |
| `quantity` from request without `>0` check | HIGH negative quantity |
| Workflow step N doesn't check step N-1 state | HIGH bypass |
| Price from request body without DB re-fetch | HIGH price manipulation |
| Coupon not marked used after redemption | HIGH coupon abuse |
| Cache key includes `X-Forwarded-Host` | HIGH cache poisoning |
| `Cache-Control: public` on user-specific endpoint | HIGH cache deception |
| Auth token cached TTL >1hr with revocation possible | MEDIUM stale auth |
| Redis SETNX TTL shorter than operation | MEDIUM race window |
| Payment endpoint without idempotency key | MEDIUM duplicate charge |
| GraphQL without depth/complexity limiting | HIGH DoS |
| `fields='__all__'` returning password_hash | CRITICAL data exposure |
| Pagination without max page_size cap | MEDIUM |
| Login endpoint without rate limit or lockout | HIGH |
| OTP endpoint without rate limit | CRITICAL |
| Webhook URL not validated against internal IPs | HIGH SSRF |
| Webhook signature missing entirely | HIGH |
| `hmac.compare_digest(sig1, sig2)` | FALSE POSITIVE (constant-time) |

## Reference Files

- [Business logic & concurrency patterns by domain](references/patterns.md)
- [Attack payloads: concurrent requests, cache poisoning, GraphQL queries](references/payloads.md)
- [Exploitation guide: race condition PoC, workflow bypass, cache poisoning](references/exploitation.md)
