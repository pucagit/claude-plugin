---
name: detect-concurrency
description: Detect distributed and concurrency vulnerabilities: race conditions in balance/quota updates, distributed lock bypass, eventual consistency abuse, cache poisoning via user-controlled keys, stale authorization decisions from cached tokens, and session inconsistency across nodes. Use during Phase 3 vulnerability detection.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Concurrency & Distributed System Vulnerability Detection

## Goal
Find race conditions and consistency failures in distributed systems that allow double-spending, cache poisoning, or bypassing authorization by exploiting timing windows or inconsistent state between components.

## Sub-Types Covered
- **Race condition in balance/quota** — Concurrent increment/decrement without atomic DB operation
- **Distributed lock bypass** — Advisory lock not enforced, or TTL too short for the operation duration
- **Eventual consistency abuse** — Reading stale data between write and replication propagation
- **Web cache poisoning** — User-controlled header poisons shared CDN/proxy cache
- **Web cache deception** — Trick cache into storing private response for public access
- **Stale authorization decisions** — Cached auth token remains valid after role revocation
- **Session inconsistency** — Different session state returned by different cluster nodes

## Grep Patterns

### Non-Atomic Shared State Operations
```bash
# Find balance/credit/quota updates — look for read-modify-write pattern outside transactions
grep -rn "\.balance\|\.credit\|\.quota\|\.inventory\|\.stock\|\.remaining\|\.usage\|\.limit\|\.count" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -i "update\|decrement\|\-=\|\+=\|save\|commit"

# Check for atomic operations (presence = safer)
grep -rn "select_for_update\|FOR UPDATE\|atomic\|transaction\|LOCK\|Mutex\|sync\.Mutex\|sync\/atomic\|compareAndSet\|INCR\|DECR\|WATCH\|optimistic\|version.*field\|row_version" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" \
  ${TARGET_SOURCE}
```

### Distributed Lock / Redis
```bash
grep -rn "redis\|redlock\|distributed_lock\|acquire_lock\|release_lock\|SETNX\|SET.*NX\|SET.*EX\|expire\|TTL\|lock\.acquire\|with.*lock\|RedisLock\|Redlock" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" \
  ${TARGET_SOURCE}
```

### Cache Key Construction
```bash
grep -rn "cache\.get(\|cache\.set(\|redis\.get(\|redis\.set(\|memcache\.\|cache_key\|cache_prefix\|CacheKey\|@cache\|@cached\|make_template_fragment_key\|cache_page\|vary_on_headers" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" \
  ${TARGET_SOURCE}

# Check if cache key includes user-controllable input
grep -rn "request\.headers\|request\.META\|X-Forwarded\|X-Original\|X-Rewrite\|Host.*cache\|cache.*Host" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" \
  ${TARGET_SOURCE}
```

### Auth Token / Session Caching
```bash
grep -rn "cache.*token\|token.*cache\|cache.*session\|session.*cache\|cache.*user\|user.*cache\|TTL.*auth\|auth.*TTL\|expire.*session\|session.*expire\|jwt.*cache\|cache.*jwt" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" \
  ${TARGET_SOURCE}
```

### HTTP Response Cache Configuration
```bash
grep -rn "Cache-Control\|Vary\|X-Cache\|Surrogate-Key\|CDN-Cache-Control\|Fastly-Surrogate\|CloudFront\|Varnish\|ETag\|Last-Modified\|max-age\|s-maxage\|public.*cache\|cache.*public" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" --include="*.conf" --include="*.yml" \
  ${TARGET_SOURCE}
```

### Idempotency Key / Duplicate Request Prevention
```bash
grep -rn "idempotency\|idempotent\|Idempotency-Key\|nonce\|replay\|duplicate.*request\|request.*id.*unique\|dedup" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.go" --include="*.rb" \
  ${TARGET_SOURCE}
```

## Detection Process

### Race Condition Check — Balance/Quota
1. Find endpoints that modify shared numeric state (balance, credits, quota, inventory)
2. Read the handler: is the read-modify-write inside a transaction with row locking?
   - SAFE (Django): `with transaction.atomic(): obj = Model.objects.select_for_update().get(id=id); obj.balance -= amount; obj.save()`
   - SAFE (SQL): `UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1` (single atomic statement)
   - SAFE (Go): `sync/atomic.AddInt64(&balance, -amount)`
   - VULNERABLE: `account = Account.objects.get(id=id); if account.balance >= amount: account.balance -= amount; account.save()`
3. Check for optimistic locking (version field): `UPDATE ... WHERE id=? AND version=?` — if version mismatch = retry, not skip
4. Check distributed lock usage for the operation — is lock TTL longer than the operation can take?

### Distributed Lock Assessment
1. Find `SETNX` / `SET NX EX` patterns (Redis distributed lock)
2. Is the lock key user-specific or global? User-specific = another user can bypass
3. What is the TTL? Is it always longer than the worst-case operation duration?
4. Is lock released in a `finally` block or only on success? Lock leak = DoS
5. Redlock: is the lock acquired on majority of Redis nodes? Single-node SETNX is unsafe under failover

### Web Cache Poisoning Check
1. Find cache key construction: is any part derived from user-controllable headers?
   - `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For` used in response but not in cache key?
2. Check CDN/nginx/Varnish config: which headers and params are part of the cache key?
3. Find responses that include header values in body (e.g., link generation using `Host` header) — these are poisoning sinks

### Web Cache Deception Check
1. Find endpoints that return user-specific data with `Cache-Control: public` or no cache control
2. Check if path extension affects caching: does `/profile/photo.css` serve the profile page cached?
3. Check Nginx/CDN config for extension-based caching rules

### Stale Auth Check
1. Find auth token caching (JWT or session data cached in Redis/Memcache)
2. Check TTL: is it longer than the time needed to revoke?
3. Check: if admin revokes user token/session, how long until cached token expires?
4. Check: if user role changes, is the cached auth object updated or must it expire?

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| Balance deduct without `select_for_update()` in transaction | HIGH race condition |
| `UPDATE ... SET balance = balance - $1 WHERE balance >= $1` (atomic SQL) | FALSE POSITIVE |
| `select_for_update()` inside `transaction.atomic()` | FALSE POSITIVE |
| Cache key includes `X-Forwarded-Host` header | HIGH cache poisoning |
| Cache key includes `Host` header (server-set, not user) | FALSE POSITIVE |
| `Cache-Control: public` on user-specific endpoint | HIGH cache deception |
| Auth token cached with TTL > 1hr, revocation possible | MEDIUM stale auth |
| Redis SETNX lock with TTL shorter than operation | MEDIUM — race window |
| Redis Redlock on single node | MEDIUM — unsafe under failover |
| Optimistic locking with version field + retry on conflict | FALSE POSITIVE |
| Payment endpoint without idempotency key | MEDIUM — duplicate charge risk |

## Reference Files

- [Concurrency vulnerability patterns by language/framework](references/patterns.md)
- [Attack payloads: concurrent request scripts, cache poisoning headers](references/payloads.md)
- [Exploitation guide: race condition PoC, cache poisoning, distributed lock bypass](references/exploitation.md)
