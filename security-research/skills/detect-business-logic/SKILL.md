---
name: detect-business-logic
description: Detect business logic vulnerabilities: race conditions (TOCTOU), double-spend, negative quantity manipulation, workflow/state machine bypass, price manipulation, coupon abuse, missing rate limiting, replay attacks, and approval process bypass. Use during Phase 3 vulnerability detection.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Business Logic Vulnerability Detection

## Goal
Find flaws in application logic that allow users to violate intended business rules — bypassing payment, escalating access, abusing workflows, or exploiting timing windows.

## Sub-Types Covered
- **Race condition / TOCTOU** — Check-then-act without atomic DB transaction or lock
- **Double-spend** — Concurrent debit/credit operations on same balance without lock
- **Negative quantity manipulation** — Signed integer or missing floor(0) check
- **Workflow / state machine bypass** — Reaching step N without completing N-1
- **Price manipulation** — Client-side price accepted by server or price overrideable
- **Coupon / discount abuse** — Coupon reusable, transferable, or applied multiple times
- **Inconsistent server-side validation** — Client validates but server trusts client
- **Replay attacks** — Requests without nonce/timestamp replayable
- **Missing rate limiting** — No limit on password attempts, OTP guesses, API calls
- **Approval process bypass** — Submitting without required approvals, skipping sign-off
- **Improper state transition** — Moving state backwards or to unauthorized state

## Grep Patterns

### Race Condition / Atomic Operations
```bash
# Check-then-act patterns outside transactions
grep -rn "if.*balance.*>=\|if.*credit.*>=\|if.*quota.*>\|if.*limit.*>\|if.*count.*<\|if.*available" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.php" \
  ${TARGET_SOURCE}

# Transaction / locking usage (absence is suspicious)
grep -rn "transaction\|with_transaction\|@transaction\|BEGIN\|COMMIT\|ROLLBACK\|atomic\|select_for_update\|FOR UPDATE\|LOCK\|Mutex\|sync\.Mutex" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Quantity / Price Validation
```bash
grep -rn "quantity\|amount\|price\|total\|balance\|credit\|debit\|refund\|discount\|coupon" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.php" \
  ${TARGET_SOURCE} | grep -i "request\.\|req\.\|params\.\|body\.\|form\.\|input\."
```

### State Machine / Workflow
```bash
grep -rn "status\|state\|step\|phase\|stage\|workflow\|approval\|pending\|approved\|rejected\|completed" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -i "update\|change\|transition\|set\|request\.\|req\.\|params\."
```

### Rate Limiting
```bash
grep -rn "rate_limit\|ratelimit\|throttle\|RateLimit\|@limit\|slowDown\|express-rate-limit\|flask_limiter\|redis.*incr\|INCR.*redis" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Nonce / Replay Prevention
```bash
grep -rn "nonce\|timestamp\|idempotency\|replay\|once\|one_time\|single_use\|used.*token\|token.*used" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

## Detection Process

Business logic vulnerabilities require reading handler logic, not just pattern matching:

### For Race Conditions
1. Find all endpoints that modify shared state (balance, quota, inventory, counter).
2. Read the handler: is the read-modify-write wrapped in a DB transaction with row-level lock?
   - SAFE: `with transaction.atomic(): obj = Model.objects.select_for_update().get(id=id); obj.balance -= amount; obj.save()`
   - VULNERABLE: `obj = Model.objects.get(id=id); if obj.balance >= amount: obj.balance -= amount; obj.save()`
3. For concurrent operations: can two simultaneous requests both pass the balance check and both deduct?

### For Negative Quantities
1. Find order/cart/transfer endpoints accepting quantity/amount parameters.
2. Read validation: is there a `quantity > 0` check server-side?
3. Test: what happens with `quantity = -1`? Does balance increase?

### For Workflow Bypass
1. Map the intended workflow from code/docs: step A → B → C.
2. Find the endpoint for step C — does it verify step B was completed?
3. If step C only checks that the object exists but not its current state → bypass possible.

### For Missing Rate Limiting
1. Find sensitive endpoints: login, password reset, OTP verification, payment.
2. Check for rate limiting decorator or middleware on those specific routes.
3. Check for global rate limiting in middleware chain.

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| Balance check + deduct outside DB transaction | HIGH race condition |
| `select_for_update()` before balance check | FALSE POSITIVE |
| `quantity` from request without `>0` check | HIGH negative quantity |
| `max(0, quantity)` enforced server-side | Mitigated — verify no other side effects |
| Workflow step N endpoint doesn't check step N-1 state | HIGH workflow bypass |
| No rate limiter on `/api/login` | MEDIUM (check if IP/account lockout exists elsewhere) |
| Coupon usage not marked as used after redemption | HIGH coupon abuse |
| Idempotency key stored and checked before processing | FALSE POSITIVE |
| Price taken from request body without DB re-fetch | HIGH price manipulation |

## Reference Files

- [Business logic vulnerable patterns by domain](references/patterns.md)
- [Attack sequences: concurrent requests, negative values, state skipping](references/payloads.md)
- [Exploitation guide: race condition tooling, double-spend PoC, workflow bypass](references/exploitation.md)
