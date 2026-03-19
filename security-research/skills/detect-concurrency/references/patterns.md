# Concurrency Vulnerability Patterns by Language/Framework

## Python / Django — Race Conditions

### Balance deduction without transaction locking
```python
# VULNERABLE: classic TOCTOU race condition
def redeem_coupon(user, coupon_code):
    coupon = Coupon.objects.get(code=coupon_code)
    if coupon.uses_remaining > 0:        # READ: 5 remaining
        # <<< RACE WINDOW: another request reads "5 remaining" simultaneously >>>
        coupon.uses_remaining -= 1       # MODIFY: 5 → 4
        coupon.save()                    # WRITE: two concurrent saves both write 4
        apply_discount(user, coupon)
    # Both requests succeed, but only one use was deducted

# VULNERABLE: balance check then deduct
def purchase(user, amount):
    account = Account.objects.get(user=user)
    if account.balance >= amount:         # READ
        account.balance -= amount         # MODIFY
        account.save()                    # WRITE — concurrent requests both deduct
    # Race: user can overdraw account by sending parallel requests

# SAFE: select_for_update() acquires row lock
from django.db import transaction

def purchase_safe(user, amount):
    with transaction.atomic():
        account = Account.objects.select_for_update().get(user=user)
        if account.balance >= amount:
            account.balance -= amount
            account.save()
        else:
            raise InsufficientFunds()

# SAFE: atomic SQL — single statement, no race window
def purchase_atomic(user, amount):
    updated = Account.objects.filter(
        user=user, balance__gte=amount
    ).update(balance=F('balance') - amount)
    if updated == 0:
        raise InsufficientFunds()
```

### Optimistic locking with version field
```python
# VULNERABLE: version check without lock
class Account(models.Model):
    balance = models.DecimalField(...)
    version = models.IntegerField(default=0)

def purchase_with_optimistic_lock(account_id, amount):
    account = Account.objects.get(id=account_id)
    # No retry on version conflict → race condition still exploitable
    Account.objects.filter(id=account_id, version=account.version).update(
        balance=account.balance - amount,
        version=account.version + 1
    )
    # If race: update affects 0 rows (version changed), but error is silently ignored

# SAFE: check rows_updated and retry
def purchase_optimistic_safe(account_id, amount, max_retries=3):
    for attempt in range(max_retries):
        account = Account.objects.get(id=account_id)
        if account.balance < amount:
            raise InsufficientFunds()
        updated = Account.objects.filter(
            id=account_id, version=account.version
        ).update(balance=account.balance - amount, version=account.version + 1)
        if updated == 1:
            return  # success
    raise ConcurrentModificationError("Too many retries")
```

## Node.js / JavaScript — Race Conditions

### Non-atomic balance update (MongoDB)
```javascript
// VULNERABLE: read-modify-write outside transaction
async function redeemVoucher(userId, voucherId) {
    const voucher = await Voucher.findById(voucherId);
    if (voucher.remainingUses > 0 && !voucher.usedBy.includes(userId)) {
        // RACE WINDOW
        voucher.remainingUses -= 1;
        voucher.usedBy.push(userId);
        await voucher.save();
        await applyDiscount(userId, voucher);
    }
}

// SAFE: findOneAndUpdate with atomic conditions
async function redeemVoucherSafe(userId, voucherId) {
    const result = await Voucher.findOneAndUpdate(
        {
            _id: voucherId,
            remainingUses: { $gt: 0 },
            usedBy: { $ne: userId }
        },
        {
            $inc: { remainingUses: -1 },
            $push: { usedBy: userId }
        },
        { new: true }
    );
    if (!result) throw new Error('Voucher not available');
    await applyDiscount(userId, result);
}
```

## Go — Non-Atomic Counter

### Unsynchronized shared state
```go
// VULNERABLE: race condition on shared counter
type RateLimiter struct {
    count int
    limit int
}

func (r *RateLimiter) Allow() bool {
    if r.count < r.limit {   // READ
        r.count++            // READ-MODIFY-WRITE (not atomic)
        return true
    }
    return false
}
// Concurrent goroutines: both read count=9, limit=10, both increment, both allowed

// SAFE: use sync/atomic
import "sync/atomic"

type AtomicRateLimiter struct {
    count int64
    limit int64
}

func (r *AtomicRateLimiter) Allow() bool {
    new := atomic.AddInt64(&r.count, 1)  // atomic increment
    if new > r.limit {
        atomic.AddInt64(&r.count, -1)    // undo if over limit
        return false
    }
    return true
}

// SAFE: use sync.Mutex
import "sync"

type MutexRateLimiter struct {
    mu    sync.Mutex
    count int
    limit int
}

func (r *MutexRateLimiter) Allow() bool {
    r.mu.Lock()
    defer r.mu.Unlock()
    if r.count < r.limit {
        r.count++
        return true
    }
    return false
}
```

## Redis Distributed Lock Patterns

### Insufficient TTL — lock expires before operation completes
```python
# VULNERABLE: TTL is 1 second but operation can take 5+ seconds
import redis

r = redis.Redis()

def process_payment(payment_id, amount):
    lock_key = f"payment_lock:{payment_id}"
    # Acquire lock with 1-second TTL
    acquired = r.set(lock_key, "1", nx=True, ex=1)
    if not acquired:
        raise Exception("Payment in progress")
    try:
        # External payment API call — can take 3-10 seconds
        result = payment_gateway.charge(amount)
        # <<< Lock has expired after 1s >>>
        # Another process acquired the lock and is also charging
        save_result(payment_id, result)
    finally:
        r.delete(lock_key)

# SAFE: TTL must exceed worst-case operation duration
def process_payment_safe(payment_id, amount):
    lock_key = f"payment_lock:{payment_id}"
    # 30 second TTL — longer than any payment API call
    acquired = r.set(lock_key, "1", nx=True, ex=30)
    if not acquired:
        raise Exception("Payment in progress")
    try:
        result = payment_gateway.charge(amount)
        save_result(payment_id, result)
    finally:
        r.delete(lock_key)
```

### Lock not released on exception (lock leak)
```python
# VULNERABLE: exception before finally — lock never released
def critical_section(resource_id):
    lock_key = f"lock:{resource_id}"
    r.setnx(lock_key, "1")
    r.expire(lock_key, 30)
    # If exception here: lock holds for 30s (DoS)
    process(resource_id)
    r.delete(lock_key)  # never reached on exception

# SAFE: always release in finally
def critical_section_safe(resource_id):
    lock_key = f"lock:{resource_id}"
    if not r.set(lock_key, "1", nx=True, ex=30):
        raise Exception("Resource locked")
    try:
        process(resource_id)
    finally:
        r.delete(lock_key)
```

## Web Cache Poisoning

### Cache key includes user-controlled header
```python
# VULNERABLE: cache key constructed using X-Forwarded-Host
# nginx.conf or application middleware:
def get_cache_key(request):
    # X-Forwarded-Host is user-controlled in most proxy setups
    host = request.headers.get('X-Forwarded-Host', request.headers.get('Host'))
    return f"page:{host}:{request.path}"

# Application generates URLs using this host:
def render_page(request):
    cache_key = get_cache_key(request)
    cached = cache.get(cache_key)
    if cached:
        return cached

    host = request.headers.get('X-Forwarded-Host', request.host)
    # Links in page use attacker-controlled host
    content = render_template('page.html', base_url=f"https://{host}")
    cache.set(cache_key, content, timeout=3600)
    return content

# Attacker sends: X-Forwarded-Host: attacker.com
# Response with links pointing to attacker.com is cached for all users
```

### Web cache deception — private response cached as public
```
# Nginx config — VULNERABLE: caches by extension, ignoring auth
location ~* \.(css|js|png|jpg|gif)$ {
    proxy_cache static_cache;
    proxy_cache_valid 200 1d;
    add_header X-Cache $upstream_cache_status;
}

# Attack: user visits /profile/../../style.css
# Server serves profile page (auth'd content)
# Nginx caches it as a static file (due to .css extension)
# Anyone accessing /profile/../../style.css gets cached private data
```
