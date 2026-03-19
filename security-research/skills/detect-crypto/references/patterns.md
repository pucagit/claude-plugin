# Cryptographic Vulnerability Patterns by Language

## Weak Password Hashing

### Python

**Vulnerable — MD5 for password storage:**
```python
import hashlib

def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()
# Crackable with: hashcat -m 0, rainbow tables

def verify_password(password, stored_hash):
    return hashlib.md5(password.encode()).hexdigest() == stored_hash
# Same weakness — same hash, no salt
```

**Vulnerable — SHA1 without salt:**
```python
def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
# Crackable with: hashcat -m 100
```

**Vulnerable — SHA256 without salt (still weak for passwords):**
```python
def hash_password(password):
    # Better than MD5, but still no salt — rainbow tables applicable
    return hashlib.sha256(password.encode()).hexdigest()
```

**Vulnerable — MD5 with static salt:**
```python
SALT = "mysalt123"  # Same salt for all users = still rainbow-tableable

def hash_password(password):
    return hashlib.md5((SALT + password).encode()).hexdigest()
```

**Safe — bcrypt:**
```python
import bcrypt

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)
```

**Safe — argon2 (preferred modern choice):**
```python
from argon2 import PasswordHasher

ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hash: str, password: str) -> bool:
    return ph.verify(hash, password)
```

**Safe — Django built-in (PBKDF2 by default, can switch to argon2):**
```python
from django.contrib.auth.hashers import make_password, check_password

# Django handles everything — algorithm, salt, iterations
hashed = make_password("raw_password")      # $pbkdf2-sha256$260000$...
is_valid = check_password("raw_password", hashed)
```

### Java

**Vulnerable:**
```java
import java.security.MessageDigest;

public String hashPassword(String password) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] hash = md.digest(password.getBytes("UTF-8"));
    return DatatypeConverter.printHexBinary(hash).toLowerCase();
}

// Also weak — SHA1:
MessageDigest md = MessageDigest.getInstance("SHA-1");
```

**Safe — BCrypt (Spring Security):**
```java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hashed = encoder.encode(rawPassword);
boolean matches = encoder.matches(rawPassword, hashed);
```

**Safe — Argon2 (Bouncy Castle):**
```java
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public byte[] hashPassword(char[] password, byte[] salt) {
    Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withSalt(salt)
        .withParallelism(2)
        .withMemoryAsKB(65536)
        .withIterations(2)
        .build();
    Argon2BytesGenerator generator = new Argon2BytesGenerator();
    generator.init(params);
    byte[] hash = new byte[32];
    generator.generateBytes(password, hash);
    return hash;
}
```

### PHP

**Vulnerable:**
```php
$hash = md5($password);
$hash = sha1($password);
$hash = md5($salt . $password);  // Weak even with salt — MD5 too fast

// Vulnerable crypt() usage:
$hash = crypt($password, 'salt');  // DES, very weak
```

**Safe:**
```php
// PHP's password_hash — uses bcrypt by default, argon2 available
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
$hash = password_hash($password, PASSWORD_ARGON2ID);

$valid = password_verify($password, $hash);

// Rehash if algorithm/cost changed:
if (password_needs_rehash($hash, PASSWORD_ARGON2ID)) {
    $newHash = password_hash($password, PASSWORD_ARGON2ID);
}
```

### Node.js

**Vulnerable:**
```javascript
const crypto = require('crypto');

function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// Also weak — SHA256 alone:
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}
```

**Safe — bcryptjs:**
```javascript
const bcrypt = require('bcryptjs');

async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}
```

---

## Insecure Random Number Generation

### Python

**Vulnerable — random module (Mersenne Twister, not CSPRNG):**
```python
import random, string

def generate_session_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
# Mersenne Twister state can be reconstructed from 624 consecutive outputs

def generate_otp():
    return str(random.randint(100000, 999999))
# Only 900000 possibilities + predictable

def generate_password_reset_token():
    return str(random.randint(0, 2**32))
# Predictable from timestamp seed
```

**Vulnerable — Math.random() (Node.js):**
```javascript
function generateToken() {
    return Math.random().toString(36).substring(2);
    // Not cryptographically secure
}

function generateOTP() {
    return Math.floor(Math.random() * 1000000);
}
```

**Vulnerable — java.util.Random:**
```java
import java.util.Random;

Random rng = new Random();  // NOT secure
String token = Long.toString(Math.abs(rng.nextLong()), 36);
int otp = rng.nextInt(1000000);
```

**Vulnerable — PHP rand() / mt_rand():**
```php
$token = rand(100000, 999999);           // Predictable
$token = mt_rand(0, PHP_INT_MAX);        // Mersenne Twister — predictable
$token = uniqid();                       // Predictable (based on time)
$token = uniqid('prefix', true);        // Still time-based, partially predictable
```

**Safe — Python:**
```python
import secrets

def generate_session_token():
    return secrets.token_urlsafe(32)  # 256 bits, CSPRNG

def generate_otp():
    return str(secrets.randbelow(1000000)).zfill(6)

def generate_reset_token():
    return secrets.token_hex(32)  # 64 hex chars
```

**Safe — Node.js:**
```javascript
const crypto = require('crypto');

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateOTP() {
    return crypto.randomInt(100000, 1000000).toString();  // Node 14.10+
}
```

**Safe — Java:**
```java
import java.security.SecureRandom;
import java.util.Base64;

SecureRandom rng = new SecureRandom();
byte[] tokenBytes = new byte[32];
rng.nextBytes(tokenBytes);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
```

**Safe — PHP:**
```php
$token = bin2hex(random_bytes(32));    // 64 hex chars
$token = base64_encode(random_bytes(32));
```

---

## Hardcoded Secrets

### In Application Configuration

**Vulnerable — Python:**
```python
# settings.py
SECRET_KEY = "django-insecure-abc123"
SECRET_KEY = "myhardcodedsecret"
JWT_SECRET = "supersecret"
DATABASE_PASSWORD = "dbpass123"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# SMTP credentials
EMAIL_HOST_PASSWORD = "smtp_password_here"
```

**Vulnerable — Java:**
```java
// application.properties
private static final String JWT_SECRET = "mySecretKey";
private static final String DB_PASSWORD = "password123";
private static final String API_KEY = "sk-abcdef123456";
```

**Vulnerable — Node.js:**
```javascript
const JWT_SECRET = "my-super-secret-key";
const DB_CONNECTION = "mongodb://admin:password@localhost/prod";
const STRIPE_SECRET = "sk_live_ABC123def456";
```

**Vulnerable — Committed .env:**
```bash
# .env (should be in .gitignore but was committed)
DATABASE_URL=postgres://user:password@host/db
JWT_SECRET=hardcoded_jwt_secret_12345
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Safe — use environment variables:**
```python
import os
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set")
```

```javascript
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET not configured');
```

---

## AES-ECB Mode

### Why ECB is Dangerous

ECB (Electronic Codebook) encrypts each 16-byte block independently with the same key. Identical plaintext blocks → identical ciphertext blocks. For structured data (images, JSON, database records), this leaks patterns.

**Vulnerable — Python (PyCryptodome):**
```python
from Crypto.Cipher import AES
import os

KEY = b'thisisakey123456'  # 16 bytes

def encrypt_data(data: bytes) -> bytes:
    # Pad to 16-byte boundary
    padding = 16 - len(data) % 16
    data = data + bytes([padding] * padding)

    cipher = AES.new(KEY, AES.MODE_ECB)  # VULNERABLE — ECB mode
    return cipher.encrypt(data)
```

**Attack — ECB Block Rearrangement:**
```python
# If user controls part of plaintext, and can observe ciphertext,
# they can rearrange 16-byte blocks to forge valid ciphertexts

# Example: cookie "role=user&admin=false" encrypted with ECB
# Attacker can rearrange blocks to get "admin=true&role=user"
# without knowing the key
```

**Vulnerable — Java:**
```java
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // ECB mode!
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
byte[] encrypted = cipher.doFinal(plaintext);
```

**Safe — AES-GCM (authenticated encryption):**
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY = get_random_bytes(32)  # 256-bit key from secure storage

def encrypt(plaintext: bytes) -> dict:
    nonce = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {"nonce": nonce, "ciphertext": ciphertext, "tag": tag}

def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
```

---

## IV Reuse in AES-CBC

**Vulnerable — static IV:**
```python
from Crypto.Cipher import AES

KEY = b'\x00' * 16  # Some key
IV = b'\x00' * 16   # STATIC IV — reused for every encryption!

def encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    return cipher.encrypt(plaintext)

# Or:
IV = bytes(16)  # All zeros — static IV
```

**Vulnerable — IV derived predictably:**
```python
import time

def encrypt(plaintext: bytes) -> bytes:
    # IV based on timestamp — predictable if attacker knows approximate time
    iv = int(time.time()).to_bytes(8, 'big').ljust(16, b'\x00')
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(plaintext)
```

**Safe — random IV per message:**
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(16)  # Fresh random IV each time
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(plaintext)
    return iv + ciphertext  # Prepend IV to ciphertext

def decrypt(data: bytes, key: bytes) -> bytes:
    iv = data[:16]      # Extract IV from first 16 bytes
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(ciphertext)
```

---

## Non-Constant-Time HMAC Comparison

### Timing Attack Vulnerability

**Vulnerable — regular string comparison:**
```python
import hmac, hashlib

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return expected == signature  # VULNERABLE — short-circuits on first mismatch
    # Attacker can measure response time to guess signature byte by byte

# Also vulnerable:
return signature == expected
return hashlib.compare_digest is not used
```

**Vulnerable — Node.js:**
```javascript
function verifySignature(payload, signature, secret) {
    const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    return expected === signature;  // VULNERABLE — regular equality check
}
```

**Vulnerable — PHP:**
```php
function verifyHmac($payload, $signature, $secret) {
    $expected = hash_hmac('sha256', $payload, $secret);
    return $expected === $signature;  // VULNERABLE
}
```

**Safe — constant-time comparison:**
```python
import hmac

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, 'sha256').hexdigest()
    return hmac.compare_digest(expected, signature)  # Constant time

# Python 3.3+:
from hmac import compare_digest
return compare_digest(expected, received)
```

```javascript
function verifySignature(payload, signature, secret) {
    const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    // crypto.timingSafeEqual requires Buffer of equal length
    return crypto.timingSafeEqual(
        Buffer.from(expected, 'hex'),
        Buffer.from(signature, 'hex')
    );
}
```

```php
function verifyHmac($payload, $signature, $secret) {
    $expected = hash_hmac('sha256', $payload, $secret);
    return hash_equals($expected, $signature);  // Constant time — PHP 5.6+
}
```

---

## Disabled TLS Verification

### Python

**Vulnerable:**
```python
import requests, urllib3

# Disable certificate verification
response = requests.get(url, verify=False)
# Warning: urllib3.exceptions.InsecureRequestWarning

# Suppress warning (hiding the problem)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
response = requests.get(url, verify=False)

# Using ssl context
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```

**Vulnerable — custom HTTPS handler:**
```python
import ssl, urllib.request

ctx = ssl._create_unverified_context()  # Explicitly skips verification
response = urllib.request.urlopen(url, context=ctx)
```

**Safe:**
```python
import requests, certifi

# Always verify (default behavior — explicit for clarity)
response = requests.get(url, verify=True)
response = requests.get(url, verify=certifi.where())
```

### Go

**Vulnerable:**
```go
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},  // DANGEROUS
}
client := &http.Client{Transport: tr}
```

**Safe:**
```go
client := &http.Client{}  // Default — uses system CA bundle
// Or explicitly:
tr := &http.Transport{
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
        // InsecureSkipVerify NOT set
    },
}
```

### Node.js

**Vulnerable:**
```javascript
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';  // Global bypass!
// Or per-request:
https.request({ hostname: 'target', rejectUnauthorized: false }, cb);
```

**Safe:**
```javascript
// Don't set NODE_TLS_REJECT_UNAUTHORIZED
// Or if needed for specific CA:
const fs = require('fs');
https.request({
    hostname: 'target',
    ca: fs.readFileSync('custom-ca.crt')
}, cb);
```

### Java

**Vulnerable:**
```java
// Trusts all certificates
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
};
SSLContext sc = SSLContext.getInstance("SSL");
sc.init(null, trustAllCerts, new java.security.SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
```

**Safe:**
```java
// Use default SSLContext which validates against system truststore
URL url = new URL("https://example.com");
HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
// No custom TrustManager, no hostname verifier override
```
