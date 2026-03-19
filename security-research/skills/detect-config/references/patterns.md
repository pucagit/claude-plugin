# Security Vulnerability Patterns — Configuration & Cryptography

## Debug / Error Disclosure

### Django — DEBUG=True in committed settings
```python
# settings.py — VULNERABLE: debug hardcoded to True
DEBUG = True
ALLOWED_HOSTS = []  # allows any host when DEBUG=True

# settings/production.py — SAFE: read from environment
import os
DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')
```

### Flask — app.debug = True
```python
# VULNERABLE
app = Flask(__name__)
app.debug = True  # exposes interactive debugger — remote code execution

# SAFE
app.debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
# WARNING: Flask's debug mode exposes a PIN-protected interactive debugger
# Even with a PIN, debug=True in production is a HIGH finding
```

### Node.js — NODE_ENV not set to production
```javascript
// VULNERABLE: verbose errors in development mode
if (process.env.NODE_ENV !== 'production') {
    app.use((err, req, res, next) => {
        res.status(500).json({ error: err.message, stack: err.stack });
    });
}
// Check if NODE_ENV is actually set in deployment config
// If not set, Express defaults to development mode
```

---

## CORS Misconfiguration

### FastAPI — wildcard with credentials / dynamic origin reflection
```python
# VULNERABLE: reflect-origin effectively allows any origin with credentials
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # cannot use * WITH credentials per CORS spec
    allow_credentials=True,        # browser will reject this, but...
    allow_methods=["*"],
    allow_headers=["*"],
)

# ALSO VULNERABLE: dynamic origin reflection
@app.middleware("http")
async def add_cors_headers(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin", "")
    response.headers["Access-Control-Allow-Origin"] = origin  # reflects ANY origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
```

### Flask-CORS — wildcard and supports_credentials
```python
# VULNERABLE: origins=* with supports_credentials=True
from flask_cors import CORS
CORS(app, origins="*", supports_credentials=True)

# SAFE
CORS(app, origins=["https://app.example.com"], supports_credentials=True)
```

### Express / cors npm package
```javascript
// VULNERABLE: reflect origin without validation
app.use(cors({
    origin: (origin, callback) => callback(null, true),  // allows ALL origins
    credentials: true,
}));

// SAFE
const ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com'];
app.use(cors({
    origin: (origin, callback) => {
        if (ALLOWED_ORIGINS.includes(origin)) callback(null, true);
        else callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
}));
```

---

## Missing Security Headers

### Django — no SecurityMiddleware
```python
# VULNERABLE: SecurityMiddleware not in INSTALLED_MIDDLEWARE, or installed but settings disabled
MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.security.SecurityMiddleware',  ← missing
]

# Even with SecurityMiddleware, these defaults must be set:
SECURE_HSTS_SECONDS = 31536000          # HSTS: 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True      # X-Content-Type-Options: nosniff
X_FRAME_OPTIONS = 'DENY'               # X-Frame-Options: DENY
SECURE_BROWSER_XSS_FILTER = True       # X-XSS-Protection: 1; mode=block (legacy)
```

### Express — helmet not used
```javascript
// VULNERABLE: no helmet, no security headers set
const express = require('express');
const app = express();
// No helmet() call — missing all security headers

// SAFE
const helmet = require('helmet');
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
        }
    },
    hsts: { maxAge: 31536000, includeSubDomains: true },
}));
```

---

## Exposed Admin / Debug Endpoints

### Django Debug Toolbar in Production
```python
# VULNERABLE: debug toolbar included in production requirements
# requirements.txt: django-debug-toolbar==4.2.0
# settings.py:
INSTALLED_APPS = [
    ...
    'debug_toolbar',  # should only be in dev/local settings
]
MIDDLEWARE = [
    'debug_toolbar.middleware.DebugToolbarMiddleware',
    ...
]
INTERNAL_IPS = ['127.0.0.1']  # can sometimes be bypassed or config broadened
```

### Spring Boot Actuator — Exposed Endpoints
```yaml
# application.yml — VULNERABLE: all endpoints exposed
management:
  endpoints:
    web:
      exposure:
        include: "*"   # exposes /actuator/env, /actuator/heapdump, /actuator/loggers, etc.
  endpoint:
    env:
      enabled: true    # /actuator/env returns environment variables INCLUDING secrets
    heapdump:
      enabled: true    # /actuator/heapdump downloads JVM heap dump (contains all in-memory data)
  server:
    port: 8080         # CRITICAL: actuator on same port as app, not a separate admin port

# SAFE
management:
  endpoints:
    web:
      exposure:
        include: "health,info"
  endpoint:
    health:
      show-details: never
```

---

## Default Credentials & Hardcoded Secrets

### In Application Configuration

**Vulnerable — Python:**
```python
# settings.py
SECRET_KEY = "django-insecure-abc123"
SECRET_KEY = "myhardcodedsecret"
JWT_SECRET = "supersecret"
DATABASE_PASSWORD = "dbpass123"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
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
$hash = crypt($password, 'salt');  // DES, very weak
```

**Safe:**
```php
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
$hash = password_hash($password, PASSWORD_ARGON2ID);

$valid = password_verify($password, $hash);

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

def generate_password_reset_token():
    return str(random.randint(0, 2**32))
# Predictable from timestamp seed
```

**Safe:**
```python
import secrets

def generate_session_token():
    return secrets.token_urlsafe(32)  # 256 bits, CSPRNG

def generate_otp():
    return str(secrets.randbelow(1000000)).zfill(6)

def generate_reset_token():
    return secrets.token_hex(32)
```

### Node.js

**Vulnerable — Math.random():**
```javascript
function generateToken() {
    return Math.random().toString(36).substring(2);  // Not cryptographically secure
}
```

**Safe:**
```javascript
const crypto = require('crypto');

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateOTP() {
    return crypto.randomInt(100000, 1000000).toString();  // Node 14.10+
}
```

### Java

**Vulnerable — java.util.Random:**
```java
import java.util.Random;

Random rng = new Random();  // NOT secure
String token = Long.toString(Math.abs(rng.nextLong()), 36);
int otp = rng.nextInt(1000000);
```

**Safe — SecureRandom:**
```java
import java.security.SecureRandom;
import java.util.Base64;

SecureRandom rng = new SecureRandom();
byte[] tokenBytes = new byte[32];
rng.nextBytes(tokenBytes);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
```

### PHP

**Vulnerable — rand() / mt_rand():**
```php
$token = rand(100000, 999999);           // Predictable
$token = mt_rand(0, PHP_INT_MAX);        // Mersenne Twister — predictable
$token = uniqid();                       // Predictable (based on time)
$token = uniqid('prefix', true);        // Still time-based, partially predictable
```

**Safe:**
```php
$token = bin2hex(random_bytes(32));    // 64 hex chars
$token = base64_encode(random_bytes(32));
```

---

## Encryption Flaws

### AES-ECB Mode

ECB encrypts each 16-byte block independently. Identical plaintext blocks produce identical ciphertext blocks, leaking patterns in structured data.

**Vulnerable — Python (PyCryptodome):**
```python
from Crypto.Cipher import AES

KEY = b'thisisakey123456'
cipher = AES.new(KEY, AES.MODE_ECB)  # VULNERABLE — ECB mode
```

**Vulnerable — Java:**
```java
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  // ECB mode!
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
```

**Safe — AES-GCM (authenticated encryption):**
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY = get_random_bytes(32)

def encrypt(plaintext: bytes) -> dict:
    nonce = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {"nonce": nonce, "ciphertext": ciphertext, "tag": tag}

def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
```

### IV Reuse in AES-CBC

**Vulnerable — static IV:**
```python
from Crypto.Cipher import AES

KEY = b'\x00' * 16
IV = b'\x00' * 16   # STATIC IV — reused for every encryption!

def encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    return cipher.encrypt(plaintext)
```

**Vulnerable — IV derived predictably:**
```python
import time

def encrypt(plaintext: bytes) -> bytes:
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
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.decrypt(ciphertext)
```

---

## TLS Verification Issues

### Python

**Vulnerable:**
```python
import requests, urllib3

response = requests.get(url, verify=False)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
response = requests.get(url, verify=False)

import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

ctx = ssl._create_unverified_context()
response = urllib.request.urlopen(url, context=ctx)
```

**Safe:**
```python
import requests, certifi

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
tr := &http.Transport{
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
}
```

### Node.js

**Vulnerable:**
```javascript
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';  // Global bypass!
https.request({ hostname: 'target', rejectUnauthorized: false }, cb);
```

**Safe:**
```javascript
const fs = require('fs');
https.request({
    hostname: 'target',
    ca: fs.readFileSync('custom-ca.crt')
}, cb);
```

### Java

**Vulnerable:**
```java
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
URL url = new URL("https://example.com");
HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
// No custom TrustManager, no hostname verifier override
```

---

## Timing Attacks — Non-Constant-Time Comparison

**Vulnerable — Python:**
```python
import hmac, hashlib

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return expected == signature  # Short-circuits on first mismatch
```

**Vulnerable — Node.js:**
```javascript
function verifySignature(payload, signature, secret) {
    const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    return expected === signature;  // Regular equality check
}
```

**Vulnerable — PHP:**
```php
function verifyHmac($payload, $signature, $secret) {
    $expected = hash_hmac('sha256', $payload, $secret);
    return $expected === $signature;  // Not constant-time
}
```

**Safe — constant-time comparison:**
```python
import hmac

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, 'sha256').hexdigest()
    return hmac.compare_digest(expected, signature)
```

```javascript
function verifySignature(payload, signature, secret) {
    const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
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

## Container / Kubernetes Misconfigurations

### Docker Compose — Privileged Container
```yaml
# docker-compose.yml — VULNERABLE
services:
  app:
    image: myapp:latest
    privileged: true           # container can escape to host
    network_mode: "host"       # no network isolation
    volumes:
      - /:/host:rw             # mounts entire host filesystem
    environment:
      - DEBUG=true
      - DB_PASSWORD=admin123   # hardcoded credential
```

### Kubernetes — Privileged Pod / Wildcard RBAC
```yaml
# pod.yaml — VULNERABLE
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: default
  automountServiceAccountToken: true     # mounts SA token into pod
  containers:
  - name: app
    securityContext:
      privileged: true                   # can escape to node
      allowPrivilegeEscalation: true
      runAsUser: 0                       # runs as root
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /                            # mounts host root

# clusterrolebinding.yaml — VULNERABLE
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: default-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin              # default SA has cluster-admin → full cluster takeover
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
```
