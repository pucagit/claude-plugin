---
name: detect-crypto
description: Detect cryptographic failures: hardcoded secrets, weak hashing algorithms (MD5/SHA1 for passwords), insecure RNG, IV reuse, ECB mode, improper TLS certificate validation, and unencrypted sensitive data storage. Use during Phase 3 vulnerability detection.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Cryptographic Failure Detection

## Goal
Find places where cryptographic controls are absent, weak, or misimplemented — creating exploitable weaknesses in confidentiality, integrity, or authentication.

## Sub-Types Covered
- **Hardcoded secrets** — API keys, passwords, JWT secrets, encryption keys in source code
- **Weak password hashing** — MD5 or SHA1 used for password storage without bcrypt/argon2
- **Unsalted hashes** — Hash without unique per-user salt
- **Custom crypto** — Rolling own encryption/hashing instead of standard libraries
- **Insecure RNG** — `random.random()`, `Math.random()`, `rand()` for security-sensitive values
- **Predictable tokens** — Session IDs or CSRF tokens from weak sources
- **IV reuse in AES-CBC** — Fixed or predictable initialization vector
- **ECB mode** — AES-ECB leaks patterns in ciphertext
- **Improper TLS validation** — `verify=False`, disabling hostname verification
- **TLS downgrade** — Supporting weak cipher suites or old TLS versions
- **Signature verification bypass** — Comparing signatures without constant-time comparison
- **Insecure key storage** — Private keys committed to git or stored in plaintext config
- **Sensitive data unencrypted at rest** — PII/payment data stored without encryption

## Grep Patterns

### Hardcoded Secrets
```bash
grep -rn "SECRET_KEY\s*=\s*['\"][^${\|PASSWORD\s*=\s*['\"][^${\|API_KEY\s*=\s*['\"\|private_key\s*=\s*['\"\|JWT_SECRET\s*=\s*['\"\|-----BEGIN.*PRIVATE\|access_key_id\s*=\s*['\"\|secret_access_key" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" --include="*.env" \
  --include="*.yml" --include="*.yaml" --include="*.json" --include="*.conf" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|example\|sample\|placeholder\|changeme\|your_"
```

### Weak Password Hashing
```bash
grep -rn "hashlib\.md5\|hashlib\.sha1\|md5(\|sha1(\|MD5\.\|SHA1\.\|MessageDigest.*MD5\|MessageDigest.*SHA.1\|hash.*password\|password.*hash" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Insecure RNG
```bash
grep -rn "random\.random(\|random\.randint(\|Math\.random(\|rand(\|srand(\|mt_rand(\|Random()\.\|new Random()" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.go" \
  ${TARGET_SOURCE} | grep -v "test\|spec"
```

### Weak TLS / Certificate Validation
```bash
grep -rn "verify=False\|ssl\._create_unverified_context\|InsecureRequestWarning\|CERT_NONE\|checkServerIdentity.*false\|rejectUnauthorized.*false\|InsecureSkipVerify.*true\|TLSClientConfig.*InsecureSkipVerify\|SSLContext.*CERT_NONE\|certifi" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.go" \
  --include="*.java" --include="*.rb" \
  ${TARGET_SOURCE}
```

### ECB Mode / IV Reuse
```bash
grep -rn "AES\.MODE_ECB\|Cipher\.getInstance.*AES/ECB\|Cipher\.getInstance.*ECB\|iv\s*=\s*b['\"]\\\\x00\|iv\s*=\s*bytes(16)\|iv.*=.*\\\\x00.*16\|initialization_vector.*static\|fixed.*iv" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" \
  ${TARGET_SOURCE}
```

### Non-Constant-Time Signature Comparison
```bash
grep -rn "==.*signature\|signature.*==\|hmac.*==\|token.*==\s*\|compare.*secret\|secret.*compare" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE} | grep -v "hmac\.compare_digest\|crypto\.timingSafeEqual\|MessageDigest\.isEqual\|secure_compare"
```

## Detection Process

1. Run each grep pattern category
2. For hardcoded secrets: confirm the value is actually used as a credential (not a default placeholder or test value)
3. For weak hashing: check if it's used for passwords (HIGH) vs checksums (LOW/informational)
4. For insecure RNG: check if output is used for security-sensitive purpose (session tokens, CSRF tokens, reset links)
5. For TLS bypass: confirm it affects production code paths, not just test helpers
6. Check `recon/architecture/framework_protections.md` — does the framework force strong hashing (Django passwords: bcrypt, argon2)?

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `hashlib.md5(password.encode()).hexdigest()` | CRITICAL — MD5 password hash |
| `hashlib.md5(file_content).hexdigest()` | FALSE POSITIVE — file integrity, not password |
| `bcrypt.hashpw(password, salt)` | FALSE POSITIVE — safe |
| `random.randint(100000, 999999)` for OTP | HIGH — predictable OTP |
| `secrets.randbelow(1000000)` for OTP | FALSE POSITIVE — CSPRNG |
| `verify=False` in production HTTP client | HIGH — TLS bypass |
| `AES.MODE_ECB` | HIGH — ECB mode |
| `AES.MODE_CBC` with random IV | FALSE POSITIVE if IV is random per message |
| `signature == hmac_signature` (== comparison) | HIGH — timing attack |
| `hmac.compare_digest(sig1, sig2)` | FALSE POSITIVE — constant-time |
| Hardcoded `SECRET_KEY = "mysecretkey"` in settings | HIGH — hardcoded secret |

## Reference Files

- [Vulnerable cryptographic patterns by language](references/patterns.md)
- [Attack techniques: hash cracking, timing attacks, ECB pattern analysis](references/payloads.md)
- [Exploitation guide: extracting secrets, breaking weak crypto](references/exploitation.md)
