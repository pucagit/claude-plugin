# Configuration Vulnerability Patterns

## Debug Mode

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

## CORS Misconfiguration

### FastAPI — wildcard with credentials (impossible per spec, but misconfigured)
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
# The real danger: when allow_origins is set to reflect origin dynamically

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

## Insecure Container Configuration

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
