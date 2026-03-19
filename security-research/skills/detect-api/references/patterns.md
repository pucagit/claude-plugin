# API Vulnerability Patterns: GraphQL, REST, Webhook

## GraphQL

### Missing depth limit — Graphene (Python)
```python
# VULNERABLE: no depth limit, attacker can cause exponential resolver calls
import graphene
from graphene_django import DjangoObjectType

class UserType(DjangoObjectType):
    class Meta:
        model = User

class PostType(DjangoObjectType):
    class Meta:
        model = Post

class Query(graphene.ObjectType):
    user = graphene.Field(UserType, id=graphene.Int())
    def resolve_user(self, info, id):
        return User.objects.get(id=id)

schema = graphene.Schema(query=Query)
# No depth limit middleware → {user{posts{author{posts{author{posts{...}}}}}}} → DB explosion

# SAFE: add depth limit
from graphql_query_cost import add_query_cost_limit  # or graphene-query-cost-analysis
# Or use: from graphql import build_ast_schema
# Or Graphene middleware:
GRAPHENE = {
    'SCHEMA': 'myapp.schema.schema',
    'MIDDLEWARE': ['graphene_django.debug.DjangoDebugMiddleware'],  # not sufficient alone
    # Must also add query depth limiting separately
}
```

### Missing depth limit — Apollo Server (JavaScript)
```javascript
// VULNERABLE: no depth or complexity limits
const { ApolloServer, gql } = require('apollo-server');
const server = new ApolloServer({
    typeDefs,
    resolvers,
    // No validationRules for depth or complexity
});

// SAFE: add depth and complexity limits
const { createComplexityLimitRule } = require('graphql-validation-complexity');
const depthLimit = require('graphql-depth-limit');
const server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules: [
        depthLimit(10),
        createComplexityLimitRule(1000),
    ],
    introspection: process.env.NODE_ENV !== 'production',
    playground: process.env.NODE_ENV !== 'production',
});
```

### GraphQL batching enabled (Apollo Server)
```javascript
// Apollo Server 4 disables batching by default, but may be re-enabled
const server = new ApolloServer({ ... });
// Express middleware with batching enabled:
app.use('/graphql', expressMiddleware(server, {
    context: ...,
}));
// If batching is on: POST /graphql with body=[query1, query2, ..., query1000]
// Each query is rate-limited separately — 1000 queries bypass per-request rate limiting
```

## REST API

### Django REST — `fields = '__all__'` exposing sensitive data
```python
# VULNERABLE: entire model exposed including sensitive fields
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        # User model has: id, username, email, password, password_hash,
        # is_staff, is_superuser, last_login, date_joined, auth_token

# What a GET /api/users/me response looks like:
# {
#   "id": 1, "username": "alice", "email": "alice@example.com",
#   "password": "pbkdf2_sha256$390000$...",  ← password hash exposed!
#   "is_staff": false, "is_superuser": false, "auth_token": "abc123"  ← token!
# }

# SAFE: explicit field allowlist
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'date_joined']
        # Never include: password, password_hash, auth_token, is_staff, is_superuser
```

### Express / Mongoose — .lean() returning full document
```javascript
// VULNERABLE: full Mongoose document returned, including password hash
router.get('/users/me', authenticate, async (req, res) => {
    const user = await User.findById(req.user.id).lean();
    res.json(user);  // includes user.password, user.__v, internal fields
});

// SAFE: use .select() to exclude sensitive fields
router.get('/users/me', authenticate, async (req, res) => {
    const user = await User.findById(req.user.id)
        .select('-password -passwordResetToken -twoFactorSecret')
        .lean();
    res.json(user);
});
```

### Missing rate limit on sensitive endpoints
```python
# Django REST — no throttle class on login view
class LoginView(APIView):
    permission_classes = [AllowAny]
    # No throttle_classes defined → no rate limiting

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            return Response({'token': user.auth_token.key})
        return Response({'error': 'Invalid credentials'}, status=401)
    # Attacker can attempt millions of passwords per minute

# SAFE: add throttle
from rest_framework.throttling import AnonRateThrottle
class LoginRateThrottle(AnonRateThrottle):
    rate = '5/minute'  # 5 attempts per minute per IP

class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]
    def post(self, request): ...
```

### Pagination without max cap
```python
# VULNERABLE: page_size is fully user-controlled
class DocumentListView(ListAPIView):
    serializer_class = DocumentSerializer

    def get_queryset(self):
        page_size = int(self.request.query_params.get('page_size', 20))
        # No cap — attacker requests page_size=1000000
        return Document.objects.all()[:page_size]

# SAFE: cap page_size
    def get_queryset(self):
        page_size = min(int(self.request.query_params.get('page_size', 20)), 100)
        return Document.objects.all()[:page_size]
```

## Webhook Security

### Webhook URL not validated — SSRF
```python
# VULNERABLE: user-supplied webhook URL is fetched by server without validation
@app.route('/api/webhooks', methods=['POST'])
@login_required
def create_webhook():
    url = request.json['url']  # http://169.254.169.254/latest/meta-data/ — SSRF!
    webhook = Webhook.objects.create(url=url, user=request.user)
    return jsonify({'id': webhook.id})

# When event fires:
def fire_webhook(webhook, payload):
    requests.post(webhook.url, json=payload)  # makes request to internal URL

# SAFE: validate URL against allowlist of schemes and block internal IPs
import ipaddress, socket
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),  # link-local/metadata
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('https',):  # https only
        return False
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return False
    except Exception:
        return False
    return True
```

### Webhook signature missing or non-constant-time
```python
# VULNERABLE: no signature verification
@app.route('/webhooks/payment', methods=['POST'])
def payment_webhook():
    data = request.json
    process_payment(data)  # processes without verifying the request is from payment provider

# VULNERABLE: string equality (timing attack)
@app.route('/webhooks/payment', methods=['POST'])
def payment_webhook():
    sig = request.headers.get('X-Payment-Signature')
    expected = hmac.new(WEBHOOK_SECRET.encode(), request.data, 'sha256').hexdigest()
    if sig == expected:  # NOT constant-time — timing attack possible
        process_payment(request.json)

# SAFE: constant-time comparison using hmac.compare_digest
import hmac, hashlib

@app.route('/webhooks/payment', methods=['POST'])
def payment_webhook():
    sig = request.headers.get('X-Payment-Signature', '')
    expected = hmac.new(WEBHOOK_SECRET.encode(), request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):  # constant-time
        return Response('Forbidden', status=403)
    process_payment(request.json)
```
