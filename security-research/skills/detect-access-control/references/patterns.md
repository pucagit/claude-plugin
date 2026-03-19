# Access Control Vulnerable Patterns by Framework

## Django REST Framework

### BOLA — Missing queryset ownership scope
```python
# VULNERABLE: fetches any user's object
class DocumentView(RetrieveUpdateDestroyAPIView):
    queryset = Document.objects.all()  # scoped to nothing
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]
    # get_object() uses pk from URL — no ownership check

# SAFE: queryset scoped to requesting user
class DocumentView(RetrieveUpdateDestroyAPIView):
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Document.objects.filter(owner=self.request.user)
```

### BFLA — Admin endpoint with only login check
```python
# VULNERABLE: any logged-in user can delete any user
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])  # should be IsAdminUser
def delete_user(request, user_id):
    User.objects.get(id=user_id).delete()
    return Response({'deleted': True})

# SAFE
@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_user(request, user_id):
    User.objects.get(id=user_id).delete()
    return Response({'deleted': True})
```

### Mass Assignment — is_staff writeable in serializer
```python
# VULNERABLE: is_staff and is_superuser are writable
class UserUpdateSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # includes is_staff, is_superuser, password

# SAFE
class UserUpdateSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        read_only_fields = ['is_staff', 'is_superuser', 'is_active']
```

## Express / Node.js

### BOLA — Route accessing DB by :id without user check
```javascript
// VULNERABLE
router.get('/invoice/:id', authenticate, async (req, res) => {
    const invoice = await Invoice.findById(req.params.id);  // any invoice
    res.json(invoice);
});

// SAFE
router.get('/invoice/:id', authenticate, async (req, res) => {
    const invoice = await Invoice.findOne({
        _id: req.params.id,
        userId: req.user.id  // scoped to current user
    });
    if (!invoice) return res.status(404).json({ error: 'Not found' });
    res.json(invoice);
});
```

### Client-provided role in registration / update
```javascript
// VULNERABLE: role taken directly from request body
router.post('/users', authenticate, async (req, res) => {
    const user = await User.create({
        email: req.body.email,
        password: req.body.password,
        role: req.body.role,  // attacker sends "admin"
    });
    res.json(user);
});
```

## Spring Boot / Java

### BOLA — No @PreAuthorize resource ownership check
```java
// VULNERABLE: any authenticated user can access any order
@GetMapping("/orders/{id}")
@PreAuthorize("isAuthenticated()")  // only checks login, not ownership
public ResponseEntity<Order> getOrder(@PathVariable Long id) {
    Order order = orderRepository.findById(id).orElseThrow();
    return ResponseEntity.ok(order);
}

// SAFE
@GetMapping("/orders/{id}")
@PreAuthorize("isAuthenticated()")
public ResponseEntity<Order> getOrder(@PathVariable Long id, Principal principal) {
    Order order = orderRepository.findByIdAndUserEmail(id, principal.getName())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    return ResponseEntity.ok(order);
}
```

## GraphQL

### Resolver without permission check
```python
# Graphene — VULNERABLE: resolver returns any user's data
class Query(graphene.ObjectType):
    user = graphene.Field(UserType, id=graphene.Int())

    def resolve_user(self, info, id):
        return User.objects.get(id=id)  # no auth check, no ownership

# SAFE
    def resolve_user(self, info, id):
        if not info.context.user.is_authenticated:
            raise GraphQLError("Authentication required")
        if id != info.context.user.id and not info.context.user.is_staff:
            raise GraphQLError("Permission denied")
        return User.objects.get(id=id)
```

### Introspection not disabled in production
```python
# Graphene Django — VULNERABLE: introspection enabled by default
GRAPHENE = {
    'SCHEMA': 'myapp.schema.schema',
}

# SAFE — disable introspection in production
GRAPHENE = {
    'SCHEMA': 'myapp.schema.schema',
    'MIDDLEWARE': ['graphql_jwt.middleware.JSONWebTokenMiddleware'],
}
# And in views.py:
from graphene_django.views import GraphQLView
from graphql.validation import NoSchemaIntrospectionCustomRule
class PrivateGraphQLView(GraphQLView):
    def get_validation_rules(self):
        rules = super().get_validation_rules()
        if not settings.DEBUG:
            rules += (NoSchemaIntrospectionCustomRule,)
        return rules
```

## JWT Claims Trusted Without Server Re-Validation

### Role in JWT body (client-modifiable if no signature check)
```python
# VULNERABLE: role extracted from JWT payload without verifying signature
import jwt
payload = jwt.decode(token, options={"verify_signature": False})
role = payload.get('role')  # attacker crafts JWT with role=admin

# SAFE: always verify signature
payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
role = payload.get('role')
```

### Role stored in JWT vs fetched from DB
```python
# RISKY: role baked into long-lived JWT — cannot be revoked without token expiry
# If user is demoted from admin, old JWT still has role=admin until expiry

# SAFER: short-lived JWT + fetch current role from DB on each request
def get_current_user_role(user_id):
    return User.objects.get(id=user_id).role  # always fresh from DB
```
