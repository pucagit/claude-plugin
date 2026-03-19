# Auth & Access Control Vulnerable Patterns

## IDOR / BOLA

### Python / Django

**Vulnerable -- no ownership scope:**
```python
class DocumentView(RetrieveUpdateDestroyAPIView):
    queryset = Document.objects.all()  # scoped to nothing
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]
    # get_object() uses pk from URL -- no ownership check
```

**Vulnerable -- only checks login, not ownership:**
```python
@login_required
def view_invoice(request, invoice_id):
    invoice = Invoice.objects.get(pk=invoice_id)  # Missing user= filter
    return render(request, 'invoice.html', {'invoice': invoice})
```

**Safe -- ownership scoped to request.user:**
```python
@login_required
def view_invoice(request, invoice_id):
    invoice = get_object_or_404(Invoice, pk=invoice_id, user=request.user)
    return render(request, 'invoice.html', {'invoice': invoice})

# DRF viewset:
class DocumentViewSet(viewsets.ModelViewSet):
    def get_queryset(self):
        return Document.objects.filter(owner=self.request.user)
```

**Safe -- DRF object-level permissions:**
```python
class IsOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user

class DocumentView(RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated, IsOwner]
    queryset = Document.objects.all()
```

### Python / Flask

**Vulnerable:**
```python
@app.route('/api/profile/<int:user_id>')
@login_required
def get_profile(user_id):
    user = User.query.get(user_id)  # No check that user_id == current_user.id
    return jsonify(user.to_dict())
```

**Safe:**
```python
@app.route('/api/profile/<int:user_id>')
@login_required
def get_profile(user_id):
    if user_id != current_user.id and not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())
```

### Express / Node.js

**Vulnerable -- user ID from params, not session:**
```javascript
app.get('/api/orders/:orderId', authenticate, async (req, res) => {
    const order = await Order.findById(req.params.orderId);
    // No check that order.userId === req.user.id
    res.json(order);
});
```

**Vulnerable -- user ID supplied in body:**
```javascript
app.put('/api/profile/update', authenticate, async (req, res) => {
    const { userId, name, email } = req.body;  // userId from client!
    await User.findByIdAndUpdate(userId, { name, email });
    res.json({ success: true });
});
```

**Safe:**
```javascript
app.get('/api/orders/:orderId', authenticate, async (req, res) => {
    const order = await Order.findOne({
        _id: req.params.orderId,
        userId: req.user.id  // Scoped to authenticated user
    });
    if (!order) return res.status(404).json({ error: 'Not found' });
    res.json(order);
});

// Profile update: always use session identity
app.put('/api/profile', authenticate, async (req, res) => {
    const { name, email } = req.body;
    await User.findByIdAndUpdate(req.user.id, { name, email });
    res.json({ success: true });
});
```

### Java / Spring Boot

**Vulnerable:**
```java
@GetMapping("/api/documents/{id}")
@PreAuthorize("isAuthenticated()")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id)
        .orElseThrow(() -> new NotFoundException("Document not found"));
    // No ownership check!
}
```

**Safe -- Spring method security with custom check:**
```java
@GetMapping("/api/documents/{id}")
@PreAuthorize("@documentSecurity.isOwner(#id, authentication.name)")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id)
        .orElseThrow(() -> new NotFoundException("Document not found"));
}

@Component
public class DocumentSecurity {
    @Autowired private DocumentRepository documentRepository;
    public boolean isOwner(Long documentId, String username) {
        return documentRepository.findById(documentId)
            .map(doc -> doc.getOwner().getUsername().equals(username))
            .orElse(false);
    }
}
```

**Safe -- query scoped to current user:**
```java
@GetMapping("/api/documents/{id}")
public Document getDocument(@PathVariable Long id, @AuthenticationPrincipal UserDetails user) {
    return documentRepository.findByIdAndOwnerUsername(id, user.getUsername())
        .orElseThrow(() -> new AccessDeniedException("Access denied"));
}
```

### Ruby on Rails

**Vulnerable:**
```ruby
def show
  @order = Order.find(params[:id])  # No scope to current_user
end
```

**Safe -- scope through current_user:**
```ruby
def show
  @order = current_user.orders.find(params[:id])  # Raises RecordNotFound if not owned
end
```

**Safe -- Pundit policy:**
```ruby
class OrderPolicy < ApplicationPolicy
  def show?
    record.user == user
  end
end

# Controller:
def show
  @order = Order.find(params[:id])
  authorize @order  # Raises Pundit::NotAuthorizedError if not owner
end
```

### Go (Gin)

**Vulnerable:**
```go
func GetDocument(c *gin.Context) {
    docID := c.Param("id")
    var doc Document
    db.First(&doc, docID)  // No user ownership scope
    c.JSON(200, doc)
}
```

**Safe:**
```go
func GetDocument(c *gin.Context) {
    docID := c.Param("id")
    userID := c.GetUint("userID")  // From JWT middleware
    var doc Document
    result := db.Where("id = ? AND user_id = ?", docID, userID).First(&doc)
    if result.Error != nil {
        c.JSON(404, gin.H{"error": "not found"})
        return
    }
    c.JSON(200, doc)
}
```

---

## BFLA (Broken Function Level Authorization)

### Django REST Framework

**Vulnerable -- admin endpoint with only login check:**
```python
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])  # should be IsAdminUser
def delete_user(request, user_id):
    User.objects.get(id=user_id).delete()
    return Response({'deleted': True})
```

**Safe:**
```python
@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_user(request, user_id):
    User.objects.get(id=user_id).delete()
    return Response({'deleted': True})
```

---

## Privilege Escalation

### Vertical -- Admin Endpoint Discovery

```bash
# Common admin paths to test with low-privilege session
curl -s https://target.com/admin/ -H "Cookie: session=user_session" -o /dev/null -w "%{http_code}"
curl -s https://target.com/api/admin/users -H "Cookie: session=user_session" -o /dev/null -w "%{http_code}"
curl -s https://target.com/api/v1/admin/ -H "Cookie: session=user_session" -o /dev/null -w "%{http_code}"
curl -s https://target.com/management/ -H "Cookie: session=user_session" -o /dev/null -w "%{http_code}"

# Try different HTTP methods
curl -X DELETE "https://target.com/api/users/1" -H "Cookie: session=user_session"
curl -X PUT "https://target.com/api/config/setting" -H "Cookie: session=user_session" -d '{"value": "x"}'
```

### Response Manipulation (MFA Bypass)

```bash
# Intercept MFA response and modify:
# Change: {"status": "mfa_required", "next": "/mfa"}
# To:     {"status": "success", "next": "/dashboard", "token": "..."}

# Or intercept MFA submission response:
# Change: HTTP 403 to HTTP 200
# Change: {"success": false} to {"success": true}
```

### Step-Skip (Forced Browsing)

```bash
# Multi-step flow: /login -> /mfa -> /dashboard
# Try accessing /dashboard directly after /login (before /mfa)
curl "https://target.com/dashboard" -H "Cookie: session=SESSION_AFTER_PASSWORD_ONLY"
```

---

## JWT Issues

### Algorithm None Attack

**Vulnerable -- accepts any algorithm:**
```python
# Python (PyJWT)
payload = jwt.decode(token, options={"verify_signature": False})

# Or: algorithms parameter accepts 'none'
payload = jwt.decode(token, key, algorithms=["HS256", "none"])
```

**Vulnerable -- Node.js:**
```javascript
// No algorithms restriction
return jwt.verify(token, process.env.JWT_SECRET);

// Or no verification at all:
const decoded = jwt.decode(token);
```

**Safe:**
```python
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # Strict allowlist
```
```javascript
const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });
```

### RS256 to HS256 Confusion Attack

**Vulnerable -- server accepts both RS256 and HS256:**
```python
payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])
# Attacker: forge JWT signed with HS256 using PUBLIC_KEY as the secret
```

**Safe:**
```python
payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
```

### Weak JWT Secret

**Vulnerable -- hardcoded or predictable:**
```python
SECRET = "secret"
SECRET = "password"
SECRET = "changeme"
SECRET = app.name  # Predictable
```

**Detection:**
```bash
hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt.txt
```

### Role in JWT Trusted Without Re-Validation

**Vulnerable -- role extracted without signature verification:**
```python
payload = jwt.decode(token, options={"verify_signature": False})
role = payload.get('role')  # attacker crafts JWT with role=admin
```

**Risky -- role baked into long-lived JWT:**
```python
# If user is demoted from admin, old JWT still has role=admin until expiry
```

**Safer -- short-lived JWT + fetch current role from DB:**
```python
def get_current_user_role(user_id):
    return User.objects.get(id=user_id).role  # always fresh from DB
```

---

## Session Management

### Session Fixation

**Vulnerable -- session not regenerated after login:**
```python
# Flask
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.form['email']).first()
    if user and user.check_password(request.form['password']):
        session['user_id'] = user.id  # Session ID unchanged from before login!
        return redirect('/')
```

**Safe -- regenerate session:**
```python
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    if user:
        session.clear()
        session['user_id'] = user.id
        session.permanent = True
        return redirect('/')
```

**Express.js:**
```javascript
app.post('/login', (req, res) => {
    const user = authenticate(req.body);
    if (user) {
        req.session.regenerate((err) => {  // Regenerate session ID
            req.session.userId = user.id;
            res.redirect('/');
        });
    }
});
```

### Predictable Reset Tokens

**Vulnerable -- using random (not CSPRNG):**
```python
import random, time
random.seed(int(time.time()))
return ''.join(random.choices(string.ascii_letters, k=32))

# Also vulnerable:
return str(random.randint(100000, 999999))  # Only 900000 possibilities
```

**Vulnerable -- UUID v1 (time-based):**
```python
token = str(uuid.uuid1())  # Contains MAC address and timestamp
```

**Safe -- CSPRNG:**
```python
import secrets
def generate_reset_token():
    return secrets.token_urlsafe(32)  # 256 bits of cryptographic randomness
```

---

## OAuth / SAML

### OAuth CSRF (Missing State Parameter)

**Vulnerable:**
```python
@app.route('/oauth/callback')
def oauth_callback():
    code = request.args.get('code')
    # No state validation!
    token = exchange_code_for_token(code)
    user = get_user_from_token(token)
    session['user_id'] = user.id
    return redirect('/')
```

**Safe -- CSRF state parameter:**
```python
@app.route('/oauth/start')
def oauth_start():
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    return redirect(f"https://provider.com/oauth/authorize?client_id=...&state={state}")

@app.route('/oauth/callback')
def oauth_callback():
    if request.args.get('state') != session.pop('oauth_state', None):
        abort(403)
    code = request.args.get('code')
    token = exchange_code_for_token(code)
    user = get_user_from_token(token)
    session['user_id'] = user.id
    return redirect('/')
```

### Open Redirect in redirect_uri

```bash
# Bypass redirect_uri validation
redirect_uri=https://legit-app.com/callback?next=https://evil.com
redirect_uri=https://legit-app.com/../../evil.com/callback
redirect_uri=https://evil.legit-app.com/callback
redirect_uri=https://legit-app.com.evil.com/callback
```

### Account Takeover via OAuth Email Misbinding

Provider allows unverified emails. Attacker registers on provider with victim's email (unverified). OAuth login links to victim's account because email matches without verifying email confirmation on provider side.

### SAML Signature Wrapping Attack

**Attacker's manipulated XML:**
```xml
<samlp:Response>
  <saml:Assertion ID="evil">
    <saml:NameID>admin@target.com</saml:NameID>
    <fakeext>
      <saml:Assertion ID="legit">
        <saml:NameID>legit@user.com</saml:NameID>
        <ds:Signature>VALID_SIGNATURE_OVER_legit</ds:Signature>
      </saml:Assertion>
    </fakeext>
  </saml:Assertion>
</samlp:Response>
```

Vulnerable SP validates signature on `#legit` but processes `#evil` assertion.

**Vulnerable detection in code:**
```python
# Verifies correct element...
signed_elem = doc.find(f".//*[@ID='{assertion_id}']")
verify_signature(signed_elem)
# ...but then picks first NameID which could be evil assertion
user = doc.findall('.//saml:NameID')[0].text
```

**Safe -- extract user from verified assertion only:**
```python
verified_assertion = signature_verify_and_return_element(saml_response)
user = verified_assertion.find('saml:NameID').text
```

### SAML XML Comment Injection

```xml
<saml:NameID>admin<!--</saml:NameID><saml:NameID>-->@user.com</saml:NameID>
```

Different parsers may extract `admin` vs `admin@user.com` depending on comment handling.

---

## Mass Assignment

### Django REST Framework

**Vulnerable:**
```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # includes is_staff, is_superuser, role
```

**Safe:**
```python
class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        read_only_fields = ['is_staff', 'is_superuser', 'is_active']
```

### Ruby on Rails

**Vulnerable:**
```ruby
def user_params
  params.require(:user).permit!  # Permits ALL parameters
end
```

**Safe:**
```ruby
def user_params
  params.require(:user).permit(:username, :email, :password)
  # role and admin deliberately excluded
end
```

### Laravel / PHP

**Vulnerable:**
```php
class User extends Model {
    protected $guarded = [];  // Allows mass assignment of all fields
}
User::create($request->all());
```

**Safe:**
```php
class User extends Model {
    protected $fillable = ['name', 'email', 'password'];
}
User::create($request->only(['name', 'email', 'password']));
```

### Express / Node.js (Mongoose)

**Vulnerable:**
```javascript
await User.findByIdAndUpdate(req.user.id, req.body);  // req.body may include role: 'admin'
```

**Safe:**
```javascript
const { name, email } = req.body;  // Destructure only allowed fields
await User.findByIdAndUpdate(req.user.id, { name, email });
```

---

## Multi-Tenant

### Client-Provided org_id / Tenant Bypass in JWT

JWT contains `{"user_id": 123, "org_id": 456}` and server uses `org_id` from JWT to scope queries.

**Exploit:** If JWT is signed with a weak secret, crack it and forge a token with a different `org_id`:
```python
import jwt
payload = {"user_id": 123, "org_id": 1, "role": "admin"}  # org_id 1 = target org
token = jwt.encode(payload, "discovered_secret", algorithm="HS256")
```

### Multi-Tenant Bypass via Mass Assignment

```bash
# Attempt to move your account to a different organization
curl -X PATCH https://target.com/api/users/me \
    -H 'Authorization: Bearer USER_TOKEN' \
    -H 'Content-Type: application/json' \
    -d '{"organization_id": 1, "org_id": 1, "tenant_id": 1}'
```

### Second-Order Mass Assignment

```bash
# Step 1: Update profile with nested org_id (appears harmless)
PATCH /api/users/me
{"name": "Attacker", "org_id": 1337}

# Step 2: Subsequent requests now operate in context of org 1337
GET /api/org/documents  # Returns documents from org 1337
```

---

## GraphQL Access Control

### Resolver Without Permission Check

```python
# Graphene -- VULNERABLE
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

### Introspection Not Disabled in Production

**Vulnerable -- introspection enabled by default:**
```python
GRAPHENE = {
    'SCHEMA': 'myapp.schema.schema',
}
```

**Safe -- disable introspection in production:**
```python
from graphene_django.views import GraphQLView
from graphql.validation import NoSchemaIntrospectionCustomRule

class PrivateGraphQLView(GraphQLView):
    def get_validation_rules(self):
        rules = super().get_validation_rules()
        if not settings.DEBUG:
            rules += (NoSchemaIntrospectionCustomRule,)
        return rules
```
