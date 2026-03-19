# Auth & Authorization Vulnerable Patterns by Language

## IDOR / Missing Ownership Checks

### Python / Django

**Vulnerable — no ownership scope:**
```python
# views.py
class DocumentView(APIView):
    def get(self, request, doc_id):
        doc = Document.objects.get(id=doc_id)  # No user scope!
        return Response(DocumentSerializer(doc).data)

# Any authenticated user can access any document by guessing doc_id
# GET /api/documents/1337/  → returns another user's document
```

**Vulnerable — only checks login, not ownership:**
```python
@login_required
def view_invoice(request, invoice_id):
    invoice = Invoice.objects.get(pk=invoice_id)  # Missing user= filter
    return render(request, 'invoice.html', {'invoice': invoice})
```

**Safe — ownership scoped to request.user:**
```python
@login_required
def view_invoice(request, invoice_id):
    invoice = get_object_or_404(Invoice, pk=invoice_id, user=request.user)
    return render(request, 'invoice.html', {'invoice': invoice})

# Or in DRF viewsets:
class DocumentViewSet(viewsets.ModelViewSet):
    def get_queryset(self):
        return Document.objects.filter(owner=self.request.user)
```

**Safe — Django REST Framework with object-level permissions:**
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

**Vulnerable — user ID from request params, not from session:**
```javascript
// GET /api/orders/:orderId
app.get('/api/orders/:orderId', authenticate, async (req, res) => {
    const order = await Order.findById(req.params.orderId);
    // No check that order.userId === req.user.id
    res.json(order);
});
```

**Vulnerable — user ID supplied in body:**
```javascript
// PUT /api/profile/update
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

// Profile update: always use session identity, never client-supplied ID
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

**Safe — Spring method security with custom check:**
```java
@GetMapping("/api/documents/{id}")
@PreAuthorize("@documentSecurity.isOwner(#id, authentication.name)")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id)
        .orElseThrow(() -> new NotFoundException("Document not found"));
}

// DocumentSecurity.java
@Component
public class DocumentSecurity {
    @Autowired
    private DocumentRepository documentRepository;

    public boolean isOwner(Long documentId, String username) {
        return documentRepository.findById(documentId)
            .map(doc -> doc.getOwner().getUsername().equals(username))
            .orElse(false);
    }
}
```

**Safe — query scoped to current user:**
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
# app/controllers/orders_controller.rb
def show
  @order = Order.find(params[:id])  # No scope to current_user
end

def update
  @order = Order.find(params[:id])  # No ownership check
  @order.update(order_params)
end
```

**Safe — scope through current_user association:**
```ruby
def show
  @order = current_user.orders.find(params[:id])  # Raises RecordNotFound if not owned
end

def update
  @order = current_user.orders.find(params[:id])
  if @order.update(order_params)
    redirect_to @order
  else
    render :edit
  end
end
```

**Safe — Pundit policy:**
```ruby
# app/policies/order_policy.rb
class OrderPolicy < ApplicationPolicy
  def show?
    record.user == user
  end

  def update?
    record.user == user
  end
end

# controller
def show
  @order = Order.find(params[:id])
  authorize @order  # Raises Pundit::NotAuthorizedError if not owner
end
```

### Go (Gin / net/http)

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

## JWT Vulnerabilities

### Algorithm None Attack

**Vulnerable — accepts any algorithm:**
```python
# Python (PyJWT)
import jwt

def verify_token(token):
    # VULNERABLE: algorithms not restricted
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload

# Or: algorithms parameter accepts 'none'
payload = jwt.decode(token, key, algorithms=["HS256", "none"])
```

**Vulnerable — Node.js:**
```javascript
const jwt = require('jsonwebtoken');

function verifyToken(token) {
    // VULNERABLE: no algorithms restriction
    return jwt.verify(token, process.env.JWT_SECRET);
    // Accepts algorithm from token header by default in old versions
}

// Or explicitly vulnerable:
const decoded = jwt.decode(token);  // No verification at all!
```

**Safe:**
```python
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # Strict allowlist
```

```javascript
const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });
```

### RS256 to HS256 Confusion Attack

**Vulnerable — server accepts both RS256 and HS256:**
```python
payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])
# Attacker: forge JWT signed with HS256 using PUBLIC_KEY as the secret
# Set header: {"alg": "HS256"}
# Sign with: hmac-sha256(base64(header)+'.'+base64(payload), public_key_bytes)
```

**Attack in Python:**
```python
import jwt, base64

# Obtain the server's public key (from JWKS endpoint, SSL cert, etc.)
public_key = open("server_public.pem").read()

payload = {"sub": "admin", "role": "admin", "exp": 9999999999}
# Sign with public key as HMAC-SHA256 secret
forged_token = jwt.encode(payload, public_key, algorithm="HS256")
```

**Safe:**
```python
# Only accept RS256, never HS256 for public-key setups
payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
```

### Weak JWT Secret Brute-Force

**Vulnerable — hardcoded or predictable secret:**
```python
SECRET = "secret"
SECRET = "password"
SECRET = "jwt_secret"
SECRET = app.name  # Predictable
SECRET = "changeme"
```

**Detection and cracking:**
```bash
# Brute-force JWT secret with hashcat
hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
hashcat -m 16500 jwt_token.txt common-jwt-secrets.txt

# With john
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt.txt

# jwt-cracker (Node.js)
jwt-cracker -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... -d /path/to/wordlist
```

---

## Mass Assignment

### Django REST Framework

**Vulnerable — all fields writable including role:**
```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # DANGEROUS: includes is_staff, is_superuser, role

# Attacker sends: {"username": "attacker", "password": "pass", "is_staff": true}
```

**Vulnerable — explicit but too broad:**
```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'role', 'is_staff']
        # role and is_staff are writable by any authenticated user
```

**Safe — explicit allowlist excluding sensitive fields:**
```python
class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        # role, is_staff, is_superuser are not included
        read_only_fields = ['role', 'is_staff', 'is_superuser']

# Separate admin serializer for privileged operations
class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
    # Only used in admin-restricted views
```

### Ruby on Rails

**Vulnerable — strong parameters too broad:**
```ruby
def user_params
  params.require(:user).permit!  # Permits ALL parameters — never use this
end

# Or too broad:
def user_params
  params.require(:user).permit(:username, :email, :password, :role, :admin)
end
# Attacker: {"user": {"username": "a", "email": "a@b.com", "role": "admin"}}
```

**Safe:**
```ruby
def user_params
  params.require(:user).permit(:username, :email, :password)
  # role and admin deliberately excluded
end

# For admin operations, separate params method:
def admin_user_params
  params.require(:user).permit(:username, :email, :password, :role, :admin)
end
```

### Laravel / PHP

**Vulnerable — fillable too broad or guarded empty:**
```php
class User extends Model {
    protected $guarded = [];  // Allows mass assignment of all fields including role
    // Or:
    protected $fillable = ['name', 'email', 'password', 'role', 'is_admin'];
}

// Controller:
User::create($request->all());  // Passes everything from request
User::where('id', $id)->update($request->all());
```

**Safe:**
```php
class User extends Model {
    protected $fillable = ['name', 'email', 'password'];  // Only safe fields
}

// Controller: use only() to restrict
User::create($request->only(['name', 'email', 'password']));
```

### Express / Node.js (Mongoose)

**Vulnerable:**
```javascript
// Merges all request body fields directly into document
app.put('/api/users/:id', authenticate, async (req, res) => {
    await User.findByIdAndUpdate(req.user.id, req.body);  // req.body may include role: 'admin'
    res.json({ success: true });
});
```

**Safe:**
```javascript
app.put('/api/users/:id', authenticate, async (req, res) => {
    const { name, email } = req.body;  // Destructure only allowed fields
    await User.findByIdAndUpdate(req.user.id, { name, email });
    res.json({ success: true });
});
```

---

## Session Management Vulnerabilities

### Session Fixation

**Vulnerable — session not regenerated after login:**
```python
# Flask
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.form['email']).first()
    if user and user.check_password(request.form['password']):
        session['user_id'] = user.id  # Session ID unchanged from before login!
        return redirect('/')
```

**Attack:** Attacker sets victim's session ID before login (e.g., via XSS or link). After victim logs in, attacker's known session ID is now authenticated.

**Safe — regenerate session after login:**
```python
from flask import session

@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    if user:
        # Clear old session and regenerate
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

**Vulnerable — using random (not CSPRNG):**
```python
import random, string, time

def generate_reset_token():
    # VULNERABLE: random is seeded by time, predictable
    random.seed(int(time.time()))
    return ''.join(random.choices(string.ascii_letters, k=32))

# Also vulnerable:
def generate_reset_token():
    return str(random.randint(100000, 999999))  # 6-digit code, only 900000 possibilities
```

**Vulnerable — UUID v1 (time-based):**
```python
import uuid
token = str(uuid.uuid1())  # Contains MAC address and timestamp — partially predictable
```

**Safe — CSPRNG:**
```python
import secrets

def generate_reset_token():
    return secrets.token_urlsafe(32)  # 256 bits of cryptographic randomness

# With expiry:
def create_reset_token(user):
    token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(hours=1)
    ResetToken.objects.create(user=user, token=token, expires_at=expiry)
    return token
```

---

## OAuth Misbinding

**Vulnerable — missing state parameter:**
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

**Attack (CSRF on OAuth):** Attacker initiates OAuth flow, intercepts callback URL. Sends victim to callback URL with attacker's `code`. Victim's session gets bound to attacker's account.

**Safe — CSRF state parameter:**
```python
@app.route('/oauth/start')
def oauth_start():
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    return redirect(f"https://provider.com/oauth/authorize?client_id=...&state={state}")

@app.route('/oauth/callback')
def oauth_callback():
    received_state = request.args.get('state')
    if received_state != session.pop('oauth_state', None):
        abort(403)  # CSRF attack detected
    code = request.args.get('code')
    token = exchange_code_for_token(code)
    user = get_user_from_token(token)
    session['user_id'] = user.id
    return redirect('/')
```

---

## SAML Bypass

### Signature Wrapping Attack

**How it works:** SAML response contains signed assertion for legitimate user. Attacker copies the signed assertion, wraps a malicious unsigned assertion around it. Parser processes the attacker's assertion but validates the legitimate one's signature.

**Vulnerable XML structure (before attack):**
```xml
<samlp:Response>
  <saml:Assertion ID="legit">
    <saml:NameID>legit@user.com</saml:NameID>
    <ds:Signature>VALID_SIGNATURE_OVER_legit</ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

**Attacker's manipulated XML:**
```xml
<samlp:Response>
  <saml:Assertion ID="evil">
    <saml:NameID>admin@target.com</saml:NameID>
    <!-- No signature on this assertion -->
    <fakeext>
      <saml:Assertion ID="legit">
        <saml:NameID>legit@user.com</saml:NameID>
        <ds:Signature>VALID_SIGNATURE_OVER_legit</ds:Signature>
      </saml:Assertion>
    </fakeext>
  </saml:Assertion>
</samlp:Response>
```

Vulnerable SP: validates signature on `#legit`, but processes `#evil` assertion.

**Detection in code:**
```python
# Vulnerable — looks up assertion by ID after signature check
assertion_id = signature_elem.get('URI').lstrip('#')
signed_elem = doc.find(f".//*[@ID='{assertion_id}']")
verify_signature(signed_elem)  # Verifies correct element
# But then:
user = doc.findall('.//saml:NameID')[0].text  # Picks first NameID — could be evil assertion!
```

**Safe — extract user from the verified assertion element:**
```python
verified_assertion = signature_verify_and_return_element(saml_response)
user = verified_assertion.find('saml:NameID').text  # From the verified element only
```

### XML Comment Injection

```xml
<!-- Payload in username field: -->
<saml:NameID>admin<!--</saml:NameID><saml:NameID>-->@user.com</saml:NameID>
```

Different XML parsers may extract `admin` vs `admin@user.com` depending on how they handle comments inside text nodes.
