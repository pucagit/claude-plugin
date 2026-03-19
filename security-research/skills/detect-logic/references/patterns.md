# Logic Vulnerability Patterns

## Race Conditions

### VULNERABLE -- Check-then-act without DB transaction (Python/Django)
```python
# VULNERABLE: two simultaneous requests can both pass the balance check
@api_view(['POST'])
def withdraw(request):
    amount = request.data['amount']
    account = Account.objects.get(user=request.user)

    if account.balance >= amount:        # check
        account.balance -= amount        # act -- not atomic
        account.save()
        process_withdrawal(amount)
        return Response({'status': 'ok'})
    return Response({'error': 'insufficient funds'}, status=400)

# Attack: send two concurrent POST /withdraw?amount=100 when balance=100
# Both requests read balance=100, both pass the check, both deduct 100
# Final balance: -100
```

### SAFE -- select_for_update() with transaction
```python
from django.db import transaction

@api_view(['POST'])
def withdraw(request):
    amount = request.data['amount']
    with transaction.atomic():
        account = Account.objects.select_for_update().get(user=request.user)
        if account.balance >= amount:
            account.balance -= amount
            account.save()
            return Response({'status': 'ok'})
    return Response({'error': 'insufficient funds'}, status=400)
```

### SAFE -- atomic SQL (single statement, no race window)
```python
def purchase_atomic(user, amount):
    updated = Account.objects.filter(
        user=user, balance__gte=amount
    ).update(balance=F('balance') - amount)
    if updated == 0:
        raise InsufficientFunds()
```

### VULNERABLE -- Node.js/Sequelize without transaction
```javascript
// VULNERABLE: no transaction, no row lock
app.post('/redeem-coupon', async (req, res) => {
    const coupon = await Coupon.findOne({ where: { code: req.body.code } });
    if (!coupon || coupon.used) {
        return res.status(400).json({ error: 'invalid coupon' });
    }
    // Race window: another request can pass the above check before this runs
    await coupon.update({ used: true });
    await applyDiscount(req.user.id, coupon.discount);
    res.json({ status: 'ok' });
});
```

### SAFE -- Sequelize with transaction + SELECT FOR UPDATE
```javascript
app.post('/redeem-coupon', async (req, res) => {
    const result = await sequelize.transaction(async (t) => {
        const coupon = await Coupon.findOne({
            where: { code: req.body.code, used: false },
            lock: t.LOCK.UPDATE,
            transaction: t
        });
        if (!coupon) throw new Error('invalid or already used coupon');
        await coupon.update({ used: true }, { transaction: t });
        await applyDiscount(req.user.id, coupon.discount, t);
    });
    res.json({ status: 'ok' });
});
```

### VULNERABLE -- MongoDB non-atomic read-modify-write
```javascript
// VULNERABLE: read-modify-write outside transaction
async function redeemVoucher(userId, voucherId) {
    const voucher = await Voucher.findById(voucherId);
    if (voucher.remainingUses > 0 && !voucher.usedBy.includes(userId)) {
        voucher.remainingUses -= 1;
        voucher.usedBy.push(userId);
        await voucher.save();
        await applyDiscount(userId, voucher);
    }
}

// SAFE: findOneAndUpdate with atomic conditions
async function redeemVoucherSafe(userId, voucherId) {
    const result = await Voucher.findOneAndUpdate(
        { _id: voucherId, remainingUses: { $gt: 0 }, usedBy: { $ne: userId } },
        { $inc: { remainingUses: -1 }, $push: { usedBy: userId } },
        { new: true }
    );
    if (!result) throw new Error('Voucher not available');
    await applyDiscount(userId, result);
}
```

### VULNERABLE -- Go without mutex or DB lock
```go
// VULNERABLE: concurrent requests race on shared balance
func Withdraw(userID string, amount float64) error {
    account, _ := db.GetAccount(userID)
    if account.Balance < amount {
        return errors.New("insufficient funds")
    }
    account.Balance -= amount
    db.UpdateAccount(account)
    return nil
}

// SAFE: database-level lock
func Withdraw(userID string, amount float64) error {
    tx, _ := db.Begin()
    defer tx.Rollback()
    var balance float64
    tx.QueryRow("SELECT balance FROM accounts WHERE id=$1 FOR UPDATE", userID).Scan(&balance)
    if balance < amount {
        return errors.New("insufficient funds")
    }
    tx.Exec("UPDATE accounts SET balance=balance-$1 WHERE id=$2", amount, userID)
    return tx.Commit()
}
```

### Optimistic locking with version field
```python
# VULNERABLE: version check without retry on conflict
def purchase_with_optimistic_lock(account_id, amount):
    account = Account.objects.get(id=account_id)
    Account.objects.filter(id=account_id, version=account.version).update(
        balance=account.balance - amount,
        version=account.version + 1
    )
    # If race: update affects 0 rows, but error is silently ignored

# SAFE: check rows_updated and retry
def purchase_optimistic_safe(account_id, amount, max_retries=3):
    for attempt in range(max_retries):
        account = Account.objects.get(id=account_id)
        if account.balance < amount:
            raise InsufficientFunds()
        updated = Account.objects.filter(
            id=account_id, version=account.version
        ).update(balance=account.balance - amount, version=account.version + 1)
        if updated == 1:
            return
    raise ConcurrentModificationError("Too many retries")
```

### Go non-atomic counter (rate limiter bypass)
```go
// VULNERABLE: race condition on shared counter
type RateLimiter struct {
    count int
    limit int
}

func (r *RateLimiter) Allow() bool {
    if r.count < r.limit {
        r.count++
        return true
    }
    return false
}

// SAFE: use sync/atomic
func (r *AtomicRateLimiter) Allow() bool {
    new := atomic.AddInt64(&r.count, 1)
    if new > r.limit {
        atomic.AddInt64(&r.count, -1)
        return false
    }
    return true
}
```

---

## Workflow Bypass

### VULNERABLE -- payment step doesn't check order status
```python
# Intended flow: create_order -> add_items -> pay -> fulfill
# VULNERABLE: /fulfill doesn't check that payment was completed

@app.route('/orders/<int:order_id>/fulfill', methods=['POST'])
def fulfill_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)
    # VULNERABLE: should check order.status == 'paid'
    order.status = 'fulfilled'
    db.session.commit()
    ship_order(order)

# Attack: POST /orders/123/fulfill directly after creation, skip payment
```

### SAFE -- strict state machine check
```python
VALID_TRANSITIONS = {
    'pending': ['paid'],
    'paid': ['fulfilled'],
    'fulfilled': ['completed'],
}

@app.route('/orders/<int:order_id>/fulfill', methods=['POST'])
def fulfill_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        abort(403)
    if order.status != 'paid':
        return jsonify({'error': f'Cannot fulfill order in status {order.status}'}), 400
    order.status = 'fulfilled'
    db.session.commit()
```

### VULNERABLE -- approval workflow bypass
```javascript
// VULNERABLE: submit_for_approval doesn't check all required approvers signed off
app.post('/requests/:id/submit', async (req, res) => {
    const request = await PurchaseRequest.findByPk(req.params.id);
    if (request.status !== 'draft') return res.status(400).json({ error: 'Not a draft' });
    // VULNERABLE: should check that manager_approved === true
    request.status = 'submitted';
    await request.save();
    res.json({ ok: true });
});
```

---

## Price/Quantity Manipulation

### VULNERABLE -- negative quantity increases balance
```python
@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    product_id = request.json['product_id']
    quantity = request.json['quantity']   # attacker sends -5
    product = Product.query.get(product_id)
    cart_item = CartItem(
        product_id=product_id,
        quantity=quantity,
        price=product.price * quantity   # negative price
    )
    db.session.add(cart_item)
    db.session.commit()

# SAFE: explicit validation
@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    quantity = request.json['quantity']
    if not isinstance(quantity, int) or quantity <= 0:
        return jsonify({'error': 'quantity must be a positive integer'}), 400
```

### VULNERABLE -- transfer with negative amount
```javascript
// VULNERABLE: negative amount transfers money from recipient to sender
app.post('/transfer', async (req, res) => {
    const { to_user_id, amount } = req.body;
    await User.increment('balance', { by: -amount, where: { id: req.user.id } });
    await User.increment('balance', { by: amount, where: { id: to_user_id } });
    res.json({ ok: true });
});
// Attack: amount = -1000 -> sender gains 1000, recipient loses 1000
```

### VULNERABLE -- price taken from client request
```python
# VULNERABLE: server uses client-supplied price instead of DB price
@app.route('/checkout', methods=['POST'])
def checkout():
    items = request.json['items']
    total = sum(item['price'] * item['quantity'] for item in items)
    charge_user(current_user, total)   # charges $0.01 instead of real price

# SAFE: re-fetch price from DB
@app.route('/checkout', methods=['POST'])
def checkout():
    items = request.json['items']
    total = 0
    for item in items:
        product = Product.query.get(item['product_id'])
        total += product.price * item['quantity']
    charge_user(current_user, total)
```

### VULNERABLE -- discount percentage from client
```javascript
// VULNERABLE: discount rate from client
app.post('/apply-promo', async (req, res) => {
    const { promo_code, discount_pct } = req.body;
    const promo = await Promo.findOne({ where: { code: promo_code } });
    if (!promo) return res.status(400).json({ error: 'invalid promo' });
    // VULNERABLE: uses client-supplied discount_pct instead of promo.discount_pct
    await applyDiscount(req.user.id, discount_pct);
});
```

### Coupon scoping issue
```python
# VULNERABLE: checks if THIS user used the coupon, but allows multiple users
# to each use a "single-use" coupon
def apply_coupon(user_id, coupon_code):
    if CouponUsage.objects.filter(user_id=user_id, code=coupon_code).exists():
        raise ValueError("You've already used this coupon")
    # But coupon.max_uses is 1 and is not checked globally!
    coupon = Coupon.objects.get(code=coupon_code)
    CouponUsage.objects.create(user_id=user_id, code=coupon_code)
    return coupon.discount
```

---

## Cache Attacks

### Web cache poisoning via X-Forwarded-Host
```python
# VULNERABLE: cache key constructed using X-Forwarded-Host
def get_cache_key(request):
    host = request.headers.get('X-Forwarded-Host', request.headers.get('Host'))
    return f"page:{host}:{request.path}"

def render_page(request):
    cache_key = get_cache_key(request)
    cached = cache.get(cache_key)
    if cached:
        return cached
    host = request.headers.get('X-Forwarded-Host', request.host)
    content = render_template('page.html', base_url=f"https://{host}")
    cache.set(cache_key, content, timeout=3600)
    return content

# Attacker sends: X-Forwarded-Host: attacker.com
# Response with links pointing to attacker.com is cached for all users
```

### Web cache deception -- private response cached as public
```
# Nginx config -- VULNERABLE: caches by extension, ignoring auth
location ~* \.(css|js|png|jpg|gif)$ {
    proxy_cache static_cache;
    proxy_cache_valid 200 1d;
    add_header X-Cache $upstream_cache_status;
}

# Attack: user visits /profile/../../style.css
# Server serves profile page (auth'd content)
# Nginx caches it as a static file (due to .css extension)
# Anyone accessing /profile/../../style.css gets cached private data
```

---

## Distributed Locks

### Insufficient TTL -- lock expires before operation completes
```python
# VULNERABLE: TTL is 1 second but operation can take 5+ seconds
import redis

r = redis.Redis()

def process_payment(payment_id, amount):
    lock_key = f"payment_lock:{payment_id}"
    acquired = r.set(lock_key, "1", nx=True, ex=1)
    if not acquired:
        raise Exception("Payment in progress")
    try:
        result = payment_gateway.charge(amount)  # takes 3-10 seconds
        # Lock has expired -- another process acquired it and is also charging
        save_result(payment_id, result)
    finally:
        r.delete(lock_key)

# SAFE: TTL must exceed worst-case operation duration
def process_payment_safe(payment_id, amount):
    lock_key = f"payment_lock:{payment_id}"
    acquired = r.set(lock_key, "1", nx=True, ex=30)
    if not acquired:
        raise Exception("Payment in progress")
    try:
        result = payment_gateway.charge(amount)
        save_result(payment_id, result)
    finally:
        r.delete(lock_key)
```

### Lock not released on exception (lock leak)
```python
# VULNERABLE: exception before delete -- lock never released
def critical_section(resource_id):
    lock_key = f"lock:{resource_id}"
    r.setnx(lock_key, "1")
    r.expire(lock_key, 30)  # separate expire -- race between setnx and expire!
    process(resource_id)
    r.delete(lock_key)  # never reached on exception

# SAFE: atomic set+expire, always release in finally
def critical_section_safe(resource_id):
    lock_key = f"lock:{resource_id}"
    if not r.set(lock_key, "1", nx=True, ex=30):
        raise Exception("Resource locked")
    try:
        process(resource_id)
    finally:
        r.delete(lock_key)
```

---

## Rate Limiting

### VULNERABLE -- login without rate limit
```python
@app.route('/api/login', methods=['POST'])
def login():
    email = request.json['email']
    password = request.json['password']
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        return jsonify({'token': generate_token(user)})
    return jsonify({'error': 'invalid credentials'}), 401
```

### VULNERABLE -- OTP endpoint without rate limit
```python
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    otp = request.json['otp']
    if current_user.totp.verify(otp):
        return jsonify({'verified': True})
    return jsonify({'error': 'invalid OTP'}), 400
# Can brute-force 6-digit OTP (1,000,000 possibilities)
```

### SAFE -- flask-limiter
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
def login(): ...

@app.route('/api/verify-otp', methods=['POST'])
@limiter.limit("3 per minute")
def verify_otp(): ...
```

### Django REST -- missing throttle class
```python
# VULNERABLE: no throttle_classes defined
class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            return Response({'token': user.auth_token.key})
        return Response({'error': 'Invalid credentials'}, status=401)

# SAFE: add throttle
from rest_framework.throttling import AnonRateThrottle
class LoginRateThrottle(AnonRateThrottle):
    rate = '5/minute'

class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]
    def post(self, request): ...
```

---

## GraphQL

### Missing depth limit -- Graphene (Python)
```python
# VULNERABLE: no depth limit, exponential resolver calls
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
# No depth limit -> {user{posts{author{posts{author{...}}}}}} -> DB explosion
```

### Missing depth limit -- Apollo Server (JavaScript)
```javascript
// VULNERABLE: no depth or complexity limits
const server = new ApolloServer({
    typeDefs,
    resolvers,
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
});
```

### GraphQL batching -- rate limit bypass
```javascript
// Apollo Server with batching enabled:
// POST /graphql with body=[query1, query2, ..., query1000]
// Each query counted as a single request -- 1000 queries bypass per-request rate limiting
app.use('/graphql', expressMiddleware(server, { context: ... }));
```

---

## API Data Exposure

### Django REST -- `fields = '__all__'` exposing sensitive data
```python
# VULNERABLE: entire model exposed including sensitive fields
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        # Exposes: password hash, is_staff, is_superuser, auth_token

# SAFE: explicit field allowlist
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'date_joined']
```

### Express/Mongoose -- .lean() returning full document
```javascript
// VULNERABLE: full Mongoose document returned, including password hash
router.get('/users/me', authenticate, async (req, res) => {
    const user = await User.findById(req.user.id).lean();
    res.json(user);
});

// SAFE: use .select() to exclude sensitive fields
router.get('/users/me', authenticate, async (req, res) => {
    const user = await User.findById(req.user.id)
        .select('-password -passwordResetToken -twoFactorSecret')
        .lean();
    res.json(user);
});
```

### Pagination without max cap
```python
# VULNERABLE: page_size is fully user-controlled
class DocumentListView(ListAPIView):
    serializer_class = DocumentSerializer
    def get_queryset(self):
        page_size = int(self.request.query_params.get('page_size', 20))
        return Document.objects.all()[:page_size]

# SAFE: cap page_size
    def get_queryset(self):
        page_size = min(int(self.request.query_params.get('page_size', 20)), 100)
        return Document.objects.all()[:page_size]
```

---

## Webhooks

### Webhook URL not validated -- SSRF
```python
# VULNERABLE: user-supplied webhook URL fetched without validation
@app.route('/api/webhooks', methods=['POST'])
@login_required
def create_webhook():
    url = request.json['url']  # http://169.254.169.254/latest/meta-data/ -- SSRF!
    webhook = Webhook.objects.create(url=url, user=request.user)
    return jsonify({'id': webhook.id})

def fire_webhook(webhook, payload):
    requests.post(webhook.url, json=payload)

# SAFE: validate URL against allowlist and block internal IPs
import ipaddress, socket
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('https',):
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
    process_payment(data)  # processes without verifying source

# VULNERABLE: string equality (timing attack)
@app.route('/webhooks/payment', methods=['POST'])
def payment_webhook():
    sig = request.headers.get('X-Payment-Signature')
    expected = hmac.new(WEBHOOK_SECRET.encode(), request.data, 'sha256').hexdigest()
    if sig == expected:  # NOT constant-time
        process_payment(request.json)

# SAFE: constant-time comparison
import hmac, hashlib

@app.route('/webhooks/payment', methods=['POST'])
def payment_webhook():
    sig = request.headers.get('X-Payment-Signature', '')
    expected = hmac.new(WEBHOOK_SECRET.encode(), request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return Response('Forbidden', status=403)
    process_payment(request.json)
```
