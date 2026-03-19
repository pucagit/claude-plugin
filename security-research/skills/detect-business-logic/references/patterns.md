# Business Logic Vulnerable Patterns by Domain

## Race Conditions

### VULNERABLE — Check-then-act without DB transaction (Python/Django)
```python
# VULNERABLE: two simultaneous requests can both pass the balance check
@api_view(['POST'])
def withdraw(request):
    amount = request.data['amount']
    account = Account.objects.get(user=request.user)

    if account.balance >= amount:        # check
        account.balance -= amount        # act — not atomic
        account.save()
        process_withdrawal(amount)
        return Response({'status': 'ok'})
    return Response({'error': 'insufficient funds'}, status=400)

# Attack: send two concurrent POST /withdraw?amount=100 when balance=100
# Both requests read balance=100, both pass the check, both deduct 100
# Final balance: -100
```

### SAFE — select_for_update() with transaction
```python
from django.db import transaction

@api_view(['POST'])
def withdraw(request):
    amount = request.data['amount']
    with transaction.atomic():
        # Row-level lock: second request blocks until first commits
        account = Account.objects.select_for_update().get(user=request.user)
        if account.balance >= amount:
            account.balance -= amount
            account.save()
            return Response({'status': 'ok'})
    return Response({'error': 'insufficient funds'}, status=400)
```

### VULNERABLE — Node.js/Sequelize without transaction
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

### SAFE — Sequelize with transaction + SELECT FOR UPDATE
```javascript
app.post('/redeem-coupon', async (req, res) => {
    const result = await sequelize.transaction(async (t) => {
        const coupon = await Coupon.findOne({
            where: { code: req.body.code, used: false },
            lock: t.LOCK.UPDATE,   // FOR UPDATE lock
            transaction: t
        });
        if (!coupon) throw new Error('invalid or already used coupon');
        await coupon.update({ used: true }, { transaction: t });
        await applyDiscount(req.user.id, coupon.discount, t);
    });
    res.json({ status: 'ok' });
});
```

### VULNERABLE — Go without mutex
```go
// VULNERABLE: concurrent requests race on shared balance
func Withdraw(userID string, amount float64) error {
    account, _ := db.GetAccount(userID)
    if account.Balance < amount {
        return errors.New("insufficient funds")
    }
    // Race window here
    account.Balance -= amount
    db.UpdateAccount(account)
    return nil
}
```

### SAFE — Go with database-level lock
```go
func Withdraw(userID string, amount float64) error {
    tx, _ := db.Begin()
    defer tx.Rollback()

    var balance float64
    // FOR UPDATE locks the row until transaction commits
    tx.QueryRow("SELECT balance FROM accounts WHERE id=$1 FOR UPDATE", userID).Scan(&balance)
    if balance < amount {
        return errors.New("insufficient funds")
    }
    tx.Exec("UPDATE accounts SET balance=balance-$1 WHERE id=$2", amount, userID)
    return tx.Commit()
}
```

---

## Negative Quantity Manipulation

### VULNERABLE — no floor(0) check on quantity
```python
# VULNERABLE: negative quantity increases balance
@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    product_id = request.json['product_id']
    quantity = request.json['quantity']   # attacker sends -5

    product = Product.query.get(product_id)
    # No check: quantity > 0
    cart_item = CartItem(
        product_id=product_id,
        quantity=quantity,
        price=product.price * quantity   # negative price → negative total!
    )
    db.session.add(cart_item)
    db.session.commit()
```

### SAFE — explicit validation
```python
@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    quantity = request.json['quantity']
    if not isinstance(quantity, int) or quantity <= 0:
        return jsonify({'error': 'quantity must be a positive integer'}), 400
    # ... rest of handler
```

### VULNERABLE — transfer with negative amount (balance increase)
```javascript
// VULNERABLE: negative amount transfers money from recipient to sender
app.post('/transfer', async (req, res) => {
    const { to_user_id, amount } = req.body;
    // No check: amount > 0
    await User.increment('balance', { by: -amount, where: { id: req.user.id } });
    await User.increment('balance', { by: amount, where: { id: to_user_id } });
    res.json({ ok: true });
});
// Attack: amount = -1000 → sender gains 1000, recipient loses 1000
```

---

## Workflow / State Machine Bypass

### VULNERABLE — payment step doesn't check order status
```python
# Intended flow: create_order → add_items → pay → fulfill
# VULNERABLE: /fulfill doesn't check that payment was completed

@app.route('/orders/<int:order_id>/fulfill', methods=['POST'])
def fulfill_order(order_id):
    order = Order.query.get_or_404(order_id)
    # Only checks ownership, NOT payment status
    if order.user_id != current_user.id:
        abort(403)
    # VULNERABLE: should check order.status == 'paid'
    order.status = 'fulfilled'
    db.session.commit()
    ship_order(order)   # ships without payment

# Attack: POST /orders/123/fulfill directly after order creation, skip payment
```

### SAFE — strict state machine check
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

### VULNERABLE — approval workflow bypass
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
// Attack: draft request → submit without manager approval
```

---

## Price Manipulation

### VULNERABLE — price taken from client request
```python
# VULNERABLE: server uses client-supplied price instead of DB price
@app.route('/checkout', methods=['POST'])
def checkout():
    items = request.json['items']
    # items = [{"product_id": 1, "quantity": 1, "price": 0.01}]
    total = sum(item['price'] * item['quantity'] for item in items)
    charge_user(current_user, total)   # charges $0.01 instead of real price

# SAFE: re-fetch price from DB
@app.route('/checkout', methods=['POST'])
def checkout():
    items = request.json['items']
    total = 0
    for item in items:
        product = Product.query.get(item['product_id'])
        total += product.price * item['quantity']   # use DB price, not client price
    charge_user(current_user, total)
```

### VULNERABLE — discount percentage from client
```javascript
// VULNERABLE: discount rate from client
app.post('/apply-promo', async (req, res) => {
    const { promo_code, discount_pct } = req.body;  // client controls discount_pct
    const promo = await Promo.findOne({ where: { code: promo_code } });
    if (!promo) return res.status(400).json({ error: 'invalid promo' });
    // VULNERABLE: uses client-supplied discount_pct instead of promo.discount_pct
    await applyDiscount(req.user.id, discount_pct);
});
```

---

## Coupon / Discount Abuse

### VULNERABLE — coupon not marked used (concurrent redemption)
```ruby
# VULNERABLE: race condition on coupon.used flag
def redeem_coupon(user, code)
    coupon = Coupon.find_by!(code: code)
    raise "Already used" if coupon.used

    # Race window: two requests can both pass the above check
    coupon.update!(used: true)
    discount_order(user, coupon.discount_amount)
end

# SAFE: use DB-level unique constraint + optimistic locking
def redeem_coupon(user, code)
    # update_all returns count of affected rows — 0 if already used
    updated = Coupon.where(code: code, used: false).update_all(used: true)
    raise "Invalid or already used" if updated == 0
    discount_order(user, Coupon.find_by!(code: code).discount_amount)
end
```

### VULNERABLE — coupon scoped per-user but not globally
```python
# VULNERABLE: checks if THIS user used the coupon, but allows multiple users
# to each use a "single-use" coupon
def apply_coupon(user_id, coupon_code):
    # Only checks current user's usage
    if CouponUsage.objects.filter(user_id=user_id, code=coupon_code).exists():
        raise ValueError("You've already used this coupon")
    # But coupon.max_uses is 1 and is not checked globally!
    coupon = Coupon.objects.get(code=coupon_code)
    CouponUsage.objects.create(user_id=user_id, code=coupon_code)
    return coupon.discount
```

---

## Missing Rate Limiting

### VULNERABLE — login without rate limit
```python
# VULNERABLE: no rate limiting on login → brute force possible
@app.route('/api/login', methods=['POST'])
def login():
    email = request.json['email']
    password = request.json['password']
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        return jsonify({'token': generate_token(user)})
    return jsonify({'error': 'invalid credentials'}), 401

# VULNERABLE: OTP endpoint without rate limit → can brute-force 6-digit OTP
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    otp = request.json['otp']
    if current_user.totp.verify(otp):
        return jsonify({'verified': True})
    return jsonify({'error': 'invalid OTP'}), 400
```

### SAFE — flask-limiter
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
def login():
    # ...

@app.route('/api/verify-otp', methods=['POST'])
@limiter.limit("3 per minute")   # OTP = high value target, tight limit
def verify_otp():
    # ...
```
