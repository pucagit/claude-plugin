# SSRF Vulnerable Patterns by Language and Framework

## Direct URL Fetch with User Input

### Python (requests / httpx / urllib)

**Vulnerable — direct user URL passed to requests:**
```python
# Flask endpoint
@app.route('/preview')
def preview_url():
    url = request.args.get('url')
    resp = requests.get(url)  # CRITICAL SSRF — no validation
    return resp.text

# Common legitimate-looking features that hide SSRF:
@app.route('/api/fetch-metadata')
def fetch_metadata():
    target_url = request.json.get('url')
    response = requests.get(target_url, timeout=5)
    return jsonify({'title': extract_title(response.text)})

# Screenshot/thumbnail service
@app.route('/screenshot')
def screenshot():
    url = request.args.get('page_url')
    result = subprocess.run(['chromium', '--headless', '--screenshot', url])
    return send_file('screenshot.png')

# File download by URL
@app.route('/import')
def import_from_url():
    source_url = request.form.get('source')
    data = urllib.request.urlopen(source_url).read()  # SSRF
    return process_data(data)

# Webhook test/ping feature
@app.route('/webhook/test', methods=['POST'])
def test_webhook():
    webhook_url = request.json.get('url')
    requests.post(webhook_url, json={'test': True})  # SSRF via webhook
    return jsonify({'status': 'sent'})
```

**Vulnerable — indirect SSRF via stored URL:**
```python
@app.route('/webhooks', methods=['POST'])
def create_webhook():
    url = request.json.get('url')
    Webhook.objects.create(url=url, user=request.user)  # URL stored
    return jsonify({'id': webhook.id})

# Triggered later — SSRF via stored webhook
def trigger_webhook(webhook_id, event_data):
    webhook = Webhook.objects.get(id=webhook_id)
    requests.post(webhook.url, json=event_data)  # SSRF here
```

**Vulnerable — weak URL validation (blocklist bypass):**
```python
def fetch_url(url):
    # WEAK VALIDATION — many bypasses exist
    blocked = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254']
    parsed = urlparse(url)
    if any(b in parsed.netloc for b in blocked):
        raise ValueError("URL not allowed")
    # But: http://0177.0.0.1/ still works (octal)
    # And: http://[::1]/ still works (IPv6)
    # And: http://2130706433/ still works (decimal IP)
    # And: http://attacker.com redirect to 127.0.0.1 works (open redirect)
    return requests.get(url)
```

**Safe — strict allowlist validation:**
```python
import ipaddress
from urllib.parse import urlparse
import socket

ALLOWED_SCHEMES = {'https', 'http'}
ALLOWED_DOMAINS = {'api.trusted-partner.com', 'cdn.trusted-service.com'}

def safe_fetch(url: str) -> requests.Response:
    parsed = urlparse(url)

    # Check scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme not allowed: {parsed.scheme}")

    # Check hostname against allowlist
    hostname = parsed.hostname
    if hostname not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain not in allowlist: {hostname}")

    # Resolve hostname and check it's not internal
    try:
        ip = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise ValueError(f"Resolved to private IP: {ip}")
    except socket.gaierror:
        raise ValueError("DNS resolution failed")

    # Make request without redirects (prevents redirect-based bypass)
    return requests.get(url, allow_redirects=False, timeout=5)
```

### Node.js / Express

**Vulnerable:**
```javascript
// Proxy/fetch endpoint
app.get('/api/proxy', async (req, res) => {
    const { url } = req.query;
    const response = await axios.get(url);  // SSRF
    res.send(response.data);
});

// Link preview feature
app.post('/api/preview-link', async (req, res) => {
    const { url } = req.body;
    const html = await fetch(url).then(r => r.text());  // SSRF
    const title = extractTitle(html);
    res.json({ title });
});

// Payment callback verification (common pattern)
app.post('/payment/ipn', async (req, res) => {
    const { verify_url } = req.body;
    const verified = await axios.get(verify_url);  // SSRF via payment IPN
    processPayment(verified.data);
});
```

**Vulnerable — URL validation bypass:**
```javascript
function isUrlAllowed(url) {
    const parsed = new URL(url);
    // Weak: only checks hostname contains allowed domain
    return parsed.hostname.includes('allowed-api.com');
    // Bypass: http://evil.com@allowed-api.com/  → hostname = "allowed-api.com"
    //         The @ makes allowed-api.com the path authority!
}
```

### Java / Spring Boot

**Vulnerable — RestTemplate with user URL:**
```java
@GetMapping("/fetch")
public String fetchContent(@RequestParam String url) {
    RestTemplate restTemplate = new RestTemplate();
    return restTemplate.getForObject(url, String.class);  // SSRF
}

// WebClient (reactive):
@GetMapping("/preview")
public Mono<String> preview(@RequestParam String url) {
    return WebClient.create(url).get().retrieve().bodyToMono(String.class);  // SSRF
}

// Vulnerable — OkHttp
@PostMapping("/webhook/test")
public ResponseEntity<?> testWebhook(@RequestBody Map<String, String> body) {
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder().url(body.get("url")).build();  // SSRF
    client.newCall(request).execute();
    return ResponseEntity.ok().build();
}
```

### Go

**Vulnerable:**
```go
func FetchHandler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    resp, err := http.Get(url)  // SSRF
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    io.Copy(w, resp.Body)
}

// Vulnerable — net/http with user URL
func proxyRequest(targetURL string) (*http.Response, error) {
    return http.DefaultClient.Get(targetURL)  // SSRF
}
```

### PHP

**Vulnerable:**
```php
// file_get_contents with user URL
$url = $_GET['url'];
$content = file_get_contents($url);  // SSRF — also supports file://, ftp://
echo $content;

// curl with user URL
$url = $_POST['webhook_url'];
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$result = curl_exec($ch);  // SSRF

// include() with URL (allow_url_include=On — rare but exists)
include($_GET['page'] . '.php');  // Also potential file:// SSRF

// Vulnerable — image processing with user URL
$url = $_GET['image_url'];
$image = imagecreatefromjpeg($url);  // PHP GD can fetch remote URLs!
```

**Vulnerable — PHP filter bypass for file://:**
```php
// Some apps use FILTER_VALIDATE_URL but still allow file://
$url = filter_var($_GET['url'], FILTER_VALIDATE_URL);
// file:///etc/passwd passes FILTER_VALIDATE_URL!
$content = file_get_contents($url);
```

---

## Document Rendering Engines (High-Severity SSRF)

### wkhtmltopdf / pdfkit

**Vulnerable — user HTML rendered to PDF:**
```python
import pdfkit

@app.route('/export/pdf', methods=['POST'])
def export_pdf():
    html_content = request.json.get('html')
    # User controls HTML — can include <iframe src="file:///etc/passwd">
    # Or: <iframe src="http://169.254.169.254/latest/meta-data/">
    pdf = pdfkit.from_string(html_content, False)
    return send_file(BytesIO(pdf), mimetype='application/pdf')
```

**Vulnerable — user URL rendered:**
```python
@app.route('/pdf')
def generate_pdf():
    url = request.args.get('url')
    # wkhtmltopdf fetches the URL — SSRF if user-controlled
    pdf = pdfkit.from_url(url, False)
    return send_file(BytesIO(pdf), mimetype='application/pdf')
```

**Vulnerable — user-supplied HTML in wkhtmltopdf script tag:**
```html
<!-- In user-supplied HTML content: -->
<script>
    // wkhtmltopdf executes JavaScript
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", false);
    xhr.send();
    document.write(xhr.responseText);
</script>
```

### Puppeteer / Playwright

**Vulnerable — URL navigation with user input:**
```javascript
const puppeteer = require('puppeteer');

app.post('/screenshot', async (req, res) => {
    const { url } = req.body;
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.goto(url);  // SSRF — can navigate to file://, http://internal/
    const screenshot = await page.screenshot();
    res.send(screenshot);
});
```

### ImageMagick

**Vulnerable — processing user-uploaded files:**
```python
import subprocess

@app.route('/convert', methods=['POST'])
def convert_image():
    file = request.files['image']
    input_path = f"/tmp/{secure_filename(file.filename)}"
    file.save(input_path)

    # ImageMagick can fetch remote URLs from file content (SVG, etc.)
    subprocess.run(['convert', input_path, 'output.png'])
    # If input_path is an SVG with: <image href="http://169.254.169.254/..."/>
    # ImageMagick fetches it!
```

---

## XML / SVG Processing (SSRF via XXE)

### Python (lxml / ElementTree)

**Vulnerable — lxml without DTD restriction:**
```python
from lxml import etree

@app.route('/process-xml', methods=['POST'])
def process_xml():
    xml_data = request.data
    # lxml resolves external entities by default!
    root = etree.fromstring(xml_data)  # SSRF if XML contains ENTITY referencing URL
    return etree.tostring(root)
```

**Vulnerable — SVG upload processed server-side:**
```python
from lxml import etree

@app.route('/upload', methods=['POST'])
def upload_svg():
    svg_file = request.files['file']
    if svg_file.filename.endswith('.svg'):
        svg_data = svg_file.read()
        # Processing SVG that may contain external references
        doc = etree.fromstring(svg_data)  # External entity fetch!
        # Or rendering it: subprocess.run(['inkscape', '--export-png', svg_path])
```

**Safe — disable external entity resolution:**
```python
from lxml import etree

def safe_parse_xml(xml_data: bytes):
    parser = etree.XMLParser(
        resolve_entities=False,    # Disable entity resolution
        no_network=True,           # No network access
        load_dtd=False,            # Don't load external DTDs
        forbid_dtd=True            # Raise error if DTD found
    )
    return etree.fromstring(xml_data, parser=parser)
```

---

## URL Validation Anti-Patterns

### Hostname-Only Check (DNS Rebinding Bypass)

```python
# Vulnerable — checks hostname but only once at request time
def validate_url(url):
    hostname = urlparse(url).hostname
    ip = socket.gethostbyname(hostname)  # DNS lookup #1 (returns 1.2.3.4)
    if ipaddress.ip_address(ip).is_private:
        raise ValueError("Private IP not allowed")
    # DNS may have changed by now! (DNS rebinding)
    response = requests.get(url)  # DNS lookup #2 (now returns 127.0.0.1!)
    return response
```

**Attack with DNS rebinding:**
1. Attacker sets up `evil.com` with very low TTL (0-1 second)
2. First DNS lookup: `evil.com` → `1.2.3.4` (public IP — passes check)
3. Attacker changes DNS: `evil.com` → `127.0.0.1`
4. Second DNS lookup (at request time): `evil.com` → `127.0.0.1`
5. Server makes HTTP request to `127.0.0.1`!

**Safe — resolve, validate, then connect to the IP directly:**
```python
import socket, ipaddress, requests
from urllib.parse import urlparse

def safe_fetch(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname

    # Resolve and validate
    ip = socket.gethostbyname(hostname)
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        raise ValueError(f"Resolved to private IP: {ip}")

    # Replace hostname with resolved IP to prevent DNS rebinding
    # (Connect to the IP we validated, not re-resolving the hostname)
    safe_url = url.replace(hostname, ip, 1)
    return requests.get(safe_url, headers={'Host': hostname},
                        allow_redirects=False, timeout=5).text
```

### Blocklist Bypass Patterns

```python
# Vulnerable — only blocks exact strings
BLOCKED = ['localhost', '127.0.0.1', '169.254.169.254']

def is_blocked(url):
    return any(b in url for b in BLOCKED)

# All of these bypass this check:
# http://0.0.0.0/           (points to localhost on many systems)
# http://[::1]/             (IPv6 loopback)
# http://[::ffff:127.0.0.1]/ (IPv4-mapped IPv6)
# http://2130706433/        (decimal representation of 127.0.0.1)
# http://0x7f000001/        (hex representation)
# http://017700000001/      (octal representation)
# http://127.000.000.001/   (padded octets)
# http://spoofed.attacker.com/ (DNS resolves to 127.0.0.1)
```
