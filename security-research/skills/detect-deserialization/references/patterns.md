# Insecure Deserialization — Vulnerable Patterns by Language

## Python

### pickle — VULNERABLE
```python
import pickle
import base64
from flask import request

@app.route('/load_session', methods=['POST'])
def load_session():
    # VULNERABLE: attacker controls the serialized data
    data = base64.b64decode(request.cookies.get('session'))
    obj = pickle.loads(data)          # RCE — arbitrary code execution
    return jsonify(obj)

# Also vulnerable via indirect paths:
def restore_from_cache(user_id):
    raw = redis_client.get(f"session:{user_id}")   # if user controls cache key or value
    return pickle.loads(raw)          # HIGH — second-order deserialization
```

### pickle — SAFE ALTERNATIVE
```python
import json

@app.route('/load_session', methods=['POST'])
def load_session():
    # SAFE: use JSON (or implement a whitelist deserializer)
    data = json.loads(request.cookies.get('session'))
    return jsonify(data)
```

### yaml.load — VULNERABLE
```python
import yaml

def parse_config(user_input):
    # VULNERABLE: full YAML with Python object construction
    config = yaml.load(user_input)         # allows !!python/object/apply: os.system
    return config

# Also found in template/config upload endpoints:
def upload_pipeline(request):
    return yaml.load(request.data)         # CRITICAL if user uploads YAML
```

### yaml — SAFE ALTERNATIVE
```python
import yaml

def parse_config(user_input):
    # SAFE: SafeLoader disables Python object construction
    config = yaml.safe_load(user_input)
    # OR explicitly:
    config = yaml.load(user_input, Loader=yaml.SafeLoader)
    return config
```

### marshal — VULNERABLE (rare but exists)
```python
import marshal

def restore_bytecode(data):
    return marshal.loads(data)   # CRITICAL — can execute arbitrary Python bytecode
```

---

## Java

### ObjectInputStream — VULNERABLE
```java
// In a servlet or message handler:
@WebServlet("/api/restore")
public class RestoreServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        // VULNERABLE: raw ObjectInputStream from request body
        ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
        Object obj = ois.readObject();   // CRITICAL if gadget libs in classpath
        processObject(obj);
    }
}

// Also common in JMX, RMI, custom protocols:
ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
Object msg = ois.readObject();    // CRITICAL — network-exposed deserialization
```

### XMLDecoder — VULNERABLE
```java
// XMLDecoder deserializes Java objects from XML — almost always exploitable
XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(
    new ByteArrayInputStream(userXmlBytes)));
Object result = decoder.readObject();   // CRITICAL — RCE via Java Beans XML
```

### XStream — VULNERABLE (versions < 1.4.20 without security framework)
```java
XStream xstream = new XStream();
// VULNERABLE: no security framework configured
Object obj = xstream.fromXML(userInput);   // CRITICAL

// SAFE: apply security framework
XStream xstream = new XStream();
xstream.addPermission(NoTypePermission.NONE);
xstream.addPermission(new ExplicitTypePermission(new Class[]{MyDto.class}));
Object obj = xstream.fromXML(userInput);
```

### DocumentBuilderFactory — XXE VULNERABLE
```java
// VULNERABLE: default factory allows external entity processing
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(userXml)));  // XXE
```

### DocumentBuilderFactory — XXE SAFE
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// Disable DTD entirely (most secure)
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// Or disable external entities:
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(userXml)));
```

---

## PHP

### unserialize — VULNERABLE
```php
<?php
// VULNERABLE: attacker-controlled serialized string
$data = base64_decode($_POST['data']);
$obj = unserialize($data);   // HIGH — PHP object injection

// Cookie-based (very common in legacy PHP):
$session = unserialize(base64_decode($_COOKIE['user_session']));

// Common in caching layers:
$cached = $redis->get("user:{$_GET['id']}");
$obj = unserialize($cached);   // HIGH if user controls cache key
```

### PHP Magic Methods — POP Chain Targets
```php
<?php
// Classes with dangerous magic methods become POP chain gadgets:
class FileWriter {
    public $filename;
    public $content;

    // __destruct called when object is destroyed after unserialize()
    public function __destruct() {
        file_put_contents($this->filename, $this->content);  // arbitrary file write
    }
}

class Logger {
    public $logFile;

    public function __toString() {
        return file_get_contents($this->logFile);  // arbitrary file read
    }
}

class CommandRunner {
    public $cmd;

    public function __wakeup() {
        system($this->cmd);   // RCE immediately on unserialize()
    }
}
```

### PHP — SAFE ALTERNATIVE
```php
<?php
// Use JSON instead of serialize/unserialize for data transport
$data = json_decode($_POST['data'], true);

// If you must deserialize, use allowed_classes to whitelist:
$obj = unserialize($data, ['allowed_classes' => ['SafeClass']]);
// Note: even with allowed_classes, only allow truly safe classes with no dangerous methods
```

---

## Ruby

### Marshal.load — VULNERABLE
```ruby
# VULNERABLE: deserializing user-controlled data
class SessionController < ApplicationController
  def restore
    data = Base64.decode64(cookies[:session])
    obj = Marshal.load(data)    # CRITICAL — arbitrary Ruby object instantiation
    render json: obj
  end
end
```

### YAML.load — VULNERABLE (Psych < 4.0)
```ruby
# In Ruby < 3.1 / Psych < 4.0, YAML.load allows object instantiation
config = YAML.load(params[:config])   # HIGH — !!ruby/object injection

# SAFE in Ruby >= 3.1 (Psych >= 4.0):
config = YAML.safe_load(params[:config])
# Or explicitly:
config = YAML.load(params[:config], permitted_classes: [])
```

---

## .NET / C#

### BinaryFormatter — VULNERABLE
```csharp
// BinaryFormatter is ALWAYS dangerous with untrusted input
// Microsoft deprecated it in .NET 5+ for this reason
using System.Runtime.Serialization.Formatters.Binary;

[HttpPost("restore")]
public IActionResult Restore([FromBody] byte[] data)
{
    BinaryFormatter formatter = new BinaryFormatter();
    using var stream = new MemoryStream(data);
    var obj = formatter.Deserialize(stream);   // CRITICAL — gadget chain RCE
    return Ok(obj);
}
```

### JSON TypeNameHandling — VULNERABLE
```csharp
// TypeNameHandling.All embeds $type metadata and deserializes arbitrary types
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All   // CRITICAL
};
var obj = JsonConvert.DeserializeObject(userJson, settings);

// TypeNameHandling.Auto is also dangerous when user controls the JSON:
var settings2 = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.Auto  // HIGH — depends on data shape
};
```

### .NET — SAFE ALTERNATIVE
```csharp
// Use System.Text.Json which does not support TypeNameHandling
using System.Text.Json;
var obj = JsonSerializer.Deserialize<MyDto>(userJson);

// If Newtonsoft required: use TypeNameHandling.None (default)
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.None  // SAFE
};
```

---

## Node.js

### node-serialize — VULNERABLE
```javascript
// node-serialize allows IIFE (immediately invoked function expressions)
const serialize = require('node-serialize');

app.post('/restore', (req, res) => {
    const obj = serialize.unserialize(req.body.data);  // CRITICAL — function injection
    res.json(obj);
});
```

### serialize-javascript — VULNERABLE (in eval path)
```javascript
const serialize = require('serialize-javascript');

// VULNERABLE if the serialized output is later eval()'d:
const data = serialize(obj, { isJSON: false });
const restored = eval('(' + untrustedData + ')');  // CRITICAL
```

### Node.js — SAFE ALTERNATIVE
```javascript
// Use JSON.parse for plain data (no function support)
const obj = JSON.parse(req.body.data);

// For structured clone (Node 17+):
const { structuredClone } = require('v8');
// Never deserialize functions from untrusted input
```
