---
name: detect-deserialization
description: Detect insecure deserialization vulnerabilities: Python pickle/yaml.load, Java ObjectInputStream gadget chains, .NET BinaryFormatter, PHP unserialize object injection, XXE via DTD, and XStream deserialization RCE. Use during Phase 3 vulnerability detection.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Insecure Deserialization Detection

## Goal
Find all places where untrusted data is passed to an unsafe deserializer, enabling remote code execution, object injection, or denial of service via crafted serialized payloads.

## Sub-Types Covered
- **Python pickle** — `pickle.loads(user_data)` enables arbitrary code execution
- **Python yaml.load** — `yaml.load(data)` without Loader=SafeLoader enables Python object instantiation
- **Java ObjectInputStream** — `readObject()` with exploitable gadget chains in classpath
- **.NET BinaryFormatter** — `Deserialize(stream)` with gadget chains
- **PHP unserialize** — `unserialize($user_input)` with PHP object injection via magic methods
- **JSON TypeNameHandling** — .NET `JsonConvert.DeserializeObject` with `TypeNameHandling.All`
- **XXE (XML External Entity)** — DTD entity expansion to read local files or SSRF
- **XStream** — Java XStream deserializing untrusted XML → RCE
- **Ruby Marshal** — `Marshal.load(user_data)` enables arbitrary code execution
- **Node.js** — `node-serialize` or `serialize-javascript` with function injection

## Grep Patterns

### Python
```bash
grep -rn "pickle\.loads(\|pickle\.load(\|yaml\.load(\|marshal\.loads(\|shelve\.open(" \
  --include="*.py" ${TARGET_SOURCE}
```

### Java
```bash
grep -rn "ObjectInputStream\|readObject()\|XMLDecoder\|XStream\|Kryo\|readResolve()\|readExternal(\|deserialize(" \
  --include="*.java" ${TARGET_SOURCE}
```

### .NET
```bash
grep -rn "BinaryFormatter\|SoapFormatter\|NetDataContractSerializer\|LosFormatter\|ObjectStateFormatter\|TypeNameHandling\|JavaScriptSerializer" \
  --include="*.cs" ${TARGET_SOURCE}
```

### PHP
```bash
grep -rn "unserialize(\|Serializable\|__wakeup\|__destruct\|__toString\|igbinary_unserialize(" \
  --include="*.php" ${TARGET_SOURCE}
```

### Ruby
```bash
grep -rn "Marshal\.load(\|YAML\.load(\|JSON\.load(" \
  --include="*.rb" ${TARGET_SOURCE}
```

### XXE (XML Parsers)
```bash
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLReader\|lxml\.etree\|xml\.etree\.ElementTree\|simplexml_load\|Nokogiri::XML\|libxml2\|DOMParser\|XMLInputFactory" \
  --include="*.java" --include="*.py" --include="*.php" --include="*.rb" \
  --include="*.js" --include="*.ts" --include="*.cs" \
  ${TARGET_SOURCE}
```

## Detection Process

1. Run grep patterns to find all deserializer call sites.
2. Trace backwards: is the input user-controlled?
   - Direct: `pickle.loads(request.data)` → CRITICAL
   - Indirect via cache: `pickle.loads(redis.get(key))` where key is user-controlled → HIGH
   - Second-order: `pickle.loads(db.query(user_id))` → HIGH
3. For Java ObjectInputStream: check classpath for known gadget library dependencies in `pom.xml` or `build.gradle`:
   - Apache Commons Collections 3.x / 4.x
   - Spring Framework
   - Groovy
   - Apache Commons BeanUtils
   - Hibernate
4. For XXE: check if parser has external entity processing disabled:
   - SAFE: `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
   - SAFE: `defusedxml.parse()`
   - VULNERABLE: `DocumentBuilderFactory.newInstance()` without feature disabling
5. Check `recon/architecture/framework_protections.md` for any global deserialization filters.

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `pickle.loads(user_input)` | CRITICAL |
| `yaml.load(data)` without `Loader=yaml.SafeLoader` | HIGH |
| `yaml.safe_load(data)` | FALSE POSITIVE |
| `ObjectInputStream` with commons-collections in classpath | CRITICAL |
| `unserialize($user_input)` in PHP | HIGH |
| `Marshal.load(request.body)` in Ruby | CRITICAL |
| `DocumentBuilderFactory.newInstance()` without feature disabling | HIGH XXE |
| `defusedxml.parse(data)` | FALSE POSITIVE |
| `TypeNameHandling.All` in JSON deserialization | HIGH |
| `TypeNameHandling.None` | FALSE POSITIVE |

## Dependency Check (Java)
```bash
# Check for gadget chain libraries in Maven/Gradle
grep -rn "commons-collections\|commons-beanutils\|spring-core\|groovy\|hibernate\|ysoserial" \
  --include="pom.xml" --include="build.gradle" --include="*.gradle" \
  ${TARGET_SOURCE}
```

## Reference Files

- [Vulnerable deserialization patterns by language](references/patterns.md)
- [Deserialization gadget payloads: ysoserial chains, PHP POP chains, pickle RCE](references/payloads.md)
- [Exploitation guide: generating payloads, XXE data exfiltration, blind deserialization](references/exploitation.md)
