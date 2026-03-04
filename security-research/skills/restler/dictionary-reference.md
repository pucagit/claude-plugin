# RESTler Fuzzing Dictionary Reference

## Dictionary Schema (`dict.json`)

### Fuzzable Data Types

Each field is an array of values cycled during fuzzing:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `restler_fuzzable_string` | string[] | `["fuzzstring"]` | String parameters |
| `restler_fuzzable_int` | string[] | `["1"]` | Integer parameters |
| `restler_fuzzable_bool` | string[] | `["true"]` | Boolean parameters |
| `restler_fuzzable_datetime` | string[] | `["2019-06-26T20:20:39+00:00"]` | Datetime parameters |
| `restler_fuzzable_number` | string[] | `["1.23"]` | Float parameters |
| `restler_fuzzable_object` | string[] | `["{}"]` | Object parameters |
| `restler_fuzzable_uuid4` | string[] | `["566048da-..."]` | UUID parameters |

### Custom Payloads

```json
{
    "restler_custom_payload": {
        "api-version": ["2024-01-01"],
        "paramName": ["value1", "value2"]
    },
    "restler_custom_payload_header": {
        "X-Custom-Header": ["value"]
    },
    "restler_custom_payload_query": {
        "queryParam": ["value1", "value2"]
    },
    "restler_custom_payload_uuid4_suffix": {
        "resourceName": ["test-prefix-"]
    }
}
```

### Body Replacement

Replace entire request body for specific endpoint/method:

```json
{
    "restler_custom_payload": {
        "/api/resource/{id}/put/__body__": ["custom body content"],
        "/api/resource/{id}/put/Content-Type": ["xml"]
    }
}
```

## Security Audit Dictionary Template

Inject attack payloads for vulnerability discovery:

```json
{
    "restler_fuzzable_string": [
        "fuzzstring",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1; DROP TABLE users--",
        "1 UNION SELECT null,null,null--",
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(1)>",
        "{{7*7}}",
        "${7*7}",
        "<%=7*7%>",
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "; cat /etc/passwd",
        "| ls -la",
        "$(whoami)",
        "`whoami`",
        "{\"$gt\":\"\"}",
        "{\"$ne\":null}",
        "{\"__proto__\":{\"admin\":true}}",
        "null",
        "undefined",
        "",
        "true",
        "false",
        "-1",
        "0",
        "99999999999",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ],
    "restler_fuzzable_int": [
        "1",
        "0",
        "-1",
        "99999999",
        "-99999999",
        "2147483647",
        "-2147483648",
        "9999999999999999999"
    ],
    "restler_fuzzable_number": [
        "1.23",
        "0",
        "-1.0",
        "999999999.99",
        "0.0000001",
        "NaN",
        "Infinity",
        "-Infinity"
    ],
    "restler_fuzzable_bool": [
        "true",
        "false",
        "1",
        "0",
        "null"
    ],
    "restler_fuzzable_object": [
        "{}",
        "null",
        "[]",
        "{\"admin\":true}",
        "{\"role\":\"admin\"}",
        "{\"__proto__\":{\"isAdmin\":true}}"
    ],
    "restler_custom_payload": {},
    "restler_custom_payload_header": {},
    "restler_custom_payload_query": {},
    "restler_custom_payload_uuid4_suffix": {}
}
```

## Dictionary Workflow

1. **Compile** → generates `dict.json` with defaults
2. **Copy** the generated dict for customization
3. **Add attack payloads** to fuzzable type arrays
4. **Add custom payloads** for target-specific magic values (API keys, versions)
5. **Value-only changes**: Use modified dict directly at test/fuzz time (no recompile)
6. **New property additions**: Set `CustomDictionaryFilePath` in `config.json`, then recompile

## IDOR Testing Payloads

For testing authorization boundary with InvalidDynamicObjectChecker:

```json
{
    "checkers": {
        "invaliddynamicobject": {
            "invalid_objects": [
                "1",
                "2",
                "admin",
                "00000000-0000-0000-0000-000000000000",
                "../../private_resource",
                "other_user_id"
            ]
        }
    }
}
```
