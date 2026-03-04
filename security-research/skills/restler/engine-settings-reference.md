# RESTler Engine Settings Reference

Complete schema for `engine_settings.json`.

## Connection

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `host` | string | From grammar | Target hostname (no https://) |
| `target_ip` | string | None | Override target IP |
| `target_port` | int | None | Override target port |
| `basepath` | string | From grammar | Override API basepath (e.g., "/api/v2") |
| `no_ssl` | bool | false | Disable TLS |
| `disable_cert_validation` | bool | false | Skip TLS cert validation |
| `reconnect_on_every_request` | bool | false | New connection per request |

## Authentication

```json
{
    "authentication": {
        "token": {
            "token_refresh_interval": 300,
            "location": "/path/to/token.txt",
            "token_refresh_cmd": "python3 get_token.py",
            "module": {
                "file": "/path/to/module.py",
                "function": "acquire_token",
                "data": {"key": "value"}
            }
        },
        "certificate": {
            "client_certificate_path": "/path/to/cert.pem",
            "client_certificate_key_path": "/path/to/key.pem"
        }
    }
}
```

Token output format (all methods):
```
{u'user1': {}}
Authorization: Bearer <token>
```

Multiple headers:
```
{u'user1': {}}
Authorization: Bearer <token>
X-Custom-Header: value
```

## Request Execution

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `max_request_execution_time` | float | 120 (max 600) | Response timeout (seconds) |
| `request_throttle_ms` | float | None | Delay between requests (ms) |
| `global_producer_timing_delay` | int | 0 | Wait after producer requests (seconds) |
| `max_async_resource_creation_time` | float | 20 | Async creation timeout (seconds) |

## Fuzzing

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `fuzzing_mode` | string | "bfs" | `bfs`, `bfs-cheap`, `random-walk`, `directed-smoke-test` |
| `max_sequence_length` | int | 100 | Max request chain length |
| `time_budget` | float | 168 | Fuzzing duration (hours) |
| `max_combinations` | int | 20 | Max parameter combinations per request |
| `random_seed` | int | 12345 | Seed for reproducibility |

## Request Filtering

```json
{
    "include_requests": [
        {"endpoint": "/api/users/*", "methods": ["GET", "POST"]},
        {"endpoint": "/api/admin/*"}
    ],
    "exclude_requests": [
        {"endpoint": "/api/health"},
        {"endpoint": "/api/admin/*", "methods": ["DELETE"]}
    ],
    "path_regex": "(\\w*)/api/(\\w*)"
}
```

## Garbage Collection

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `dyn_objects_cache_size` | int | 10 | Max objects per type before GC |
| `garbage_collection_interval` | int | None | Cleanup frequency (seconds) |
| `garbage_collector_cleanup_time` | int | 300 | Final cleanup duration (seconds) |

## Logging

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `disable_logging` | bool | false | Skip network logs |
| `save_results_in_fixed_dirname` | bool | false | Fixed dir name vs experiment<pid> |
| `use_trace_database` | bool | false | Structured ndjson logging |

## Per-Resource Settings

```json
{
    "per_resource_settings": {
        "/api/resource/{id}": {
            "producer_timing_delay": 5,
            "create_once": 1
        }
    }
}
```

## Security Audit Template

Recommended engine settings for security testing:

```json
{
    "host": "TARGET_HOST",
    "target_port": 8080,
    "no_ssl": true,
    "max_request_execution_time": 30,
    "request_throttle_ms": 100,
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
                "<img src=x onerror=alert(1)>",
                "${7*7}",
                "null",
                "-1",
                "0",
                "99999999"
            ]
        }
    },
    "custom_bug_codes": ["5*"],
    "authentication": {
        "token": {
            "token_refresh_interval": 300,
            "token_refresh_cmd": "python3 ${AUDIT_DIR}/scripts/get_token.py"
        }
    }
}
```
