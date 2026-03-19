# Semgrep Rule Syntax Reference

## Rule YAML Schema

```yaml
rules:
  - id: unique-rule-identifier         # Required: unique ID
    message: >-                         # Required: description + remediation
      What was found and how to fix it.
    severity: ERROR                     # Required: ERROR, WARNING, INFO
    languages: [python]                 # Required: target language(s)
    metadata:                           # Optional: CWE, OWASP, etc.
      cwe: CWE-XXX
      owasp: "A0X:2021"
      confidence: HIGH
      category: security

    # === Choose ONE top-level pattern approach ===

    # Option 1: Simple pattern match
    pattern: dangerous_function($USER_INPUT)

    # Option 2: AND logic — all patterns must match
    patterns:
      - pattern: dangerous_function($INPUT)
      - pattern-not: dangerous_function(sanitize($INPUT))
      - pattern-inside: |
          def $FUNC(...):
              ...

    # Option 3: OR logic — any pattern matches
    pattern-either:
      - pattern: eval($X)
      - pattern: exec($X)

    # Option 4: Regex matching (PCRE2, multiline mode)
    pattern-regex: 'password\s*=\s*["\'][^"\']+["\']'

    # === Optional: file filtering ===
    paths:
      include: ["src/**"]
      exclude: ["*_test.*", "vendor/**"]

    # === Optional: autofix ===
    fix: $DICT.get($KEY)
```

## Pattern Operators

### Core Patterns

| Operator | Logic | Purpose |
|---|---|---|
| `pattern` | — | Match code directly |
| `patterns` | AND | All sub-patterns must match |
| `pattern-either` | OR | Any sub-pattern can match |
| `pattern-not` | NOT | Exclude matches |
| `pattern-inside` | SCOPE | Match only within enclosing context |
| `pattern-not-inside` | !SCOPE | Match only outside context |
| `pattern-regex` | REGEX | PCRE2 regex on code text |
| `pattern-not-regex` | !REGEX | Exclude regex matches |

### Metavariable Operators

**`metavariable-regex`** — filter by regex on captured value:
```yaml
metavariable-regex:
  metavariable: $METHOD
  regex: (system|exec|popen)
```

**`metavariable-pattern`** — match metavariable against nested patterns:
```yaml
metavariable-pattern:
  metavariable: $OPTS
  patterns:
    - pattern-not: "{secureOptions: ...}"
```

**`metavariable-comparison`** — compare using Python expressions:
```yaml
metavariable-comparison:
  metavariable: $SIZE
  comparison: $SIZE > 1024
```

Supports: `+`, `-`, `*`, `/`, `%`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `and`, `or`, `not`, `int()`, `str()`, `re.match()`.

**`focus-metavariable`** — narrow match to specific captured variable:
```yaml
patterns:
  - pattern: def $FUNC(..., $ARG : bad, ...): ...
  - focus-metavariable: $ARG
```

## Pattern Syntax

### Ellipsis (`...`)

Matches zero or more items in current scope:

```yaml
# Any arguments
func(...)

# First arg is 1, rest anything
func(1, ...)

# Any statements in function body
def $F(...):
    ...
```

### Metavariables (`$X`)

Capture and reuse code expressions:

```yaml
# $X must be the same variable in both patterns (within `patterns` AND logic)
patterns:
  - pattern: $X = user_input()
  - pattern: dangerous($X)
```

| Syntax | Meaning |
|---|---|
| `$X` | Capture any single expression |
| `$...X` | Capture zero or more expressions |
| `$_` | Match any expression (anonymous, no capture) |
| `"..."` | Match any string literal |

### Typed Metavariables

Constrain by type (language-dependent):

```yaml
# Java: match Logger instances
pattern: (java.util.logging.Logger $LOGGER).log(...)

# Go: match specific receiver type
pattern: ($READER : *zip.Reader).Open($INPUT)
```

### Deep Expression Matching (`<... P ...>`)

Match pattern nested anywhere in an expression:

```yaml
# Find is_admin() anywhere inside an if condition
pattern: |
  if <... $USER.is_admin() ...>:
      ...
```

## Metavariable Binding Rules

- **Within `patterns` (AND)**: Same metavariable must match identical code across sub-patterns
- **Within `pattern-either` (OR)**: Metavariables are independent per branch
- **Anonymous `$_`**: Matches but does not bind (no consistency enforced)

## Taint Mode

Add `mode: taint` for data flow tracking. See [taint-rules.md](taint-rules.md) for details.

```yaml
rules:
  - id: taint-example
    mode: taint
    severity: ERROR
    languages: [python]
    message: "Tainted data reaches sink"
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sanitizers:
      - pattern: escape($X)
    pattern-sinks:
      - pattern: eval($X)
```

### Source/Sink Options

- `exact: true` — only the matched expression is tainted (not sub-expressions)
- `by-side-effect: only` — track taint via side effects, not return values

### Propagators (Pro feature)

```yaml
pattern-propagators:
  - pattern: strcpy($DST, $SRC)
    from: $SRC
    to: $DST
```

## Semgrep Equivalences

Semgrep automatically handles:
- **Import aliases**: `import subprocess as sp` → `sp.call(...)` matches `subprocess.call(...)`
- **Constant propagation**: Variables assigned literal values are tracked
- **Associativity/commutativity**: `A && B && C` matches `(A && B) && C`
