---
name: detect-xss
description: Detect Cross-Site Scripting vulnerabilities: stored XSS, reflected XSS, DOM-based XSS, template injection, unsafe markdown rendering, client-side template injection, DOM clobbering, and CSP bypass vectors. Use during Phase 3 vulnerability detection.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# XSS Vulnerability Detection

## Goal
Find all places where user-controlled data reaches an HTML rendering context without proper encoding — enabling script injection, session hijacking, or credential theft.

## Sub-Types Covered
- **Stored XSS** — User input saved to DB, rendered in template without encoding
- **Reflected XSS** — Input from URL/form immediately reflected in response
- **DOM-based XSS** — Client-side JS reads from URL/storage and writes to DOM sink
- **Template auto-escape bypass** — `| safe`, `{!! !!}`, `v-html`, `dangerouslySetInnerHTML`
- **Unsafe markdown rendering** — `marked(userInput)` without DOMPurify sanitization
- **Client-side template injection** — AngularJS `{{7*7}}` in ng-app context
- **DOM clobbering** — Named anchors/forms overriding global JS variables
- **CSP bypass vectors** — JSONP endpoints, `unsafe-inline`, `unsafe-eval`, Angular injection

## Grep Patterns

### Server-Side Template Rendering (Check for Missing Escape)
```bash
grep -rn "render_template_string\|\.render(\|Markup(\|mark_safe(\|format_html\|SafeData\|{% autoescape off\|{%- raw %\|\.html\|SafeString\|unescaped\|noescape" \
  --include="*.py" --include="*.rb" --include="*.java" \
  ${TARGET_SOURCE}
```

### Server-Side: Unescaped Output in Templates
```bash
# Jinja2/Django/Twig unsafe markers
grep -rn "| safe\|{% autoescape off\|{!! \|raw(\|unescape(" \
  --include="*.html" --include="*.j2" --include="*.jinja" \
  --include="*.twig" --include="*.blade.php" \
  ${TARGET_SOURCE}

# Go html/template vs text/template
grep -rn "text/template\|template\.HTML(\|template\.JS(\|template\.URL(" \
  --include="*.go" \
  ${TARGET_SOURCE}
```

### DOM-Based XSS Sinks (JavaScript)
```bash
grep -rn "innerHTML\|outerHTML\|document\.write(\|document\.writeln(\|insertAdjacentHTML\|\.html(\|\.append(\|\.prepend(\|eval(\|setTimeout.*string\|setInterval.*string\|location\.href\s*=\|location\.assign(\|location\.replace(" \
  --include="*.js" --include="*.ts" --include="*.html" \
  ${TARGET_SOURCE} | grep -v "test\|spec\|node_modules"
```

### DOM-Based XSS Sources (JavaScript)
```bash
grep -rn "location\.hash\|location\.search\|location\.href\|document\.referrer\|window\.name\|document\.URL\|URLSearchParams\|decodeURIComponent\|localStorage\.\|sessionStorage\." \
  --include="*.js" --include="*.ts" \
  ${TARGET_SOURCE} | grep -v "test\|spec"
```

### React / Vue / Angular Unsafe Rendering
```bash
grep -rn "dangerouslySetInnerHTML\|v-html=\|ng-bind-html\|bypassSecurityTrustHtml\|DomSanitizer.*bypass\|trustAsHtml" \
  --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" \
  --include="*.vue" --include="*.html" \
  ${TARGET_SOURCE}
```

### Unsafe Markdown / Rich Text Rendering
```bash
grep -rn "marked(\|showdown\.\|remarkable\.\|markdown-it\|sanitize.*false\|sanitize: false\|DOMPurify\|sanitizeHtml\|xss(" \
  --include="*.js" --include="*.ts" \
  ${TARGET_SOURCE}
```

### AngularJS Client-Side Template Injection
```bash
grep -rn "ng-app\|angular\.module\|\$scope\|\$compile\|\$eval\|ng-bind\|\{\{.*request\|\{\{.*param" \
  --include="*.html" --include="*.js" \
  ${TARGET_SOURCE}
```

## Detection Process

1. **Map stored XSS paths**: Find DB writes of user input → find templates that render those fields → check if field is auto-escaped or uses `| safe`.
2. **Map reflected XSS paths**: Find request parameters → trace to template context → check encoding.
3. **DOM XSS source-to-sink**: Find DOM sources (location.hash, location.search, URL params via JS) → follow JS code to DOM sinks (innerHTML, eval, document.write).
4. **Check framework protections**: Read `recon/architecture/framework_protections.md` for auto-escape status:
   - Jinja2 auto-escape ON + no `| safe` = FALSE POSITIVE
   - React JSX text interpolation = FALSE POSITIVE; `dangerouslySetInnerHTML` = HIGH
   - Django templates auto-escape = FALSE POSITIVE; `mark_safe()` = HIGH
5. **CSP analysis**: Check HTTP headers or meta tags for CSP. A weak CSP may allow bypass even if XSS exists.

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `{{ user_input }}` in Jinja2 with auto-escape | FALSE POSITIVE |
| `{{ user_input \| safe }}` in Jinja2 | HIGH |
| `<div>{{ data }}</div>` in React JSX | FALSE POSITIVE |
| `dangerouslySetInnerHTML={{ __html: userInput }}` | HIGH |
| `element.innerHTML = location.hash.slice(1)` | CRITICAL — DOM XSS |
| `element.textContent = location.hash.slice(1)` | FALSE POSITIVE |
| `marked(userComment)` without DOMPurify | HIGH |
| `marked(userComment)` + `DOMPurify.sanitize()` | FALSE POSITIVE if configured correctly |
| `v-html="userInput"` in Vue | HIGH |
| `bypassSecurityTrustHtml(input)` in Angular | HIGH |

## Reference Files

- [Vulnerable XSS patterns by framework/language](references/patterns.md)
- [XSS payloads: filter bypass, CSP bypass, event handler injection](references/payloads.md)
- [Exploitation guide: session hijacking, credential theft, CSRF via XSS](references/exploitation.md)
