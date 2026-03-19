# XSS Vulnerable Patterns by Framework and Language

## Python / Jinja2 / Flask

### VULNERABLE — mark_safe / Markup
```python
from markupsafe import Markup
from flask import render_template_string

# VULNERABLE: user input wrapped in Markup() bypasses auto-escaping
@app.route('/profile')
def profile():
    username = request.args.get('name')
    # mark_safe equivalent in Jinja2 context:
    return render_template_string(
        '<div>Hello {{ name }}</div>',
        name=Markup(username)   # CRITICAL — auto-escape bypassed
    )

# VULNERABLE: render_template_string with user-controlled template
@app.route('/render')
def render():
    template = request.args.get('t')
    return render_template_string(template)   # SSTI + XSS
```

### VULNERABLE — Jinja2 | safe filter
```html
<!-- templates/comment.html -->
<div class="comment">
  {{ comment.body | safe }}    <!-- HIGH: body stored from user input -->
</div>

<!-- Django equivalent -->
{% autoescape off %}
  {{ user_bio }}               <!-- HIGH -->
{% endautoescape %}
```

### SAFE — Default Jinja2 auto-escape
```html
<!-- SAFE: auto-escape converts < > & " ' to HTML entities -->
<div>{{ user_input }}</div>
```

---

## PHP

### VULNERABLE — Direct echo without escaping
```php
<?php
// CRITICAL: direct reflection of GET/POST parameter
echo $_GET['search'];
echo $_POST['username'];
echo htmlspecialchars_decode($_GET['q']);   // VULNERABLE: undoing escape

// VULNERABLE: sprintf into HTML without escaping
$html = sprintf('<div class="user">%s</div>', $_GET['name']);
echo $html;

// VULNERABLE: stored XSS via database
$bio = $db->query("SELECT bio FROM users WHERE id=?", [$_GET['id']])->fetch();
echo $bio['bio'];   // HIGH if bio was stored without sanitization
?>
```

### SAFE — htmlspecialchars
```php
<?php
// SAFE: htmlspecialchars encodes HTML special characters
echo htmlspecialchars($_GET['search'], ENT_QUOTES, 'UTF-8');

// SAFE: htmlentities
echo htmlentities($_GET['name'], ENT_QUOTES, 'UTF-8');
?>
```

---

## Go — text/template vs html/template

### VULNERABLE — text/template (no auto-escape)
```go
import "text/template"

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    tmpl := template.Must(template.New("").Parse(`<div>Hello {{.}}</div>`))
    tmpl.Execute(w, name)   // CRITICAL — text/template does NOT escape HTML
}
```

### VULNERABLE — template.HTML / template.JS unsafe type conversions
```go
import "html/template"

func handler(w http.ResponseWriter, r *http.Request) {
    userInput := r.URL.Query().Get("callback")
    // Casting to template.HTML bypasses auto-escape
    data := struct{ Content template.HTML }{
        Content: template.HTML(userInput),   // HIGH — escaping bypassed
    }
    tmpl.Execute(w, data)
}
```

### SAFE — html/template with no unsafe casts
```go
import "html/template"

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    tmpl := template.Must(template.New("").Parse(`<div>Hello {{.}}</div>`))
    tmpl.Execute(w, name)   // SAFE — html/template auto-escapes
}
```

---

## React

### VULNERABLE — dangerouslySetInnerHTML
```jsx
// HIGH: renders raw HTML from user-controlled string
function Comment({ body }) {
    return <div dangerouslySetInnerHTML={{ __html: body }} />;
}

// Also vulnerable via ref + innerHTML:
function UserBio({ bio }) {
    const divRef = useRef(null);
    useEffect(() => {
        divRef.current.innerHTML = bio;   // HIGH — DOM XSS
    }, [bio]);
    return <div ref={divRef} />;
}
```

### SAFE — JSX text interpolation
```jsx
// SAFE: React escapes by default in JSX expressions
function Comment({ body }) {
    return <div>{body}</div>;   // SAFE — auto-escaped
}
```

---

## Vue.js

### VULNERABLE — v-html directive
```html
<!-- HIGH: v-html renders raw HTML, bypasses Vue's escaping -->
<template>
  <div v-html="userComment"></div>
</template>

<script>
export default {
    data() {
        return {
            userComment: this.$route.query.comment   // from URL → v-html sink
        };
    }
}
</script>
```

### SAFE — Vue text interpolation
```html
<!-- SAFE: double curly braces auto-escape HTML -->
<template>
  <div>{{ userComment }}</div>
</template>
```

---

## Angular

### VULNERABLE — bypassSecurityTrustHtml
```typescript
import { DomSanitizer } from '@angular/platform-browser';

@Component({
    template: `<div [innerHTML]="safeContent"></div>`
})
export class UserProfileComponent {
    safeContent: SafeHtml;

    constructor(private sanitizer: DomSanitizer,
                private route: ActivatedRoute) {
        const bio = this.route.snapshot.queryParams['bio'];
        // HIGH: explicitly bypassing Angular's sanitizer
        this.safeContent = this.sanitizer.bypassSecurityTrustHtml(bio);
    }
}
```

### SAFE — Angular [innerHTML] with sanitizer (default behavior)
```typescript
@Component({
    template: `<div [innerHTML]="userContent"></div>`
    // Angular sanitizes [innerHTML] by default — SAFE for most cases
})
export class Component {
    userContent = this.route.snapshot.queryParams['bio'];
    // Angular's sanitizer strips script tags and dangerous attributes
    // but may still allow some vectors — DOMPurify is preferred for rich content
}
```

---

## JavaScript — DOM XSS Source-to-Sink Chains

### VULNERABLE — location.hash → innerHTML
```javascript
// CRITICAL: URL fragment directly into DOM sink
// URL: https://app.com/page#<img src=x onerror=alert(1)>
document.addEventListener('DOMContentLoaded', () => {
    const content = decodeURIComponent(location.hash.slice(1));
    document.getElementById('content').innerHTML = content;   // CRITICAL
});
```

### VULNERABLE — URLSearchParams → eval
```javascript
// CRITICAL: URL parameter into eval
const params = new URLSearchParams(location.search);
const callback = params.get('callback');
eval(callback);   // CRITICAL

// Or via setTimeout with string:
setTimeout(params.get('delay'), 1000);   // CRITICAL if first arg is string
```

### VULNERABLE — document.referrer → innerHTML
```javascript
// HIGH: referrer can be controlled by attacker-hosted page
const source = document.referrer;
document.getElementById('back-link').innerHTML =
    `<a href="${source}">Go Back</a>`;   // HIGH — href injection + innerHTML
```

### VULNERABLE — jQuery .html() with user data
```javascript
// HIGH: jQuery .html() is equivalent to innerHTML
$('#output').html(location.hash.slice(1));      // CRITICAL
$('.message').html($.ajax.responseText);         // HIGH

// Also vulnerable:
$('#container').append('<div>' + userInput + '</div>');  // HIGH
```

### SAFE — textContent and innerText
```javascript
// SAFE: textContent never interprets HTML
document.getElementById('content').textContent = location.hash.slice(1);
element.innerText = userInput;   // SAFE
```

---

## Unsafe Markdown Rendering

### VULNERABLE — marked() without sanitization
```javascript
// HIGH: marked renders HTML including script tags
import marked from 'marked';

function renderComment(markdown) {
    // Default marked allows <script> in markdown
    return { __html: marked(markdown) };
}

// Rendered in React:
<div dangerouslySetInnerHTML={renderComment(user.comment)} />
```

### SAFE — marked() with DOMPurify
```javascript
import marked from 'marked';
import DOMPurify from 'dompurify';

function renderComment(markdown) {
    const rawHtml = marked(markdown);
    const clean = DOMPurify.sanitize(rawHtml, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li'],
        ALLOWED_ATTR: ['href', 'title']
    });
    return { __html: clean };
}
```

---

## AngularJS (Legacy) Client-Side Template Injection

### VULNERABLE — ng-app + user input in template context
```html
<!-- CRITICAL: AngularJS evaluates {{ }} expressions -->
<!-- If user input reaches between {{ }}: -->
<div ng-app>
    <!-- URL: /?name={{constructor.constructor('alert(1)')()}} -->
    <p>Hello, {{ userParam }}</p>
</div>
```

### VULNERABLE — Server-rendered AngularJS page with reflected input
```html
<!-- Server reflects URL param into ng-app page body -->
<!-- PHP: echo "Hello " . $_GET['name']; -->
<!-- Result: Hello {{7*7}} → AngularJS evaluates to "Hello 49" -->
<div ng-app ng-controller="AppCtrl">
    Hello <?php echo $_GET['name']; ?>
</div>
```
