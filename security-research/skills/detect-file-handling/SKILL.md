---
name: detect-file-handling
description: Detect file handling vulnerabilities: arbitrary file upload, MIME type bypass, stored XSS via SVG/HTML upload, path traversal via filename, zip slip, unsafe archive extraction, ImageMagick/Ghostscript RCE via file processing, and temporary file race conditions. Use during Phase 3 vulnerability detection.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# File Handling Vulnerability Detection

## Goal
Find unsafe file upload handling, archive extraction, and file processing that can lead to arbitrary file write, remote code execution, stored XSS, or path traversal.

## Sub-Types Covered
- **Unrestricted file upload** — No validation of file type or content
- **MIME type bypass** — Extension or Content-Type checked but not actual file content
- **Stored XSS via file** — SVG or HTML file served from same origin enables XSS
- **Path traversal via filename** — `../../../etc/passwd` in uploaded filename
- **Zip slip** — Directory traversal via archive entry names (`../../../../etc/cron.d/evil`)
- **Unsafe archive extraction** — `tarfile.extractall()` or `zipfile.extractall()` without path validation
- **ImageMagick RCE** — Malicious image with embedded commands (CVE-2016-3714 "ImageTragick")
- **Ghostscript RCE** — Malicious PostScript/EPS file execution
- **Temporary file race** — Predictable temp file path in `/tmp` (TOCTOU)
- **Symlink attack** — Archive contains symlink pointing outside extraction directory

## Grep Patterns

### File Upload Handling
```bash
grep -rn "request\.FILES\|request\.files\|file\.save(\|upload\.\|uploaded_file\|multipart\|Content-Type.*multipart\|form\.file\|IFormFile\|MultipartFile\|@RequestParam.*MultipartFile" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" --include="*.cs" \
  ${TARGET_SOURCE}
```

### Archive Extraction
```bash
grep -rn "zipfile\.extractall\|zipfile\.extract\|tarfile\.extractall\|tarfile\.extract\|ZipFile(\|TarFile(\|shutil\.unpack_archive\|Decompress\|ZipArchive\|ZipEntry\|unzip\|extract(" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Image / Document Processing
```bash
grep -rn "ImageMagick\|Ghostscript\|wand\.\|PIL\.Image\|Pillow\|subprocess.*convert\|subprocess.*gs\|exec.*convert\|pdfkit\|pdf.*process\|exiftool\|libreoffice.*convert" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" \
  ${TARGET_SOURCE}
```

### Filename Handling
```bash
grep -rn "filename\s*=\|file\.name\|request\.filename\|secure_filename\|os\.path\.basename\|os\.path\.join.*upload\|path\.join.*upload\|sanitize.*filename\|werkzeug\.secure_filename" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.java" \
  --include="*.php" --include="*.rb" --include="*.go" \
  ${TARGET_SOURCE}
```

### Temporary File Usage
```bash
# Note: mkstemp() is safe; mktemp() is vulnerable (TOCTOU)
grep -rn "tempfile\.mktemp(\|\/tmp\/\$\|os\.tmpnam(\|tmpnam(\|mktemp(" \
  --include="*.py" --include="*.c" --include="*.cpp" --include="*.php" \
  --include="*.rb" --include="*.java" \
  ${TARGET_SOURCE}
```

### File Extension Validation
```bash
# Find extension-only validation (bypassable)
grep -rn "endswith.*\(.*\.\|split.*\.\|\[-1\].*ext\|\.extension\|os\.path\.splitext\|path\.extname\|fileInfo\.Name" \
  --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java" \
  ${TARGET_SOURCE}
```

## Detection Process

### File Upload Check
1. Find file upload endpoints (from grep above and endpoint inventory)
2. Read the handler: what validation is performed?
   - Check: extension validation only? MIME type validation? Magic bytes validation?
   - Check: is the file served from the same origin or a CDN/separate domain?
3. If served from same origin + accepts SVG or HTML → stored XSS via SVG
4. If no content validation → arbitrary file upload
5. Check: is the storage path user-controlled? Is `filename` from request used directly in storage path?

### Archive Extraction Check
1. Find `extractall()` or `extract()` calls
2. Read surrounding code — is each entry path checked before extraction?
   - SAFE: `if not os.path.abspath(os.path.join(dest, entry.name)).startswith(os.path.abspath(dest) + os.sep): raise Exception`
   - VULNERABLE: `zip_ref.extractall(dest_dir)` without entry path check
3. Check for symlink entries: `if entry.issym(): skip`
4. Check for absolute paths in archive entries: `if entry.name.startswith('/'): skip`

### ImageMagick Check
1. Find ImageMagick invocations (`convert`, `mogrify`, `wand.Image`, PIL with ImageMagick backend)
2. Check `policy.xml` restrictions:
   ```bash
   grep -rn "policy.xml\|<policy.*coder\|MVG\|MSL\|LABEL\|TEXT\|EPHEMERAL\|URL\|HTTPS\|HTTP\|FTP" ${TARGET_SOURCE}
   find /etc/ImageMagick-* -name policy.xml 2>/dev/null
   ```
3. If processing user-uploaded files without restricted coders: HIGH — ImageTragick
4. Check ImageMagick version: `convert --version` — versions < 7.0.1-1 are vulnerable to ImageTragick

### Temporary File Race
1. Find `mktemp()` calls (NOT `mkstemp()`)
2. Check if file is created, then opened in a separate step (TOCTOU window)
3. Check if temp path is predictable (e.g., `/tmp/upload_${userId}_${timestamp}`)
4. If predictable and used in a privileged operation (e.g., root process reads it), HIGH

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `zipfile.extractall(dest)` without entry path check | CRITICAL — zip slip |
| `zipfile.extractall(dest)` with `os.path.abspath` startswith check | FALSE POSITIVE |
| `tarfile.extractall()` without filter (Python < 3.12) | HIGH — tar slip |
| `tarfile.extractall(filter='data')` (Python 3.12+) | FALSE POSITIVE |
| File upload accepting `.svg` served same-origin | HIGH — stored XSS |
| File upload accepting `.svg` served from CDN subdomain | MEDIUM (CSP dependent) |
| `tempfile.mktemp()` (not mkstemp) | MEDIUM — race condition |
| `tempfile.mkstemp()` | FALSE POSITIVE |
| ImageMagick processing user files without restrictive policy.xml | HIGH — ImageTragick |
| Filename not sanitized with `secure_filename` or equivalent | MEDIUM — path traversal |
| Extension check only (no magic bytes) | MEDIUM — MIME bypass |
| Upload stored at user-controlled path component | HIGH — path traversal |

## Reference Files

- [Example of good findings and exploits](references/good-findings.md)
- [Vulnerable file handling patterns by language/framework](references/patterns.md)
- [Attack files: malicious zip, SVG XSS, ImageMagick MSL payload, path traversal filenames](references/payloads.md)
- [Exploitation guide: zip slip, ImageMagick RCE, SVG XSS, MIME bypass](references/exploitation.md)
