# Memory Corruption — Vulnerable C/C++ Patterns and Safe Alternatives

## Stack Buffer Overflow

### VULNERABLE — strcpy with fixed buffer
```c
// CRITICAL: no bounds check — src can be arbitrarily long
void handle_username(char *input) {
    char buf[64];
    strcpy(buf, input);    // overflow if input > 63 bytes
    process_username(buf);
}

// Also vulnerable in network handlers:
void read_request(int sock) {
    char header[256];
    int n = recv(sock, header, 65536, 0);  // recv reads up to 65536 but buf is 256
    header[n] = '\0';   // OOB write
}
```

### VULNERABLE — gets() (never safe)
```c
void get_name() {
    char name[32];
    gets(name);     // CRITICAL: reads until newline with NO length limit
    printf("Hello, %s\n", name);
}
```

### VULNERABLE — sprintf into fixed buffer
```c
void build_path(const char *filename) {
    char path[256];
    sprintf(path, "/var/www/uploads/%s", filename);  // overflow if filename > ~236 bytes
    process_file(path);
}
```

### VULNERABLE — strcat into fixed buffer
```c
void append_extension(char *filename) {
    char result[128];
    strcpy(result, filename);
    strcat(result, ".bak");   // overflow if strlen(filename) + 4 >= 128
}
```

### SAFE ALTERNATIVES
```c
// strncpy (be careful: doesn't guarantee null termination)
strncpy(buf, input, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\0';

// strlcpy (BSD, always null-terminates)
strlcpy(buf, input, sizeof(buf));

// snprintf (recommended for path/string building)
snprintf(path, sizeof(path), "/var/www/uploads/%s", filename);

// fgets (for stdin input instead of gets)
fgets(name, sizeof(name), stdin);

// strncat with remaining space
strncat(result, ".bak", sizeof(result) - strlen(result) - 1);
```

---

## Heap Buffer Overflow

### VULNERABLE — malloc without overflow check on size
```c
// CRITICAL: if user controls 'count', count * sizeof(int) can overflow to small value
void allocate_records(int count) {
    // If count = 0x40000001 and sizeof(int) = 4:
    // 0x40000001 * 4 = 0x100000004 → wraps to 4 on 32-bit → heap overflow
    int *records = malloc(count * sizeof(int));
    for (int i = 0; i < count; i++) {
        records[i] = read_record();   // writes past the 4-byte allocation
    }
}

// VULNERABLE: attacker controls nmemb in calloc
void *buf = calloc(user_nmemb, user_size);   // integer overflow if both large
```

### VULNERABLE — memcpy with user-controlled length into fixed heap allocation
```c
void process_packet(uint8_t *pkt, size_t pkt_len) {
    uint8_t *buf = malloc(256);     // fixed 256-byte allocation
    size_t data_len = *(uint32_t *)(pkt + 4);   // length from packet header
    memcpy(buf, pkt + 8, data_len);  // CRITICAL: data_len not checked against 256
    handle_data(buf, data_len);
}
```

### SAFE ALTERNATIVES
```c
// Check for integer overflow before multiplication
#include <stdint.h>
if (count > SIZE_MAX / sizeof(int)) {
    return ERROR_OVERFLOW;
}
int *records = malloc(count * sizeof(int));

// Use calloc (it does the overflow check internally on most libc):
int *records = calloc(count, sizeof(int));
if (!records) return ERROR_ALLOC;

// Or use __builtin_mul_overflow (GCC/Clang):
size_t total;
if (__builtin_mul_overflow(count, sizeof(int), &total)) {
    return ERROR_OVERFLOW;
}
int *records = malloc(total);

// Validate data_len before memcpy:
if (data_len > 256) {
    return ERROR_INVALID;
}
memcpy(buf, pkt + 8, data_len);
```

---

## Format String Vulnerability

### VULNERABLE — user input as format string
```c
// CRITICAL: printf(user_input) allows %n, %x, etc.
void log_error(char *user_message) {
    printf(user_message);        // CRITICAL
    fprintf(stderr, user_message); // CRITICAL
    syslog(LOG_ERR, user_message); // CRITICAL
}

// Also vulnerable in network services:
void send_response(int sock, char *message) {
    char response[1024];
    sprintf(response, message);  // CRITICAL if message contains format specifiers
    send(sock, response, strlen(response), 0);
}
```

### Format String Exploitation Consequence
```
Payload: %x.%x.%x.%x           → reads 4 values off the stack (info leak)
Payload: %s                      → reads a char* off the stack (crash or info leak)
Payload: AAAA%6$n               → writes to address 0x41414141 (arbitrary write)
Payload: %100c%6$n              → writes value 100 to target address
```

### SAFE ALTERNATIVES
```c
// Always use a literal format string:
printf("%s", user_message);        // SAFE
fprintf(stderr, "%s", user_message); // SAFE
syslog(LOG_ERR, "%s", user_message); // SAFE
```

---

## Use-After-Free (UAF)

### VULNERABLE — using pointer after free
```c
// Pattern 1: free in error path, use continues
void process_request(struct request *req) {
    char *buf = malloc(req->size);
    if (!buf) return;

    if (parse_request(buf, req) < 0) {
        free(buf);
        // VULNERABLE: falls through to use of buf
    }
    send_response(buf, req->size);   // UAF if parse_request failed
}

// Pattern 2: dangling pointer via callback
struct handler {
    char *data;
    void (*callback)(struct handler *);
};

void destroy_handler(struct handler *h) {
    free(h->data);
    // h->data is now dangling — if callback is called later:
}

void trigger_callback(struct handler *h) {
    h->callback(h);   // callback may use h->data (UAF)
}
```

### VULNERABLE — use-after-free via cache/global
```c
static struct session *cached_session = NULL;

void invalidate_session(struct session *s) {
    free(s);
    // cached_session still points to freed memory
}

void handle_request() {
    if (cached_session) {
        use_session(cached_session);   // UAF if invalidate_session was called
    }
}
```

### SAFE ALTERNATIVES
```c
// Zero pointer after free:
free(buf);
buf = NULL;
// Now use of buf will null-dereference (crash) instead of UAF (exploitation)

// Or use RAII in C++:
std::unique_ptr<char[]> buf(new char[size]);
// Automatically freed when out of scope, pointer invalidated
```

---

## Double Free

### VULNERABLE — double free via error handling
```c
char *buf = malloc(size);
if (!buf) goto error;

if (do_work(buf) < 0) {
    free(buf);        // first free in error handler
    goto error;
}

return buf;

error:
    free(buf);        // second free — double free if do_work failed
    return NULL;
```

### VULNERABLE — double free via multiple code paths
```c
void cleanup(struct ctx *ctx) {
    if (ctx->buf) free(ctx->buf);
    // ...
}

void handle_timeout(struct ctx *ctx) {
    free(ctx->buf);      // first free
    ctx->state = TIMEOUT;
    cleanup(ctx);        // second free via cleanup
}
```

### SAFE ALTERNATIVES
```c
// Pattern 1: NULL after free
free(ctx->buf);
ctx->buf = NULL;   // cleanup's check if (ctx->buf) will now be false

// Pattern 2: Single cleanup path (avoid freeing in error handlers — use goto cleanup)
char *buf = malloc(size);
if (!buf) { result = -1; goto done; }

if (do_work(buf) < 0) { result = -2; goto done; }

// ... more work ...

done:
    free(buf);   // single free point
    return result;
```

---

## Out-of-Bounds Array Access

### VULNERABLE — user-controlled array index
```c
// CRITICAL: no bounds check on user-provided index
char *lookup_record(int user_index) {
    static char *records[MAX_RECORDS];
    return records[user_index];   // OOB if user_index < 0 or >= MAX_RECORDS
}

// VULNERABLE in packet parsing:
uint8_t dispatch_table[256];
uint8_t opcode = packet[0];
handler_fn fn = handlers[opcode];  // Safe only if packet[0] is always 0-255 AND handlers has 256 entries
```

### SAFE ALTERNATIVES
```c
char *lookup_record(int user_index) {
    if (user_index < 0 || user_index >= MAX_RECORDS) {
        return NULL;   // bounds check
    }
    return records[user_index];
}
```

---

## Unsafe Rust Patterns

### VULNERABLE — raw pointer dereference without bounds check
```rust
unsafe {
    let ptr: *mut u8 = buffer.as_mut_ptr();
    // No check that offset < buffer.len()
    *ptr.add(user_offset) = value;   // OOB write if user_offset >= buffer.len()
}
```

### VULNERABLE — slice from raw parts with user length
```rust
unsafe {
    // user_len not validated against actual allocation size
    let slice = std::slice::from_raw_parts(ptr, user_len);
    process(slice);   // reads beyond allocation if user_len too large
}
```

### SAFE Rust alternatives
```rust
// Bounds check before unsafe block:
if user_offset >= buffer.len() {
    return Err(Error::OutOfBounds);
}
unsafe { *buffer.as_mut_ptr().add(user_offset) = value; }

// Or use safe slice indexing (panics instead of UB):
buffer[user_offset] = value;

// Or use get_mut:
if let Some(elem) = buffer.get_mut(user_offset) {
    *elem = value;
}
```
