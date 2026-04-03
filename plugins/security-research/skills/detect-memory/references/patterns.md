# Memory Safety Vulnerability Patterns Reference

Vulnerable vs. safe code patterns for memory safety vulnerabilities across C/C++, Rust, Go, Python, Java, and Node.js.

---

## 1. Stack Buffer Overflow

### Vulnerable:
```c
// strcpy — no length check, overwrites stack
void process_name(const char *input) {
    char buf[64];
    strcpy(buf, input);  // BUG: input may be > 64 bytes
}

// gets — always unsafe, removed from C11
void read_line() {
    char buf[128];
    gets(buf);  // BUG: no limit at all
}

// sprintf — format can produce more than buf can hold
void build_path(const char *user) {
    char path[256];
    sprintf(path, "/home/%s/.config", user);  // BUG: unbounded
}
```

### Safe:
```c
void process_name(const char *input) {
    char buf[64];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';  // ensure NUL termination
}

// strlcpy (BSD/macOS/glibc ≥2.38) — always NUL-terminates
void process_name_bsd(const char *input) {
    char buf[64];
    strlcpy(buf, input, sizeof(buf));  // returns needed length for truncation check
}

// fgets for user input — length-bounded
void read_line_safe() {
    char buf[128];
    if (fgets(buf, sizeof(buf), stdin) == NULL) handle_error();
}

// snprintf — bounded, returns needed length
void build_path(const char *user) {
    char path[256];
    int n = snprintf(path, sizeof(path), "/home/%s/.config", user);
    if (n < 0 || (size_t)n >= sizeof(path)) handle_truncation();
}
```

---

## 2. Heap Buffer Overflow

### Vulnerable:
```c
// memcpy OOB — source larger than destination
void copy_data(const uint8_t *src, size_t src_len) {
    uint8_t *dst = malloc(64);
    memcpy(dst, src, src_len);  // BUG: src_len may exceed 64
}

// Off-by-one — missing +1 for NUL terminator
char *dup_string(const char *s) {
    size_t len = strlen(s);
    char *buf = malloc(len);   // BUG: needs len+1
    memcpy(buf, s, len + 1);  // writes one past allocation
    return buf;
}

// Integer overflow in size calculation collapses into tiny alloc
void make_grid(size_t w, size_t h) {
    size_t sz = w * h * sizeof(int);  // BUG: overflows if w*h > SIZE_MAX/4
    int *grid = malloc(sz);
    memset(grid, 0, w * h * sizeof(int));  // writes beyond allocation
}
```

### Safe:
```c
// calloc — zero-initializes and checks overflow internally
void copy_data_safe(const uint8_t *src, size_t src_len) {
    uint8_t *dst = malloc(src_len);  // allocate exactly what we need
    if (!dst) handle_oom();
    memcpy(dst, src, src_len);
}

char *dup_string_safe(const char *s) {
    size_t len = strlen(s);
    char *buf = malloc(len + 1);  // +1 for NUL
    if (!buf) return NULL;
    memcpy(buf, s, len + 1);
    return buf;
}

void make_grid_safe(size_t w, size_t h) {
    size_t sz;
    if (__builtin_mul_overflow(w, h, &sz) ||
        __builtin_mul_overflow(sz, sizeof(int), &sz)) {
        handle_overflow();
    }
    int *grid = calloc(w * h, sizeof(int));  // calloc checks overflow
    if (!grid) handle_oom();
}
```

---

## 3. Use-After-Free

### Vulnerable:
```c
// Dangling pointer read after free
void process_item(struct Item *item) {
    free(item->data);
    log_item(item);  // BUG: item->data is dangling
    printf("size: %zu\n", item->data_len);  // still ok, but...
    use(item->data);  // BUG: UAF
}

// C++ iterator invalidation
void remove_evens(std::vector<int> &v) {
    for (auto it = v.begin(); it != v.end(); ++it) {
        if (*it % 2 == 0)
            v.erase(it);  // BUG: erase invalidates it; ++it then UB
    }
}

// Error-path UAF — obj freed on error, then used in cleanup
int open_connection(Context *ctx) {
    Object *obj = alloc_object();
    ctx->obj = obj;
    if (init_object(obj) < 0) {
        free(obj);           // freed here
        return -1;
    }
    register_object(ctx);   // ctx->obj still points to freed obj on later use
    return 0;
}
```

### Safe:
```c
// Null after free — prevents accidental reuse
void process_item_safe(struct Item *item) {
    free(item->data);
    item->data = NULL;  // poison the pointer immediately
    item->data_len = 0;
    log_item(item);
}

// C++ RAII — unique_ptr prevents manual free
void process_raii() {
    auto data = std::make_unique<Data>();
    // data freed automatically; no dangling pointer possible
}

// Erase-remove idiom
void remove_evens_safe(std::vector<int> &v) {
    v.erase(std::remove_if(v.begin(), v.end(),
                           [](int x){ return x % 2 == 0; }),
            v.end());
}
```

---

## 4. Double Free

### Vulnerable:
```c
// Explicit double free
void cleanup(struct Buf *b) {
    free(b->data);
    // ... lots of code ...
    free(b->data);  // BUG: freed again
}

// Conditional double free
void handle_response(Response *r) {
    char *body = malloc(r->len);
    if (parse(r, body) < 0) {
        free(body);  // freed on error path
    }
    free(body);  // BUG: freed again unconditionally
}

// Error-path double free
int process(Context *ctx) {
    Data *d = create_data();
    ctx->data = d;
    if (validate(d) < 0) {
        free(d);    // freed here
        goto done;
    }
done:
    free(ctx->data);  // BUG: d already freed
    return -1;
}
```

### Safe:
```c
// Single cleanup path — set NULL after free
void cleanup_safe(struct Buf *b) {
    free(b->data);
    b->data = NULL;  // free(NULL) is always safe
}

// One free, clearly scoped
void handle_response_safe(Response *r) {
    char *body = malloc(r->len);
    int rc = parse(r, body);
    free(body);  // single free at end regardless of outcome
    if (rc < 0) handle_error();
}

// C++ RAII avoids manual tracking entirely
void process_cpp(Context &ctx) {
    ctx.data = std::make_unique<Data>();
    if (!validate(*ctx.data)) throw std::runtime_error("invalid");
    // unique_ptr destructs once, no double free possible
}
```

---

## 5. Invalid / Arbitrary Free

### Vulnerable:
```c
// Free of stack pointer
void bad_free() {
    char buf[64] = "hello";
    char *p = buf;
    free(p);  // BUG: p points to stack, not heap
}

// Deserialization-path arbitrary free (REF2 TopK pattern)
// Attacker controls serialized data; heap blob loaded first
// with attacker-supplied pointers, items loaded second,
// error path frees attacker-controlled values.
int load_topk(FILE *f, TopK *tk) {
    // Step 1: load raw blob — contains attacker pointers for items[]
    fread(tk, sizeof(*tk), 1, f);          // tk->items may now be attacker pointer

    // Step 2: load individual items into already-tainted array
    for (int i = 0; i < tk->count; i++) {
        tk->items[i] = malloc(sizeof(Item));
        fread(tk->items[i], sizeof(Item), 1, f);
        if (ferror(f)) {
            // BUG: earlier tk->items[j] (j < i) were set by attacker blob,
            // so we free attacker-supplied pointers here
            for (int j = 0; j < i; j++)
                free(tk->items[j]);  // arbitrary free
            return -1;
        }
    }
    return 0;
}
```

### Safe:
```c
// Zero-initialize struct before loading to clear any stale/attacker pointers
int load_topk_safe(FILE *f, TopK *tk) {
    memset(tk, 0, sizeof(*tk));  // wipe first — no attacker pointers survive

    // Read only the scalar fields we trust
    uint32_t count;
    if (fread(&count, sizeof(count), 1, f) != 1) return -1;
    if (count > MAX_TOPK_COUNT) return -EINVAL;
    tk->count = count;

    tk->items = calloc(count, sizeof(Item *));
    if (!tk->items) return -ENOMEM;

    for (uint32_t i = 0; i < count; i++) {
        tk->items[i] = malloc(sizeof(Item));
        if (!tk->items[i] || fread(tk->items[i], sizeof(Item), 1, f) != 1) {
            for (uint32_t j = 0; j < i; j++) free(tk->items[j]);
            free(tk->items);
            return -1;
        }
    }
    return 0;
}
```

---

## 6. Type Confusion

### Vulnerable:
```c
// void* cast mismatch — alloc as TypeA, cast to TypeB
void *make_obj(int type) {
    if (type == 1) return malloc(sizeof(TypeA));
    return malloc(sizeof(TypeB));
}
void use_obj(void *obj) {
    TypeA *a = (TypeA *)obj;  // BUG: may actually be TypeB
    a->field_only_in_a = 1;  // memory corruption
}

// Union type punning — undefined behavior in C++
union PunUnion { float f; uint32_t u; };
float bits_to_float(uint32_t bits) {
    union PunUnion p;
    p.u = bits;
    return p.f;  // BUG: UB in C++ (ok in C99)
}

// C++ static_cast without RTTI check
void process(Base *b) {
    Derived *d = static_cast<Derived *>(b);  // BUG: b may not be Derived
    d->derived_method();  // vtable corruption / wrong dispatch
}
```

### Safe:
```c
// Tag the allocation
typedef struct { int type; } ObjHeader;
void use_obj_safe(ObjHeader *hdr) {
    if (hdr->type == TYPE_A) {
        TypeA *a = (TypeA *)hdr;
        a->field_only_in_a = 1;
    }
}

// memcpy punning — well-defined in both C and C++
float bits_to_float_safe(uint32_t bits) {
    float f;
    memcpy(&f, &bits, sizeof(f));
    return f;
}

// dynamic_cast with null check
void process_safe(Base *b) {
    Derived *d = dynamic_cast<Derived *>(b);
    if (!d) return;  // safe — returns nullptr if wrong type
    d->derived_method();
}
```

---

## 7. Integer Overflow

### Vulnerable:
```c
// Width * height * bpp overflows uint32_t for large images
uint8_t *alloc_image(uint32_t w, uint32_t h) {
    uint32_t sz = w * h * 4;  // BUG: overflows silently → tiny alloc
    return malloc(sz);
}

// Signed/unsigned comparison — negative index wraps to huge positive
void index_array(int idx, uint8_t *arr, size_t len) {
    if (idx < len) {           // BUG: if len > INT_MAX, comparison misbehaves
        arr[idx] = 0xFF;       // negative idx wraps to OOB write
    }
}

// Signed overflow in length increment
int grow_buffer(int cur_len, int add) {
    int new_len = cur_len + add;  // BUG: signed overflow is UB; may go negative
    return realloc_buf(new_len);
}
```

### Safe:
```c
// __builtin_mul_overflow — sets carry flag, no UB
uint8_t *alloc_image_safe(uint32_t w, uint32_t h) {
    size_t sz;
    if (__builtin_mul_overflow((size_t)w, (size_t)h, &sz) ||
        __builtin_mul_overflow(sz, 4u, &sz)) {
        return NULL;
    }
    return malloc(sz);
}

// Explicit type and bounds check before indexing
void index_array_safe(size_t idx, uint8_t *arr, size_t len) {
    if (idx >= len) return;  // both unsigned — no sign confusion
    arr[idx] = 0xFF;
}

// Checked addition
int grow_buffer_safe(size_t cur_len, size_t add) {
    size_t new_len;
    if (__builtin_add_overflow(cur_len, add, &new_len)) return -EOVERFLOW;
    return realloc_buf(new_len);
}
```

---

## 8. Uninitialized Memory

### Vulnerable:
```c
// Stack variable read before write
int get_value(int flag) {
    int result;             // BUG: uninitialized
    if (flag) result = 42;
    return result;          // may return garbage if !flag
}

// Heap alloc without zeroing
struct Config *make_config() {
    struct Config *c = malloc(sizeof(*c));  // BUG: fields are garbage
    c->timeout = 30;        // only some fields set; rest uninitialized
    return c;
}

// Partial struct initialization leaks padding bytes
struct Packet {
    uint8_t  type;
    uint8_t  _pad[3];  // compiler padding
    uint32_t length;
};
void send_packet(int fd, uint8_t type, uint32_t length) {
    struct Packet pkt;
    pkt.type   = type;    // BUG: _pad is uninitialized — info leak
    pkt.length = length;
    write(fd, &pkt, sizeof(pkt));
}
```

### Safe:
```c
int get_value_safe(int flag) {
    int result = 0;  // initialize at declaration
    if (flag) result = 42;
    return result;
}

struct Config *make_config_safe() {
    struct Config *c = calloc(1, sizeof(*c));  // zero-initializes all fields
    if (!c) return NULL;
    c->timeout = 30;
    return c;
}

void send_packet_safe(int fd, uint8_t type, uint32_t length) {
    struct Packet pkt = {0};  // zero entire struct including padding
    pkt.type   = type;
    pkt.length = length;
    write(fd, &pkt, sizeof(pkt));
}
```

---

## 9. Format String

### Vulnerable:
```c
// Direct user input as format — attacker writes arbitrary memory
void log_message(const char *user_msg) {
    printf(user_msg);        // BUG: %n writes, %x leaks stack
}

// syslog with user-controlled format
void log_event(const char *event) {
    syslog(LOG_INFO, event); // BUG: same class of vulnerability
}

// fprintf with attacker format in structured log
void audit(FILE *log, const char *action) {
    fprintf(log, action);    // BUG: action may contain %n
}
```

### Safe:
```c
void log_message_safe(const char *user_msg) {
    printf("%s", user_msg);         // format string is a literal, not user data
}

void log_event_safe(const char *event) {
    syslog(LOG_INFO, "%s", event);  // event is an argument, not the format
}

void audit_safe(FILE *log, const char *action) {
    fprintf(log, "%s\n", action);
}
```

---

## 10. Out-of-Bounds Read

### Vulnerable:
```c
// strlen on non-NUL-terminated buffer — reads past allocation
// REF2 pattern: RM_LoadStringBuffer returns length-prefixed blob
// without appending NUL; caller passes it to strlen.
char *load_key(RedisModuleCtx *ctx, RedisModuleKey *key) {
    size_t blob_len;
    char *blob = RedisModule_LoadStringBuffer(key, &blob_len);
    // BUG: blob is NOT NUL-terminated; strlen reads beyond blob_len
    size_t key_len = strlen(blob);
    char *out = malloc(key_len + 1);
    memcpy(out, blob, key_len + 1);  // copies OOB byte
    return out;
}

// Array index without bounds check
uint8_t table_lookup(uint8_t *table, int idx) {
    return table[idx];  // BUG: idx may be negative or >= table size
}
```

### Safe:
```c
// Use the returned length — never call strlen on untrusted buffers
char *load_key_safe(RedisModuleCtx *ctx, RedisModuleKey *key) {
    size_t blob_len;
    char *blob = RedisModule_LoadStringBuffer(key, &blob_len);
    char *out = malloc(blob_len + 1);
    if (!out) return NULL;
    memcpy(out, blob, blob_len);
    out[blob_len] = '\0';  // explicitly NUL-terminate
    return out;
}

// Bounds-checked lookup
uint8_t table_lookup_safe(uint8_t *table, size_t table_size, size_t idx) {
    if (idx >= table_size) abort();  // or return default
    return table[idx];
}
```

---

## 11. Rust `unsafe` Patterns

### Vulnerable:
```rust
// Raw pointer arithmetic past allocation
unsafe fn read_field(base: *const u8, offset: usize) -> u8 {
    // BUG: no bounds check; offset may point past allocation
    *base.add(offset)
}

// transmute between incompatible types
fn reinterpret(val: u32) -> f32 {
    unsafe { std::mem::transmute::<u32, f32>(val) }
    // Only safe when sizes match AND the bit pattern is valid for the target type
    // Will silently produce NaN / infinity for certain inputs
}

// slice::from_raw_parts with attacker-controlled length
unsafe fn make_slice(ptr: *const u8, len: usize) -> &'static [u8] {
    // BUG: len may exceed actual allocation; no lifetime guarantee
    std::slice::from_raw_parts(ptr, len)
}
```

### Safe:
```rust
// Bounds-checked access via safe slice
fn read_field(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()  // returns None on OOB — no unsafe needed
}

// f32::from_bits — semantically clear, avoids transmute
fn reinterpret_safe(val: u32) -> f32 {
    f32::from_bits(val)  // well-defined for all u32 values
}

// Wrap unsafe in a checked constructor
fn make_slice_safe(ptr: *const u8, len: usize, cap: usize) -> Option<&'static [u8]> {
    if len > cap { return None; }
    // SAFETY: ptr valid for cap bytes, len ≤ cap, lifetime managed by caller
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}
```

---

## 12. Go cgo Patterns

### Vulnerable:
```go
// unsafe.Pointer arithmetic — bypasses Go's type system
func readByte(p unsafe.Pointer, offset uintptr) byte {
    // BUG: Go GC may move objects; pointer arithmetic is not tracked
    return *(*byte)(unsafe.Pointer(uintptr(p) + offset))
}

// C.CString without C.free — heap leak
func passString(s string) {
    cs := C.CString(s)       // allocates C heap memory
    C.process_string(cs)     // BUG: cs never freed → leak
}

// Passing Go pointer containing Go pointer to C (cgo rule violation)
type GoStruct struct { inner *int }

func violateCgoRules(gs *GoStruct) {
    C.take_ptr(unsafe.Pointer(gs))  // BUG: gs contains Go pointer gs.inner
    // Go GC may relocate gs.inner while C holds gs
}
```

### Safe:
```go
// Keep unsafe arithmetic strictly in one place with lifetime comments
func readByte_safe(buf []byte, offset int) (byte, error) {
    if offset < 0 || offset >= len(buf) {
        return 0, errors.New("index out of range")
    }
    return buf[offset], nil  // no unsafe needed
}

// Always pair C.CString with defer C.free
func passString_safe(s string) {
    cs := C.CString(s)
    defer C.free(unsafe.Pointer(cs))  // freed even on panic
    C.process_string(cs)
}

// Pass only C-allocated memory or primitive values across cgo boundary
func cgoSafe(data []byte) {
    if len(data) == 0 { return }
    C.take_bytes((*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data)))
    // &data[0] is a Go pointer but contains no Go pointers — cgo allows this
}
```

---

## 13. Python ctypes Patterns

### Vulnerable:
```python
import ctypes

lib = ctypes.CDLL("./libfoo.so")

# Buffer sizing mismatch — C function writes more than buffer holds
def call_fill(n):
    buf = ctypes.create_string_buffer(64)
    lib.fill_buffer(buf, n)   # BUG: if n > 64, overflow into adjacent memory

# ctypes.cast to wrong type
def bad_cast(ptr):
    # BUG: ptr may point to a different struct; accessing wrong fields
    obj = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_uint64))
    return obj[0]

# string_at without length — reads until NUL in C heap
def read_blob(ptr):
    # BUG: blob may not be NUL-terminated; reads OOB
    return ctypes.string_at(ptr)
```

### Safe:
```python
import ctypes

lib = ctypes.CDLL("./libfoo.so")

# Declare argtypes/restype so ctypes validates arguments
lib.fill_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
lib.fill_buffer.restype  = ctypes.c_int

def call_fill_safe(n):
    size = min(n, 64)                       # clamp to buffer size
    buf = ctypes.create_string_buffer(size)
    lib.fill_buffer(buf, size)              # C function given correct bound

# Use the correct target type and validate the source
def safe_cast(ptr, expected_type):
    return ctypes.cast(ptr, ctypes.POINTER(expected_type))

# Always supply length when reading non-NUL-terminated data
def read_blob_safe(ptr, known_length):
    return ctypes.string_at(ptr, known_length)  # reads exactly known_length bytes
```

---

## 14. Java JNI Patterns

### Vulnerable:
```java
// GetByteArrayElements without Release — GC pressure / pin leak
public native void processBytes(byte[] data);
```

```c
// In the JNI implementation:
JNIEXPORT void JNICALL Java_Foo_processBytes(JNIEnv *env, jobject obj, jbyteArray data) {
    jbyte *buf = (*env)->GetByteArrayElements(env, data, NULL);
    // BUG: if process() throws/returns early, Release is never called
    // Array stays pinned; GC cannot compact or collect it
    process((uint8_t *)buf, (*env)->GetArrayLength(env, data));
    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
}

// Critical section not released on error path
JNIEXPORT void JNICALL Java_Foo_critRead(JNIEnv *env, jobject obj, jbyteArray arr) {
    jbyte *p = (*env)->GetPrimitiveArrayCritical(env, arr, NULL);
    if (validate(p) < 0) return;  // BUG: critical section never released; JVM stuck
    (*env)->ReleasePrimitiveArrayCritical(env, arr, p, JNI_ABORT);
}
```

### Safe:
```c
JNIEXPORT void JNICALL Java_Foo_processBytes(JNIEnv *env, jobject obj, jbyteArray data) {
    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (!buf) return;  // OOM

    process((uint8_t *)buf, len);

    // Always release — JNI_ABORT = discard changes (use 0 to commit)
    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_Foo_critRead(JNIEnv *env, jobject obj, jbyteArray arr) {
    jbyte *p = (*env)->GetPrimitiveArrayCritical(env, arr, NULL);
    if (!p) return;

    int rc = validate(p);
    // Release BEFORE any other JNI calls or early returns
    (*env)->ReleasePrimitiveArrayCritical(env, arr, p, JNI_ABORT);

    if (rc < 0) throw_java_exception(env, "validation failed");
}
```

---

## 15. Node.js N-API Patterns

### Vulnerable:
```cpp
// Buffer::New ownership confusion → double free
// Node takes ownership of the data pointer; caller must NOT also free it
Napi::Value CreateBuffer(const Napi::CallbackInfo &info) {
    uint8_t *data = new uint8_t[1024];
    fill(data, 1024);
    auto buf = Napi::Buffer<uint8_t>::New(info.Env(), data, 1024);
    // BUG: finalizer will delete[] data when GC collects buf,
    // but caller may also delete[] data → double free
    delete[] data;
    return buf;
}

// UAF — GC collects JS object while native code still holds raw pointer
Napi::Value UseAfterGC(const Napi::CallbackInfo &info) {
    Napi::Object obj = info[0].As<Napi::Object>();
    MyData *raw = obj.Get("ptr").As<Napi::External<MyData>>().Data();
    // BUG: no persistent reference; GC may collect obj between here and use
    DoWork();           // JS callbacks may trigger GC
    raw->field = 1;     // UAF if obj was collected during DoWork()
    return info.Env().Undefined();
}
```

### Safe:
```cpp
// Provide a custom finalizer — do NOT free data manually after New()
static void Finalizer(Napi::Env /*env*/, uint8_t *data) {
    delete[] data;  // GC calls this exactly once
}

Napi::Value CreateBuffer_safe(const Napi::CallbackInfo &info) {
    uint8_t *data = new uint8_t[1024];
    fill(data, 1024);
    // Transfer ownership to Node; Finalizer is the sole free path
    return Napi::Buffer<uint8_t>::New(info.Env(), data, 1024, Finalizer);
    // do NOT delete[] data here
}

// Napi::Persistent keeps the JS object alive across GC cycles
struct WorkContext {
    Napi::Persistent<Napi::Object> ref;  // prevents GC
    MyData *raw;
};

Napi::Value UseAfterGC_safe(const Napi::CallbackInfo &info) {
    Napi::Object obj = info[0].As<Napi::Object>();
    WorkContext ctx;
    ctx.ref = Napi::Persistent(obj);     // GC-root; object will not be collected
    ctx.raw = obj.Get("ptr").As<Napi::External<MyData>>().Data();

    DoWork();           // GC cannot collect obj — ref is alive
    ctx.raw->field = 1; // safe: obj is still rooted
    ctx.ref.Reset();    // release root when done
    return info.Env().Undefined();
}
```
