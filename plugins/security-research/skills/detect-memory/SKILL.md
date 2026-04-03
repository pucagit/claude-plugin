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

When done, report: DONE
