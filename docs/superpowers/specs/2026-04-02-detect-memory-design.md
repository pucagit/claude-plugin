# detect-memory Skill Design

## Context

The security-research plugin has four detection skills (`detect-injection`, `detect-auth`, `detect-logic`, `detect-config`), but memory safety vulnerabilities are underserved — only covered as a small C/C++-only subsection in `detect-injection`. Memory bugs are among the most impactful vulnerability classes (RCE, info leak, privilege escalation) and span many languages via unsafe bindings (Rust unsafe, Go cgo, Python ctypes, Java JNI, Node.js N-API).

This skill creates a dedicated `detect-memory` skill that:
1. Provides comprehensive memory safety detection across all languages with unsafe memory access
2. Guides exploitation chain construction (info leak → primitive → ASLR bypass → RCE) with multi-allocator tactics
3. Removes the memory corruption subsection from `detect-injection` to eliminate overlap

Reference quality standard: modeled after REF1.md (RedisTimeSeries OOB Write + RCE) and REF2.md (RedisBloom Invalid Free + UAF → RCE) in `/home/kali/claude-plugin/mem_ref/`.

## Skill Structure

Follow the exact detect-* template used by all other detection skills:

```
skills/detect-memory/
├── SKILL.md                    ← Main skill file (frontmatter + all sections)
└── references/
    ├── patterns.md             ← Vulnerable vs. safe code patterns per language
    ├── payloads.md             ← Exploitation payloads and allocator-specific primitives
    ├── exploitation.md         ← Full chain construction guide (REF1/REF2 style)
    └── cool_techniques.md      ← Empty, populated by capture-technique
```

### SKILL.md Sections (in order)

#### 1. Frontmatter

```yaml
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
```

#### 2. Goal

Identify memory safety vulnerabilities in compiled code and unsafe language bindings. Trace bugs to exploitation primitives (arbitrary read/write, info leak, control flow hijack). Guide exploitation chain construction through allocator-specific tactics.

#### 3. Learned Techniques

Point to `references/cool_techniques.md`. Same format as other detect-* skills.

#### 4. Coverage Table

| Category | Sub-types |
|----------|-----------|
| Stack Buffer Overflow | strcpy/strcat/gets/sprintf, stack-based OOB write, VLA overflow |
| Heap Buffer Overflow | malloc+memcpy OOB, off-by-one heap, chunk metadata corruption |
| Use-After-Free | dangling pointer deref, UAF in error paths, iterator invalidation UAF |
| Double Free | explicit double free, error-path double free, conditional double free |
| Invalid/Arbitrary Free | free of stack/global pointer, free of attacker-controlled address, deserialization-path free |
| Type Confusion | void* cast mismatch, union type punning, polymorphic object confusion |
| Integer Overflow/Underflow | size calc overflow → undersized alloc, signed/unsigned comparison |
| Uninitialized Memory | stack var read before write, heap alloc without zeroing, partial struct init |
| Format String | printf with user-controlled format, syslog format injection |
| Out-of-Bounds Read | strlen on non-NUL-terminated buffer, array index OOB read (info leak) |
| Unsafe Language Bindings | Rust `unsafe {}`, Go cgo/`unsafe.Pointer`, Python ctypes/C extensions, Java JNI/Unsafe, Ruby C extensions, Node.js N-API/native addons |
| Allocator-Specific Exploitation | glibc ptmalloc (tcache/fastbin/unsorted bin), jemalloc (runs/tcache), musl-malloc, Windows heap (LFH/segment heap), V8/Go runtime allocators |

#### 5. Grep Patterns

Organized by vulnerability class. Each block has a comment explaining what the pattern catches and language-specific file filters.

**Dangerous Functions (C/C++):**
```bash
grep -rn "strcpy(\|strcat(\|gets(\|sprintf(\|vsprintf(\|strncpy(" --include="*.c" --include="*.cpp" --include="*.h" ${TARGET_SOURCE}
grep -rn "printf(\|fprintf(\|syslog(\|snprintf(" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
grep -rn "\bmalloc(\|\bcalloc(\|\brealloc(\|\bfree(" --include="*.c" --include="*.cpp" --include="*.h" ${TARGET_SOURCE}
grep -rn "\bdelete\b\|\bdelete\[\]" --include="*.cpp" --include="*.h" ${TARGET_SOURCE}
```

**Allocation Size Calculations:**
```bash
grep -rn "malloc(.*\*\|calloc(.*," --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
grep -rn "realloc(.*," --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
```

**Free + Use Patterns (UAF/Double Free):**
```bash
grep -rn "free(" --include="*.c" --include="*.cpp" -A5 ${TARGET_SOURCE} | grep -v "= NULL"
grep -rn "delete " --include="*.cpp" -A5 ${TARGET_SOURCE}
```

**Error Path Cleanup:**
```bash
grep -rn "goto\s\+\(err\|fail\|cleanup\|out\|error\|done\)" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
grep -rn "if.*err\|if.*fail\|if.*<\s*0" --include="*.c" --include="*.cpp" -A10 ${TARGET_SOURCE}
```

**Unsafe Language Bindings:**
```bash
grep -rn "unsafe {" --include="*.rs" ${TARGET_SOURCE}
grep -rn "unsafe\.Pointer\|C\.\|cgo" --include="*.go" ${TARGET_SOURCE}
grep -rn "ctypes\.\|cffi\.\|from ctypes" --include="*.py" ${TARGET_SOURCE}
grep -rn "JNIEnv\|GetByteArrayElements\|ReleasePrimitiveArrayCritical" --include="*.java" --include="*.c" ${TARGET_SOURCE}
grep -rn "napi_\|Napi::" --include="*.cc" --include="*.cpp" --include="*.h" ${TARGET_SOURCE}
grep -rn "rb_str_new\|RSTRING_PTR\|Data_Get_Struct" --include="*.c" --include="*.h" ${TARGET_SOURCE}
```

**Memory-Mapped I/O and Shared Memory:**
```bash
grep -rn "mmap(\|munmap(\|shm_open(" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
```

**Format String Sinks:**
```bash
grep -rn "printf(\|fprintf(\|syslog(\|err(\|warn(" --include="*.c" --include="*.cpp" ${TARGET_SOURCE} | grep -v '"%'
```

**Struct/Object Initialization:**
```bash
grep -rn "struct.*{" --include="*.c" --include="*.cpp" -A3 ${TARGET_SOURCE} | grep -v "= {0}\|= {}\|memset\|bzero"
```

**Cross-Module Boundaries:**
```bash
grep -rn "dlopen\|dlsym\|LoadLibrary\|GetProcAddress" --include="*.c" --include="*.cpp" ${TARGET_SOURCE}
grep -rn "RedisModule_\|PyArg_Parse\|napi_get_cb_info" ${TARGET_SOURCE}
```

#### 6. Detection Process

1. **Binary/Module Inventory** — Identify all compiled binaries, shared libraries (.so/.dll/.dylib), native extensions. For each, catalog: language, compiler, target architecture, and hardening properties (PIE, NX, stack canary, RELRO, CFI). Use `checksec`, `readelf -l`, or `otool -h`.

2. **Dangerous Function Scan** — Run the grep patterns above. Prioritize: functions with no bounds checking (strcpy, gets, sprintf) → functions with user-controlled size args (memcpy, realloc) → format string sinks with non-literal format args.

3. **Allocation-Use-Free Lifecycle Tracing** — For each allocation site found, use LSP `findReferences` and `callHierarchy` to trace the full lifecycle:
   - Where is memory allocated?
   - Where is it used (read/write)?
   - Where is it freed?
   - Is there a use-after-free gap? Missing free (leak)? Double free path?

4. **Integer Overflow in Size Calculations** — Trace user-controlled values into malloc/calloc/realloc size arguments. Check for: missing overflow guards, implicit truncation (size_t → int → size_t), multiplication overflow before allocation.

5. **Cross-Module Boundary Analysis** — Identify where data crosses module/library boundaries (plugin APIs, FFI, shared memory, serialization/deserialization). These are where type confusion, size mismatches, and lifetime mismatches occur. Example: REF1 — TimeSeries OOB write corrupted adjacent Bloom heap structures across module boundary.

6. **Error Path Audit** — For each function with cleanup/goto labels, trace every error/early-return path. Check: are all allocated resources freed exactly once? Are freed pointers set to NULL or made unreachable? Is state consistent on error return? Example: REF2 — RDB deserialization error path freed attacker-controlled heap pointers.

7. **Unsafe Language Binding Audit** — For non-C/C++ codebases:
   - Rust: audit all `unsafe {}` blocks for raw pointer arithmetic, transmute, slice::from_raw_parts with unchecked length
   - Go: audit cgo calls and `unsafe.Pointer` conversions for pointer passing rule violations
   - Python: audit ctypes/cffi buffer handling for size mismatches
   - Java: audit JNI code for GetByteArrayElements without matching Release, critical section violations
   - Node.js: audit N-API/nan for buffer lifecycle and prevent GC-during-native-call bugs

8. **Exploitation Primitive Assessment** — For each confirmed vulnerability, classify the primitive it provides:
   - **Arbitrary write**: heap overflow that overwrites adjacent structure fields, format string %n
   - **Arbitrary read**: OOB read, format string %s/%x, UAF-to-string-read
   - **Info leak**: stack/heap pointer leak for ASLR bypass, PIE base computation
   - **Control flow hijack**: function pointer overwrite, GOT overwrite, vtable corruption
   - Cross-reference with `references/exploitation.md` for allocator-specific chain construction.

#### 7. Confirmation Rules

| Pattern | Verdict |
|---------|---------|
| `strcpy(fixed_buf, user_str)` | CRITICAL — stack buffer overflow, RCE if canary absent |
| `malloc(user_len * elem_size)` without overflow check | HIGH — integer overflow → undersized heap alloc |
| `free(ptr); ... use(ptr)` with no NULL assignment between | HIGH — use-after-free |
| `free(ptr); ... free(ptr)` on any code path | HIGH — double free |
| `free(attacker_controlled_ptr)` | CRITICAL — arbitrary free primitive |
| `printf(user_string)` | HIGH — format string (read/write primitive) |
| `memcpy(dst, src, user_len)` where dst is fixed-size | CRITICAL — heap overflow |
| `unsafe { *raw_ptr }` without bounds validation | HIGH — Rust unsafe OOB access |
| `C.GoString(cPtr)` without length limit | MEDIUM — Go cgo buffer overread |
| `strcpy` into stack buffer with canary + ASLR + PIE | MEDIUM — exploitable but requires info leak chain |
| `malloc(n); memset(buf, 0, n)` | FALSE POSITIVE — properly initialized |
| `free(ptr); ptr = NULL;` | FALSE POSITIVE — safe UAF prevention |
| `snprintf(buf, sizeof(buf), "%s", input)` | FALSE POSITIVE — bounds-checked |

#### 8. LSP Integration

Same as other detect-* skills:
- `mcp__ide__getDiagnostics` for type checking and compiler warnings
- `findReferences` for tracking pointer/buffer usage across functions
- `goToDefinition` for custom allocator wrappers and free functions
- `callHierarchy` for tracing allocation → use → free chains across call boundaries
- Specific to memory: use LSP to resolve typedef chains (e.g., `RSTRING_PTR` → actual char* access), identify custom allocator wrappers (`xmalloc`, `safe_malloc`), and trace object lifecycle through constructor/destructor pairs

#### 9. Beyond Pattern Matching — Semantic Analysis

- **Custom Allocator Analysis**: Many projects wrap malloc/free. Identify wrappers (`zmalloc`, `xmalloc`, `g_malloc`, `PyMem_Malloc`) and treat them as allocation sites. Check if wrappers add safety (zeroing, overflow checks) or just forward.
- **Object Lifecycle State Machines**: For complex objects (connection handles, file descriptors, module contexts), model the state machine: ALLOCATED → INITIALIZED → IN_USE → FREED. Verify all transitions are valid and no state is skipped.
- **Serialization/Deserialization Boundaries**: RDB load, protobuf decode, JSON parse into native structs — these are high-value targets where attacker-controlled data directly influences allocation sizes and pointer values (per REF2: TopK RDB deserialization).
- **Heap Layout Reasoning**: When assessing exploitability, reason about heap adjacency. Which allocations are the same size class? What structures could be corrupted by an N-byte overflow? Reference allocator-specific behavior in `references/exploitation.md`.
- **Cross-Language Boundary Semantics**: At FFI boundaries, check: Who owns the memory? When is it freed? Are lifetimes correctly communicated? Does the binding layer copy or alias? GC-managed language calling into C is a UAF factory if lifetimes mismatch.

### Reference Files

#### `references/patterns.md`

Organized by vulnerability class, with per-language examples:

1. **Stack Buffer Overflow** — C/C++ (strcpy, gets, sprintf), safe alternatives (strncpy, strlcpy, snprintf)
2. **Heap Buffer Overflow** — malloc+memcpy patterns, off-by-one, safe alternatives
3. **Use-After-Free** — dangling pointer, iterator invalidation, error-path UAF. C++ unique_ptr vs raw pointer
4. **Double Free** — explicit, conditional, error-path. Safe: single cleanup path, RAII
5. **Invalid Free** — stack pointer free, deserialization-path free (REF2 pattern)
6. **Type Confusion** — void* casts, union punning, C++ RTTI bypass
7. **Integer Overflow** — size calc patterns, safe: `__builtin_mul_overflow`, `checked_mul`
8. **Uninitialized Memory** — stack/heap patterns, safe: `= {0}`, `memset`, `calloc`
9. **Format String** — printf family, syslog. Safe: literal format strings
10. **OOB Read** — strlen on non-NUL-terminated, array indexing. Info leak implications
11. **Rust unsafe** — raw pointer arithmetic, transmute, slice::from_raw_parts
12. **Go cgo** — unsafe.Pointer, C.CString without C.free, pointer passing violations
13. **Python ctypes** — buffer sizing, ctypes.cast, string_at without length
14. **Java JNI** — GetByteArrayElements lifecycle, critical section rules
15. **Node.js N-API** — Buffer::New ownership, prevent-GC patterns

#### `references/payloads.md`

1. **Stack Overflow Payloads** — offset finding (cyclic pattern), x86/x86-64 shellcode, ROP chain templates
2. **Format String Payloads** — stack reading (%x/%p), arbitrary write (%n), GOT overwrite, canary leak
3. **Heap Exploitation — glibc ptmalloc** — tcache poisoning, tcache key bypass (glibc 2.32+), fastbin dup, unsorted bin attack, house of force, safe-linking bypass
4. **Heap Exploitation — jemalloc** — region spray, run metadata corruption, tcache manipulation
5. **Heap Exploitation — musl-malloc** — group corruption, unbin attack
6. **Heap Exploitation — Windows** — LFH exploitation, segment heap tactics
7. **ASLR/PIE Bypass Techniques** — format string leak, partial overwrite, /proc/self/maps, auxiliary vector traversal (REF1 pattern), heap pointer scanning (REF1 pattern), DEBUG OBJECT info leak (REF2 pattern)
8. **Stack Canary Bypass** — format string leak, byte-by-byte brute force, overwrite with known value
9. **Control Flow Hijack** — GOT overwrite (partial RELRO), function pointer overwrite, vtable corruption, dictType.hashFunction hijack (REF1 pattern), moduleType hijack (REF2 pattern)
10. **Language-Specific** — Rust unsafe exploitation, Go runtime internals, Python object struct corruption

#### `references/exploitation.md`

Full exploitation chain construction guide, modeled after REF1/REF2 advisory format:

1. **Phase 1: Binary Hardening Assessment** — checksec table (PIE, NX, Canary, RELRO, CFI), per-binary and per-.so analysis, identify weakest link in module chain
2. **Phase 2: Primitive Classification** — Map confirmed vulnerability to primitive type (arbitrary read/write/free, info leak, control flow hijack)
3. **Phase 3: Information Leak Strategy** — Techniques per protection level:
   - No PIE: direct address usage
   - PIE + no ASLR: fixed base
   - Full ASLR+PIE: stack-based leak (auxiliary vectors, REF1 Chain 1), heap-based leak (pointer scanning, REF1 Chain 2), DEBUG/diagnostic leak (REF2), format string leak, partial overwrite
4. **Phase 4: Heap Grooming** — Allocator-specific:
   - glibc: tcache bin filling, fastbin consolidation, unsorted bin abuse, controlled free ordering
   - jemalloc: region spray for adjacency, run alignment exploitation
   - musl: group-based spray
   - Windows: LFH randomization defeat via spray volume
5. **Phase 5: Primitive Escalation** — Convert limited primitive to full arbitrary read/write:
   - OOB write → corrupt adjacent struct → gain stronger primitive
   - UAF → controlled reallocation → type confusion → arbitrary read/write
   - Info leak → compute base addresses → targeted overwrite
6. **Phase 6: Control Flow Hijack** — Targets by RELRO status:
   - Partial RELRO: GOT overwrite (REF1 Chain 2: strstr@GOT → system)
   - Full RELRO: function pointer in writable data (REF1 Chain 1: dictType.hashFunction → system)
   - C++: vtable pointer overwrite
   - Module/plugin: moduleType struct hijack (REF2: DEL triggers attacker-controlled function)
7. **Phase 7: Full Exploit Template** — pwntools template with: target setup, info leak stage, heap grooming stage, primitive construction, payload delivery, RCE trigger
8. **Chain Documentation Format** — Template matching REF1/REF2 advisory structure:
   - Root cause with file/function/line
   - CWE classification
   - Exploitation chain (numbered steps)
   - Binary hardening table
   - Prerequisites/special conditions
   - Reproduction steps
   - CVSS 3.1 scoring

#### `references/cool_techniques.md`

```markdown
<!-- Techniques are added by /security-research:capture-technique -->
```

Empty initially, populated during audits.

## Changes to security-orchestrator

Update `agents/security-orchestrator.md` to include `detect-memory` in the Phase 2 hunting skill invocation list, alongside the other detect-* skills.

## Changes to detect-injection

### Remove from SKILL.md:
- Coverage table: remove "Memory corruption" row
- Grep patterns: remove "Memory Corruption (C/C++ only)" subsection (lines ~151-157)
- Confirmation rules: remove strcpy, printf format, free/UAF rows (lines ~192-194)
- Add cross-reference: "For memory safety vulnerabilities (buffer overflow, UAF, format string, unsafe bindings), see `detect-memory`."

### Remove from references/:
- `patterns.md`: remove Section 12 "Memory Corruption" (lines ~1122-1260)
- `payloads.md`: remove Section 13 "Memory Corruption Payloads" (lines ~981-1078)
- `exploitation.md`: remove Section 11 "Memory Corruption Exploitation" (lines ~838-1000+)
- Add cross-reference note at former locations: "Memory corruption content moved to detect-memory skill."

## Verification

1. Invoke `detect-memory` against a C/C++ project with known memory bugs — confirm grep patterns fire and detection process finds vulnerabilities
2. Invoke `detect-memory` against a Rust project with `unsafe` blocks — confirm unsafe binding audit works
3. Verify `detect-injection` no longer contains memory-related content
4. Verify the orchestrator can invoke `detect-memory` alongside other detect-* skills
5. Run a test audit comparing findings quality against REF1/REF2 advisory format
