---
name: detect-memory
description: Detect memory corruption vulnerabilities in C/C++ and unsafe Rust code: buffer overflows, heap overflows, use-after-free, double free, integer overflow leading to buffer overflow, format string vulnerabilities, and out-of-bounds access. Skip this skill if no native code (C/C++/unsafe Rust) is detected in the target.
argument-hint: "<target_source> <audit_dir>"
user-invokable: false
---

# Memory Corruption Vulnerability Detection

## Goal
Find memory safety violations in native code that can be exploited for arbitrary code execution, information disclosure, or denial of service.

## Applicability Check
First, determine if this skill applies:
```bash
# Check for C/C++ or Rust unsafe code
find ${TARGET_SOURCE} -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.cc" 2>/dev/null | head -5
grep -rn "unsafe {" --include="*.rs" ${TARGET_SOURCE} | head -5
```
If no C/C++ files and no unsafe Rust blocks found: **skip this skill** and note "detect-memory: skipped — no native code detected."

## Sub-Types Covered
- **Stack buffer overflow** — Fixed-size stack buffer overwritten by unbounded input
- **Heap buffer overflow** — Heap allocation overwritten beyond its bounds
- **Use-after-free (UAF)** — Memory accessed after being freed
- **Double free** — `free()` called twice on same pointer
- **Integer overflow → buffer overflow** — `malloc(n * user_val)` without overflow check
- **Format string** — User input used as printf format argument
- **Out-of-bounds read/write** — Array access without bounds checking
- **Race condition in memory** — TOCTOU in memory allocation/deallocation
- **Type confusion** — Object cast to incompatible type
- **Null pointer dereference** — Dereferencing unchecked pointer → DoS

## Grep Patterns

### Dangerous String/Memory Functions (C/C++)
```bash
grep -rn "strcpy(\|strcat(\|gets(\|sprintf(\|vsprintf(\|scanf(\"%s\"\|stpcpy(\|wcscpy(\|wcscat(" \
  --include="*.c" --include="*.cpp" --include="*.h" --include="*.cc" \
  ${TARGET_SOURCE}
```

### Unbounded memcpy / Memory Allocation
```bash
grep -rn "memcpy(\|memmove(\|memset(\|malloc(\|calloc(\|realloc(\|alloca(" \
  --include="*.c" --include="*.cpp" --include="*.h" --include="*.cc" \
  ${TARGET_SOURCE}
```

### Format String Vulnerabilities
```bash
grep -rn "printf(\|fprintf(\|sprintf(\|snprintf(\|syslog(\|err(\|warn(\|vprintf(\|dprintf(" \
  --include="*.c" --include="*.cpp" \
  ${TARGET_SOURCE}
```

### free() Usage (UAF / Double Free)
```bash
grep -rn "\bfree(\b\|delete \b\|delete\[\]" \
  --include="*.c" --include="*.cpp" --include="*.h" \
  ${TARGET_SOURCE}
```

### Integer Overflow in Size Calculations
```bash
grep -rn "malloc(\|calloc(\|new.*\[\|realloc(" \
  --include="*.c" --include="*.cpp" \
  ${TARGET_SOURCE} | grep -E "\*|size_t|int.*len|user"
```

### Unsafe Rust
```bash
grep -rn "unsafe {" --include="*.rs" ${TARGET_SOURCE}
grep -rn "raw_pointer\|as \*mut\|as \*const\|std::ptr\|ptr::read\|ptr::write\|offset(" \
  --include="*.rs" ${TARGET_SOURCE}
```

## Detection Process

1. Run grep patterns to find dangerous function calls.
2. For each `strcpy(dst, src)`: trace `src` — is it user-controlled? Is `dst` a fixed-size buffer?
3. For `sprintf(buf, fmt, ...)`: check if `buf` is fixed-size and `fmt`/args can overflow it.
4. For `printf(user_input)` where user_input is the first (format) arg: format string vulnerability.
5. For `malloc(n * user_val)`: check for integer overflow guard before allocation.
6. For `free(ptr)`: search for subsequent uses of `ptr` in the same function and callees.
7. For double free: trace control flow paths — can `free(ptr)` be called twice?
8. For unsafe Rust: check if raw pointer arithmetic is bounded by slice length.

## Confirmation Rules

| Pattern | Verdict |
|---|---|
| `strcpy(fixed_buf, user_str)` | CRITICAL — classic stack overflow |
| `strncpy(buf, user_str, sizeof(buf))` | LOW — bounded (verify null termination) |
| `gets(buf)` | CRITICAL — always vulnerable |
| `fgets(buf, sizeof(buf), stdin)` | FALSE POSITIVE |
| `printf(user_format)` | HIGH — format string |
| `printf("%s", user_string)` | FALSE POSITIVE |
| `malloc(len * sizeof(int))` without overflow check | MEDIUM — integer overflow |
| `malloc(checked_mul(len, sizeof(int)))` | FALSE POSITIVE |
| `free(ptr); /* ... */; *ptr = val` | HIGH — use-after-free |
| `if (ptr) free(ptr); if (ptr) free(ptr);` | HIGH — double free |
| `buf[user_index]` without bounds check | HIGH — OOB read/write |

## Reference Files

- [Vulnerable C/C++ patterns with safe alternatives](references/patterns.md)
- [Memory corruption payloads: shellcode, ROP gadgets, heap spray](references/payloads.md)
- [Exploitation guide: stack overflow to RCE, heap exploitation, format string leaks](references/exploitation.md)
