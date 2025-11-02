# Rust Tickler CTF Write‑Up

**Challenge hint:** “Ooooh Rust! AND tickles? Rusty tickles…?”

**Solver:** bwallace  
**Date:** 2025-10-23 13:12:33

---

## 1. Initial Inspection

We received a single Windows executable named `rust_tickler`.

```bash
file rust_tickler
```
Output:
```
PE32+ executable for MS Windows 6.00 (console), x86-64
```

That suggests a Rust binary (not surprising from the hint).

---

## 2. Static Analysis with Radare2

We loaded the binary in **radare2** and began with full analysis:

```bash
r2 -AA rust_tickler
s main
pdf
```

The disassembly showed `main` calling another function `fcn.140002250`, which in turn invoked `fcn.140006590`. These functions primarily set up Windows exception handlers and synchronization primitives — typical Rust runtime boilerplate.

Example snippet:

```asm
call qword [sym.imp.KERNEL32.dll_AddVectoredExceptionHandler]
call qword [sym.imp.KERNEL32.dll_SetThreadStackGuarantee]
call qword [sym.imp.KERNEL32.dll_GetCurrentThread]
```

Nothing here handled user input or strings — it’s all standard threading infrastructure.

---

## 3. Hunting for Suspicious Data

Next, we inspected static data sections for embedded strings:

```bash
iz
```

Among the results, one stood out in the `.data` segment:

```
7=06*gagg30d03gf2`f5g5dba3c0hhcd2c`4b,
```

This was the only unusual ASCII string that looked obfuscated — possibly the flag ciphertext.

---

## 4. Testing Decoding Hypotheses

Given the challenge hint (“tickles”), we suspected XOR encoding — a common “tickle” of bytes.

We wrote a simple Python brute‑forcer to XOR each character of the string against all printable ASCII keys (32–126).

```python
s = b"7=06*gagg30d03gf2`f5g5dba3c0hhcd2c`4b,"
for k in range(32, 127):
    decoded = bytes([c ^ k for c in s])
    if all(32 <= b <= 126 for b in decoded):
        print(k, chr(k), decoded)
```

Running this yielded many gibberish lines until **key 81 ('Q')**, which revealed:

```
flag{6066ba5ab67c17d6d530b2a9925c21e3}
```

---

## 5. Verifying the Result

The result perfectly matches typical CTF flag syntax.

**Final Flag:** `flag{6066ba5ab67c17d6d530b2a9925c21e3}`

---

## 6. Lessons Learned

- The binary’s misleading complexity (with synchronization and panic handlers) was due to Rust’s standard runtime, not the challenge logic.  
- The author embedded a single encoded string, expecting solvers to separate real logic from Rust internals.  
- The “tickle” clue pointed straight to a byte‑wise XOR “tickle.”

---

## 7. Command Summary

```bash
# Static inspection
file rust_tickler
strings rust_tickler | less

# Deep disassembly
r2 -AA rust_tickler
s main
pdf
iz

# XOR brute force
python3 xor_decode.py
```

---

**Flag:** `flag{6066ba5ab67c17d6d530b2a9925c21e3}`
