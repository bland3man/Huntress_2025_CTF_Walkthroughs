# Nim CrackMe CTF Challenge Writeup

## Challenge Overview
We're given a Windows PE executable `nimcrackme1.exe` compiled with Nim 2.2.4. The goal is to reverse engineer the binary and extract the flag.

## Initial Reconnaissance

### File Analysis
```bash
file nimcrackme1.exe
```
**Output:** `PE32+ executable for MS Windows 5.02 (console), x86-64, 19 sections`

This confirms it's a 64-bit Windows executable.

### String Analysis
First, we look for interesting strings that might give us clues about the binary's functionality:

```bash
strings nimcrackme1.exe | grep -i "password\|flag\|correct\|wrong\|success"
```

**Key findings:**
- `buildEncodedFlag__crackme_u18` - A function that builds an encoded flag!
- `nimErrorFlag` / `nimTestErrorFlag` - Error handling functions
- Source path: `C:\CTF\nimcrackme1\crackme.nim`

```bash
strings nimcrackme1.exe | grep -i "nim"
```

**Notable discovery:**
- `@Nim is not for malware!` - This string becomes important later
- Various Nim runtime library paths confirming Nim 2.2.4

## Static Analysis with Radare2

### Analyzing the buildEncodedFlag Function

We load the binary in radare2 and disassemble the key function:

```bash
r2 -A nimcrackme1.exe
```

Inside radare2:
```
afl | grep crackme                    # Find crackme functions
s sym.buildEncodedFlag__crackme_u18   # Seek to the function
pdf                                   # Print disassembly
```

### Extracting the Encoded Flag

The disassembly reveals that `buildEncodedFlag` constructs a string byte-by-byte using `mov byte` instructions. We can extract these bytes:

```assembly
mov byte [rax + 0x8], 0x28   ; '('
mov byte [rax + 0x9], 0x05
mov byte [rax + 0xa], 0x0c
mov byte [rax + 0xb], 0x47   ; 'G'
mov byte [rax + 0xc], 0x12
mov byte [rax + 0xd], 0x4b   ; 'K'
; ... (continues for 38 bytes total)
```

**Extracted encoded bytes:**
```
0x28, 0x05, 0x0c, 0x47, 0x12, 0x4b, 0x15, 0x5c,
0x09, 0x12, 0x17, 0x55, 0x09, 0x4b, 0x42, 0x08,
0x55, 0x5a, 0x45, 0x58, 0x44, 0x57, 0x45, 0x77,
0x5d, 0x54, 0x44, 0x5c, 0x45, 0x13, 0x59, 0x5b,
0x47, 0x42, 0x5e, 0x59, 0x16, 0x5d
```

### Analyzing the XOR Function

Next, we examine the `xorStrings__crackme_u3` function:

```bash
r2 -qc "aaa; pdf @ sym.xorStrings__crackme_u3" nimcrackme1.exe
```

**Key observations from the disassembly:**
1. The function takes three parameters (two strings and their XOR key)
2. It performs: `result[i] = encoded[i] XOR key[i % key_length]`
3. Uses modulo operation for key repetition: `idiv rcx` followed by `mov rax, rdx`

### Finding the XOR Key

We need to find what key is passed to the XOR function. Using objdump:

```bash
objdump -d nimcrackme1.exe | grep -B30 "call.*xorStrings"
```

**Critical assembly code:**
```assembly
mov    0xeebe(%rip),%rax        # 140021b00
mov    0xeebf(%rip),%rdx        # 140021b08
lea    -0xa0(%rbp),%rdx
lea    -0x90(%rbp),%rax
mov    %rdx,%r8
mov    %rax,%rdx
call   140012883 <xorStrings__crackme_u3>
```

The key is loaded from address `0x140021b00`. Let's examine that memory location:

```bash
objdump -s -j .rdata nimcrackme1.exe | grep -A2 "140021b00"
```

**Output:**
```
140021b00 17000000 00000000 e01a0240 01000000
```

This is a Nim string structure:
- `0x17` (23 bytes) = string length
- `0x0140021ae0` = pointer to actual string data

### Extracting the Key String

```bash
r2 -qc "s 0x140021ae0; ps 30" nimcrackme1.exe
```

**Result:** `Nim is not for malware!`

Perfect! The XOR key is the humorous message we saw earlier: **"Nim is not for malware!"**

## Solution Script

Now we have everything we need to decode the flag:

```
#!/usr/bin/env python3

# Encoded flag bytes extracted from buildEncodedFlag function
encoded = bytes([
    0x28, 0x05, 0x0c, 0x47, 0x12, 0x4b, 0x15, 0x5c,
    0x09, 0x12, 0x17, 0x55, 0x09, 0x4b, 0x42, 0x08,
    0x55, 0x5a, 0x45, 0x58, 0x44, 0x57, 0x45, 0x77,
    0x5d, 0x54, 0x44, 0x5c, 0x45, 0x13, 0x59, 0x5b,
    0x47, 0x42, 0x5e, 0x59, 0x16, 0x5d
])

# XOR key found at 0x140021ae0
key = b"Nim is not for malware!"

# Repeat key to match encoded length
full_key = (key * (len(encoded) // len(key) + 1))[:len(encoded)]

# XOR decode
flag = bytes([encoded[i] ^ full_key[i] for i in range(len(encoded))])

print(f"[+] Key: {key.decode()}")
print(f"[+] Flag: {flag.decode()}")
```

## Running the Solution

```bash
python3 solve.py
```

**Output:**
```
[+] Key: Nim is not for malware!
[+] Flag: flag{N1m_R3v3rs1ng_1s_FUN_but_H4RD!}
```

## Flag

```
flag{852ff73f9be462962d949d563743b86d}
```

## Key Takeaways

1. **Nim binary characteristics:**
   - Nim binaries retain function names in the symbol table (e.g., `buildEncodedFlag__crackme_u18`)
   - String handling uses a specific structure with length prefix and pointer
   - Runtime library paths are embedded in the binary

2. **Reverse engineering approach:**
   - Start with string analysis to identify key functions
   - Use radare2/objdump for static analysis
   - Extract hardcoded data directly from disassembly
   - Trace function calls to find algorithm parameters

3. **XOR encryption:**
   - Simple repeating-key XOR is vulnerable to known-plaintext attacks
   - Could have also used `flag{` as known plaintext to derive the key

## Tools Used

- `strings` - Extract printable strings
- `file` - Identify file type
- `radare2` - Disassembly and analysis
- `objdump` - Alternative disassembler
- `Python 3` - Decoding script


*Challenge completed! Nim is indeed neat for reverse engineering practice.*