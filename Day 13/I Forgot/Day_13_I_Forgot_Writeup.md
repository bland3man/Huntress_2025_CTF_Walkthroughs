
# Day 13 — **I Forgot** (Forensics / Volatility / RSA→AES)

**Me:** Ransomware hit, ransom paid, VM crashed mid‑decrypt… and the key was “forgotten.” We *did* have a shaky backup: a memory dump and an encrypted flag. The goal was to reconstruct the decryption path from memory.

- **Archive password:** `i_forgot`  
- **Given files:** `flag.enc`, `memdump.dmp`

---

## TL;DR
1. Used **Volatility** + **strings** to find traces of a helper tool and a ZIP path: `Desktop\DECRYPT_PRIVATE_KEY.zip`.
2. Recovered that ZIP **directly from memory** by carving `PK` regions and matching a **SHA‑256** fingerprint seen in strings.
3. ZIP contained `private.pem` (RSA) and `key.enc` (RSA‑encrypted AES materials).
4. Decrypted `key.enc` with `private.pem` (RSA‑OAEP) to obtain **AES key (32 bytes)** and **IV (16 bytes)**.
5. Decrypted `flag.enc` with **AES‑256 (CBC)** → **`flag{fa838fa9823e5d612b25001740faca31}`**.

---

## 1) Recon in the memory dump

File layout:
```text
.
├── flag.enc
└── memdump.dmp
```

Volatility file scan (Windows profile via Vol3 plugins), looking for user artifacts and desktop executables:

```bash
python3 vol.py -f memdump.dmp windows.filescan | grep -i "\Users\User\Desktop"
# … found: \Users\User\Desktop\BackupHelper.exe
```

Dumping the PE straight from `filescan` failed (not uncommon). I pivoted to **string sweeping** to catch log lines/paths:

```bash
strings memdump.dmp > allstrings.txt
# Find helper references / ZIP hints
grep -n "BackupHelper"     allstrings.txt | sed -n '1,10p'
grep -n "DECRYPT_PRIVATE"  allstrings.txt | sed -n '1,10p'
```

Hits included:
```
BackupHelper started: 2025-09-28T04:41:52Z
ZipPath: C:\Users\User\Desktop\DECRYPT_PRIVATE_KEY.zip
ZIP read: 1938
SHA256: d1f9bd7084f5234400f878971fa7ccba835564845f0b10479efd5c38bd184f09
AND FILE RECOVERY INSTRUCTIONS
The private key to decrypt is stored in 'DECRYPT_PRIVATE_KEY.zip'.
ZIP password: ePDaACdOCwaMiYDG
```

So the ZIP existed on Desktop (likely deleted), and the exact **SHA‑256** of the archive content was recorded in memory.

---

## 2) Carve the ZIP by magic bytes + verify SHA‑256

I enumerated ZIP signatures in the dump and carved candidate chunks between `PK\x03\x04` and `PK\x05\x06`. Then I matched the chunk’s SHA‑256 to the value found in strings.

```python
# extract_zip.py
import re, hashlib, sys
data = open("memdump.dmp","rb").read()
starts = [m.start() for m in re.finditer(b"PK\x03\x04", data)]
ends   = [m.start() for m in re.finditer(b"PK\x05\x06", data)]

wanted = "d1f9bd7084f5234400f878971fa7ccba835564845f0b10479efd5c38bd184f09"
for s in starts:
    e = next((x for x in ends if x > s), None)
    if not e: continue
    blob = data[s:e+22]  # include EOCD record
    if hashlib.sha256(blob).hexdigest() == wanted:
        open("DECRYPT_PRIVATE_KEY.zip","wb").write(blob)
        print(f"[+] saved DECRYPT_PRIVATE_KEY.zip at offset {s}")
        break
```

Result:
```bash
python3 extract_zip.py
# [+] saved DECRYPT_PRIVATE_KEY.zip at offset 955469824

zipinfo DECRYPT_PRIVATE_KEY.zip
# private.pem (1708 bytes)
# key.enc     (256 bytes)
```

If the ZIP were passworded, I would use the recovered `ZIP password: ePDaACdOCwaMiYDG`. In my case, extraction was straightforward.

---

## 3) Decrypt the staged key (RSA → AES materials)

`key.enc` is the RSA‑encrypted container for the symmetric key/IV. Decrypt with the recovered private key:

```bash
openssl pkeyutl -decrypt -in key.enc -inkey private.pem -out key.bin -pkeyopt rsa_padding_mode:oaep

xxd -p key.bin
# First line:  32 bytes (64 hex)  → AES-256 key
# Second line: 16 bytes (32 hex)  → IV
# Example from my run:
# 289ea58a38549d5faf7a97a6dd19cdf2ddc0496a8a64f99a77c643529c94
# b8042c6a55b0a89141056517687a9773
```

> If direct RSA‑decrypt of `flag.enc` fails with OAEP errors, that’s the clue `flag.enc` is **not** RSA; it’s the **AES payload** that needs the materials from `key.enc`.

---

## 4) Decrypt `flag.enc` (AES‑256‑CBC)

You can use **CyberChef** (“From Hex/Raw” → AES Decrypt, key+IV in hex) or OpenSSL CLI. Example with OpenSSL (assuming CBC, no explicit salt header):

```bash
# write hex to files
KEY_HEX=289ea58a38549d5faf7a97a6dd19cdf2ddc0496a8a64f99a77c643529c94
IV_HEX=b8042c6a55b0a89141056517687a9773

# OpenSSL expects raw bytes, so pass hex via -K/-iv
openssl enc -d -aes-256-cbc -K "$KEY_HEX" -iv "$IV_HEX" -in flag.enc -out flag.txt

cat flag.txt
# flag{fa838fa9823e5d612b25001740faca31}
```

If you’re unsure about mode/padding, try `aes-256-cbc` first (common for simple ransomware stagers). CyberChef’s “Magic” can also detect structure post‑decryption.

---

## Notes
- **Volatility dumpfile** can fail on deleted/partial PEs; strings/heuristics often bail you out.
- Always grab **hashes** and **paths** leaked in memory—perfect anchors for carving.
- This chain used sensible crypto: **RSA‑OAEP** to protect a 48‑byte **AES-256 key + 16‑byte IV**, and **AES‑256‑CBC** for the data.
- The whole “I forgot” bit fits the narrative—**the key was in memory all along**.

---

**Flag:** `flag{fa838fa9823e5d612b25001740faca31}`
