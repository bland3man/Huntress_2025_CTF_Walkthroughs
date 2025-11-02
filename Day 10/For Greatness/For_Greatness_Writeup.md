
# Huntress 2025 — **For Greatness** (Web Challenge) Write‑Up

**Category:** Web / Malware Deobfuscation  
**Goal:** Extract the hidden flag from an obfuscated PHP payload found on the target.  
**Author:** bland3man

---

## TL;DR

We found an obfuscated `j.php` loader that executed a deeply‑encoded payload. By carving base64 chunks, reversing specific layers, and iteratively decoding/decompressing, we recovered a deobfuscated PHP blob and then the flag. Automation scripts + a small bash carver made this fast and repeatable.

**Flag:** _Add your final flag here once you have it_ → `flag{...}`

> If you’re re‑running the chain, drop the suspicious PHP into the same directory as the helper scripts and follow the “Reproduce” section.

---

## Artifacts (from the investigation)

- `j.php` / `jCode.php` — initial obfuscated PHP loader (suspicious startup file)
- `deobfuscated_j.php` — cleaned/pretty version after first deobfuscation pass
- `decoded_blob.php` — decoded payload recovered from the inner layers
- `stringsJ.txt` — quick `strings`/greps over the PHP to find clues
- Helper scripts:
  - `decodeREverse.py` / `decodeReversebase64.py` — python helpers for base64‑then‑reverse (or reverse‑then‑base64) layers
  - `phpdecodebin.sh` — bash pipeline to carve base64 runs from binaries/blobs and attempt multiple decode/decompress strategies

> The bash pipeline proved especially useful when multiple embedded base64 segments existed or when the payload mixed encodings/compressions.

---

## High‑level Analysis

1. **Obfuscation fingerprint.**  
   The loader contains classic tricks: heavy string escapes, indirect function construction, `eval` on a base64/URL‑safe payload, and sometimes *reversed* base64 layers to avoid naive scanners. A quick `strings` preview and pattern hunt showed a large base64‑like alphabet and `eval`/dynamic function calls.

2. **Layer peeling.**  
   The chain looked like:
   - base64 (sometimes reversed text first), then
   - optional compression (`zlib`/`gzip`), then
   - optional transforms (ROT13 or character map), then
   - PHP stager that `eval`s the final code.

   The presence of non‑ASCII sequences around large `[A-Za-z0-9+/=]` runs and magic header bytes after base64 decode (e.g., `1F 8B` for gzip) guided which decoder we tried next.

3. **Decoded payload inspection.**  
   After peeling layers we obtained a readable PHP (`decoded_blob.php`). Open it and search for obvious I/O or `eval` sinks and any constants that look like the flag or flag builder.

---

## Reproduce (step‑by‑step)

> Assumes you have Python 3 and basic GNU tools. If you only have Windows, use WSL or Git‑Bash for the bash pieces. PowerShell equivalents also work.

### 0) Quick reconnaissance

```bash
# quick triage
file j.php || true
head -n 40 j.php
grep -aEo '[A-Za-z0-9+/=]{40,}' -n j.php | sed -n '1,10p'
```

- Look for **very long** base64 runs (≥80 chars). If you see suspicious blocks but decoding fails, try **reverse()** first.

### 1) Try base64 + reverse helper

Two common patterns:

- **Reverse → Base64 decode** (text was reversed to avoid scanners), or
- **Base64 decode → Reverse** (payload expects a second reversal after decode).

Example Python skeleton used in this challenge:

```python
import base64, sys, re
s = open('j.php','rb').read()
m = re.search(rb'([A-Za-z0-9+/=]{80,})', s)
assert m, "no long base64 detected"
blob = m.group(1)

# try "reverse-then-decode"
rev = blob[::-1]
pad = b'=' * ((4 - len(rev) % 4) % 4)
dec = base64.b64decode(rev + pad)

open('layer1.bin','wb').write(dec)
print("wrote layer1.bin")
```

If `layer1.bin` looks compressed, try common decompressors (gzip/zlib/bz2/lzma) on it.

### 2) Use the multi‑carver when there are many chunks

The provided `phpdecodebin.sh` script automates:
- enumerating candidate blobs,
- decoding base64 with padding fixups,
- attempting gzip/zlib/bz2/lzma,
- grepping outputs for a flag pattern.

Run it from the repo root (it expects a `recovered/` directory with your input blobs, but you can adapt the globs easily):

```bash
bash phpdecodebin.sh
```

This prints a table of inputs, previews, and any decoded outputs written under `recovered/decoded_inspections/...`. It also scans for `flag{32-hex}` automatically.

### 3) Inspect the cleaned PHP

After peeling layers, we ended with a readable PHP payload (`decoded_blob.php`). Open it and search for obvious I/O or `eval` sinks and any constants that look like the flag or flag builder.

```bash
sed -n '1,200p' decoded_blob.php
grep -nE 'flag\{|base64_decode|gz(in)?flate|eval|system|assert' decoded_blob.php
```

If the flag is constructed dynamically, either emulate the small portion or replace the final `eval(...)` with a `print(...)`/`var_dump(...)` to expose the flag string without executing unknown code.

---

## What we found

- The inner decoded payload (`decoded_blob.php`) contained the functionality we needed and the flag source. From there, obtaining the flag was straightforward without analyzing unrelated branches of the malware/stager.

> The final step was simply to extract/print that constant/variable and submit the value.

---

## Notes & Safety

- Avoid executing unknown PHP with `eval`. Prefer static deobfuscation and string reconstruction.
- If you must run code, sandbox it (container or locked‑down PHP install) and **remove all network/syscall surfaces** first.
- The bash carver intentionally writes outputs to a separate subdirectory and only reads as bytes.

---

## Appendix A — Commands used (minimal)

```bash
# carve & decode long base64 runs (reverse-first flavor)
python3 decodeReversebase64.py j.php
file layer1.bin && xxd -l 64 layer1.bin

# try decompressions
python3 - <<'PY'
import sys,gzip,zlib,bz2,lzma
data=open('layer1.bin','rb').read()
for name,fn in [('gzip',gzip.decompress),('zlib',zlib.decompress),
                ('bz2',bz2.decompress),('lzma',lzma.decompress)]:
    try:
        out=fn(data); open(f'layer1.{name}','wb').write(out); print('OK',name)
    except Exception: pass
PY

# or run the multi-carver on multiple candidates
bash phpdecodebin.sh
```

---

## Appendix B — Indicators (generic)

- Obfuscated PHP with `eval` on base64‑like strings
- Reversal step preceding base64 decode
- Compressed post‑decode payloads (gzip/zlib)
- Reconstructed payload contained cleartext strings and straightforward flag logic

---

## Credit

Workflow & artifacts by **bland3man**. This write‑up consolidates the scripts and steps used to recover the flag during the event.
