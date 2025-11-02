# Huntress 2025 — For Greatness (Malware) Write‑Up
**Category:** Malware / Web Deobfuscation  
**Author:** Blandman3  
**Goal:** Extract the hidden flag from an obfuscated PHP payload found in a phishing kit.

---

## TL;DR
A single obfuscated **`j.php`** loader hid a multi‑layer payload. I short‑circuited execution by swapping a sink for `echo`, carved the inner **Base64** blob, handled a misleading **`gzuncompress()`** hint, and iteratively decoded until the final PHP appeared. The payload’s mailer function embeds the flag inside the **From** header.

**Flag:** `flag{f791310cef49f4d25d0778107033117f}`

---

## Artifacts
- `j.php` / `jCode.php` — initial obfuscated PHP loader (from the kit)
- `deobfuscated_j.php` — first readable pass
- `decoded_blob.php` — inner decoded payload
- `stringsJ.txt` — quick grep/strings output
- Helpers:
  - `decodeREverse.py`, `decodeReversebase64.py` — reverse/base64 toy decoders
  - `phpdecodebin.sh` — bash carver that tries b64 → decompress combos

> These are optional; you can reproduce with just stock PHP/Python/CLI.

---

## High‑Level Notes
- Classic obfuscation: **escaped octal/hex**, **indirect function construction**, **`eval` on decoded content**.
- Multiple layers of **Base64**; a **`gzuncompress(): data error`** after base64 decode was a *clue to try other layers first*, not a dead end.
- Final payload exposes a `mailTo()` that contains the **flag disguised inside the From address**.

---

## Step‑by‑Step

### 1) Stop the stager from executing and make it print
Open `j.php`. Find the point right before dynamic execution. In my sample the execution hop labeled `NmVIQ` was the pivot. I replaced the sink with `echo` so I could dump the next blob safely.

```php
// Before: code ultimately flows to an eval-like sink
goto NmVIQ;

// After: replace with echo to dump the next stage
NmVIQ: echo "... long \ooo\xxx escaped string ...";
```

Run it:

```bash
php j.php > stage0_dump.txt
```

This produced a **long Base64 string** (several kilobytes).

---

### 2) Decode Base64; treat `gzuncompress()` as a hint, not a requirement
First pass:

```bash
base64 -d stage0_dump.txt > stage1.bin || true
```

Trying `gzuncompress()` directly throws:

```
Warning: gzuncompress(): data error
```

That’s fine—this commonly signals **“there’s another transform first”** (e.g., second Base64 block, reversed text, or different compressor).

---

### 3) Carve and iterate through typical combos
Quick and dirty carve of large Base64 runs, then try decode + decompress families:

```bash
grep -aEo '[A-Za-z0-9+/=]{80,}' stage0_dump.txt | while read b; do
  printf '%s' "$b" | base64 -d 2>/dev/null |   (gzip -dc 2>/dev/null || zlib-flate -uncompress 2>/dev/null || cat) >> stage_mash.bin
done
```

(You can swap in `phpdecodebin.sh` to automate more formats; it brute‑tests Base64 with padding fixes + gzip/zlib/bz2/lzma attempts.)

Result was a readable PHP blob saved as **`decoded_blob.php`**.

---

### 4) Read the final payload instead of running it
Open the decoded PHP and search for sinks and obvious IOCs:

```bash
grep -nE 'mail\(|flag\{|From:|base64_decode|gz(in)?flate|eval' decoded_blob.php
```

In my sample the **mailer** was the giveaway:

```php
public function mailTo($add, $cont){
    $subject = '++++Office Email From Greatness+++++';
    $headers = 'Content-type: text/html; charset=UTF-8' . "\r\nFrom: Greatness <ghost+}f7113307018770d52d4f94fec013197f{galf@greatness.com>" . "\r\n";
    @mail($add, $subject, $cont, $headers);
}
```

That `From` address hides the flag in reverse order (`...}...{galf`). Reverse/normalize and you get:

```
flag{f791310cef49f4d25d0778107033117f}
```

No need to execute anything on a live interpreter.

---

## Why the `gzuncompress()` warning mattered
A lot of kits sprinkle calls to `gzinflate/gzuncompress` *after* an additional transform. Hitting the warning simply told me **“you decoded too early”**. The fix was to **peel another Base64 (or reverse) layer** first, then try decompression again. The bash carver makes this mechanical.

---

## Reproduce (minimal commands)
```bash
# 1) Dump the inner blob by neutering the sink to echo
php j.php > stage0_dump.txt

# 2) Base64 decode
base64 -d stage0_dump.txt > stage1.bin || true

# 3) Try decompress families (skip failures)
python3 - <<'PY'
import gzip,zlib,bz2,lzma,sys
d=open('stage1.bin','rb').read()
for name,fn in [('gzip',gzip.decompress),('zlib',zlib.decompress),
                ('bz2',bz2.decompress),('lzma',lzma.decompress)]:
    try:
        out=fn(d); open(f'stage1.{name}.php','wb').write(out); print('OK',name)
    except Exception: pass
PY

# 4) Inspect for IOCs / the flag
grep -nE 'flag\{|From:|mail\(' stage1.*.php decoded_blob.php || true
```

---

## Indicators of Compromise (generic)
- Obfuscated PHP loader with eval/dynamic function construction
- Multiple Base64 layers, sometimes reversed
- Optional gzip/zlib in the chain
- Suspicious mailer with hard‑coded “From” and/or exfil address

---

## Final Answer
**Flag:** `flag{f791310cef49f4d25d0778107033117f}`
