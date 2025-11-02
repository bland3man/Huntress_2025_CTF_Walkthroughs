# Day 02 – **Spaghetti** (Startup “strings of pasta”)

> _“spaghetti is really just strings of pasta!”_  
Suspicious startup artifact contained obfuscated payloads embedded as long runs of `~` and `%`. Three sub‑prompts map to three discoveries: **MainFileSettings**, **My Fourth Oasis**, and **MEMEMAN**.

---

## TL;DR
- **MainFileSettings** → Decode a `~/%` blob as **binary** (`~→0`, `%→1`), then HTML‑decode entity strings to reveal the flag. fileciteturn1file0L10-L21 fileciteturn1file0L41-L59  
- **My Fourth Oasis** → Same `~/%` decoding across *all* chunks; concatenate; grep for the flag in text outputs. fileciteturn1file15L10-L20 fileciteturn1file15L33-L52  
- **MEMEMAN** → Two decoders: (1) Oasis-style `~/% → bits → bytes`, (2) “Homba” style `~→000`, `%→4` → hex bytes; stitch segments; look for text or images (BMP/PNG/GIF/JPG) that contain the flag beside “MEMEMAN.” fileciteturn1file1L12-L22 fileciteturn1file1L24-L34 fileciteturn1file13L27-L34

---

## Evidence: what the file looked like
Strings and pseudo‑script referenced an on‑disk `AYGIW.tmp`, web fetches, and lots of filler quotes—classic decoy noise. fileciteturn1file7L8-L13 fileciteturn1file9L30-L37

---

## Part 1 — **MainFileSettings** (4 pts)

### Approach
1. Extract the first long quoted blob of only `~` and `%`.  
2. Convert `~→0`, `%→1`; pack every 8 bits into a byte; write `main_decoded.*`.  
3. Some output was HTML‑entity text; HTML‑decode to surface `flag{…}`.  
   fileciteturn1file0L10-L27 fileciteturn1file0L41-L59

### Commands
```bash
# Find & decode the ~/% bitstring
python3 - <<'PY'
import re, pathlib, html
data = pathlib.Path("spaghetti").read_text(errors="ignore")
m = re.search(r'"([~%\s]{20,})"', data, flags=re.S)
raw = m.group(1)
bits = "".join(ch for ch in raw.replace("\n","").replace("\r","").replace("\t","").replace("~","0").replace("%","1") if ch in "01")
out = bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))
pathlib.Path("main_decoded.bin").write_bytes(out)
pathlib.Path("main_decoded.txt").write_text(out.decode("latin1","replace"))
# If text contains '&#…;' entities, decode them:
decoded = html.unescape(pathlib.Path("main_decoded.txt").read_text(errors="ignore"))
pathlib.Path("mainfile_html_decoded.txt").write_text(decoded)
print("Search for flag in mainfile_html_decoded.txt")
PY

grep -in "flag{" mainfile_html_decoded.txt || true
```
(Adapted directly from working notebook.) fileciteturn1file0L20-L31 fileciteturn1file0L45-L59

**Result:** Flag recovered from the HTML‑decoded text.

---

## Part 2 — **My Fourth Oasis** (3 pts)

### Approach
1. Collect **all** quoted `~/%` chunks.  
2. Decode each chunk `~→0`, `%→1` → bytes; if human‑readable, also emit a `.txt`.  
3. Concatenate all byte outputs (often one logical script) and sweep for `flag{`.  
   fileciteturn1file15L10-L20 fileciteturn1file15L33-L52

### Commands
```bash
python3 - <<'PY'
import re, glob, pathlib
src = pathlib.Path("spaghetti").read_text(errors="ignore")
chunks = re.findall(r'"([~%\s]{20,})"', src, flags=re.S)

def decode_bits(s):
    bits = s.translate(str.maketrans({"~":"0","%":"1"}))
    bits = "".join(ch for ch in bits if ch in "01")
    if len(bits)<8 or len(bits)%8: return None, None
    b = bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))
    return bits, b

decoded = []
for i,c in enumerate(chunks):
    bits,b = decode_bits(c)
    if not b: continue
    pathlib.Path(f"oasis_{i:02}.bin").write_bytes(b)
    if sum(32<=x<127 or x in (9,10,13) for x in b)/len(b) > 0.7:
        pathlib.Path(f"oasis_{i:02}.txt").write_text(b.decode("latin1","replace"))
    decoded.append(i)

combo = b''.join(pathlib.Path(f"oasis_{i:02}.bin").read_bytes() for i in sorted(decoded))
pathlib.Path("oasis_combined.bin").write_bytes(combo)
try:
    pathlib.Path("oasis_combined.txt").write_text(combo.decode("latin1","replace"))
except: pass

print("Possible flags:")
for f in sorted(glob.glob("oasis_*.txt")+glob.glob("oasis_combined.txt")):
    for n,line in enumerate(pathlib.Path(f).read_text(errors="ignore").splitlines(),1):
        if "flag{" in line.lower():
            print(f"{f}:{n}: {line.strip()}")
PY
```
**Result:** Flag observed in one of the per‑chunk `.txt` outputs / the combined script. fileciteturn1file15L41-L52

---

## Part 3 — **MEMEMAN** (beside the meme)

### Heuristic
Author hid a second payload “beside” the meme. We ran two decoders over each `~/%` blob:
- **Oasis**: `~/% → bits → bytes` (8‑bit packing)  
- **Homba**: `~→000`, `%→4` then interpret as hex pairs  
Stitch per‑method; attempt to render as images (BMP/PNG/GIF/JPG) or parse text; grep for `flag{`. fileciteturn1file1L12-L22 fileciteturn1file1L24-L34 fileciteturn1file13L27-L34

### One‑shot runner
```bash
python3 mememan.py
# produces mememan_oasis_XX.(bin/txt) and mememan_homba_XX.(bin/txt)
# also mememan_oasis_combined.* / mememan_homba_combined.* (image extensions auto-added)
```
(Decoder behavior & image heuristics.) fileciteturn1file13L15-L34

### Alt: brute carve if needed
If the spaghetti blob was noisy, we also carved BMPs directly (`BM` magic), split even/odd streams, stripped UTF‑8 noise bytes, and turned long hex runs into bytes—then re‑scanned for `BM`. fileciteturn1file12L27-L39 fileciteturn1file14L1-L11 fileciteturn1file14L13-L26 fileciteturn1file14L31-L41

**Result:** An image/text payload adjacent to the meme revealed the flag line.

---

## Notes & Indicators
- The script chunks and function names in the “spaghetti” strings hinted at custom decoders (`HombaAmigo`, `Oasis`). fileciteturn1file8L30-L36  
- A remote raw text fetch (`textbin`) appeared in the strings—useful context but not required once the local blobs were decoded. fileciteturn1file9L30-L37

---

## Artifacts
- `main_decoded.bin`, `mainfile_html_decoded.txt` (MainFileSettings)  
- `oasis_*.bin/.txt`, `oasis_combined.*` (My Fourth Oasis)  
- `mememan_oasis_*`, `mememan_homba_*`, `mememan_*_combined.*` (MEMEMAN)  
- Optional carves: `mememan_candidate_*.bmp/bin` (if needed)

> Per the prompt: once you uncover the intended payloads, **no deeper reversing is required**—just follow the context clues and extract the flags.
