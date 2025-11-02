# Day 27 — Trashcan (Forensics) — Write-Up (from my POV)

## Challenge
**Category:** Forensic  
**Prompt:** The actor hid data in the Recycle Bin. Metadata “might not be what it should be.” Find the flag.

ZIP password: _provided with challenge_ (unzips to a pile of `$I*.txt` / `$R*.txt` files).

---

## What the Recycle Bin actually stores (quick primer)
On NTFS:

- **$Rxxxxxx.ext** → the deleted file’s *content* (renamed).
- **$Ixxxxxx.ext** → an *administrative sidecar* that stores:
  - original file size (8 bytes, little-endian)
  - FILETIME the item was deleted (8 bytes)
  - original full path (UTF-16LE)
  - pairs 1:1 with the `$R…` by the same random stem

If the actor wants to hide data “in the metadata,” stuffing *numeric values* into the `$I` records (or a CSV derived from them) is a classic move.

---

## Files
After unzipping `trashcan.zip`:

```
$I01XCGF.txt  $ICVE4M2.txt  ...  $R08ZI07.txt  $RJUUXYN.txt  ...
# dozens of paired $I / $R text files
```

I ran a standard **$I parser** to inventory everything into a CSV (columns: `$I File Name`, `$R File Name`, `Size (Bytes)`, `Timestamp (UTC)`, `Original Path`, etc.). You can use any $I-parser you like; the result looks like this (snippet):

```
"$I File Name","$R File Name","Size (Bytes)","Timestamp (UTC)","Original File Name With Path",...
"$I01XCGF.txt","$R01XCGF.txt","49","12-14-1642 08:40:03 UTC","C:\Users\flag\Desktop\flag.txt",...
"$I08ZI07.txt","$R08ZI07.txt","50","12-14-1642 08:40:04 UTC","C:\Users\flag\Desktop\flag.txt",...
...
```

Notice two things:

1. **Timestamps** are nonsense (“1642”) → likely decoys.
2. **Size (Bytes)** looks suspiciously like **ASCII codes** (e.g., 49 = `'1'`, 100 = `'d'`, 123 = `'{'`, etc.).

This fits the prompt: “metadata might not be what it should be.”

---

## Short path (manual confirm)
I first sanity-checked the idea by taking the “Size (Bytes)” values (from the CSV) and mapping them as ASCII:

```python
# quick experiment with the extracted numbers (trimmed here for brevity)
flag_nums = [
  102,102,102,108,108,108,97,97,97,103,103,103,123,123,123,49,49,49,100,100,100,
  50,50,50,98,98,98,50,50,50,98,98,98,48,48,48,53,53,53,54,54,54,57,57,57,
  # ... continues ...
  125,125,125,10,10,10
]

# We can see each value is repeated 3x, so take every 3rd or collapse triplets
decoded = ''.join(chr(flag_nums[i]) for i in range(1, len(flag_nums), 3))
print(decoded)
```

Output:

```
flag{1d2b2b05671ed1ee5812678850d5e329}
```

Why every third? Because **each code was tripled**: `fff lll aaa ggg {{{ ... }}}`. Taking the middle of each triplet (or deduping triplets) yields the intended string.

---

## Full reproducible approach (CSV → flag)

If you have the CSV from your $I parser (e.g., `recycle_inventory.csv`), this extracts the flag end-to-end:

```python
import csv

nums = []
with open('recycle_inventory.csv', newline='', encoding='utf-8') as f:
    r = csv.DictReader(f)
    for row in r:
        # Only use entries that point back to the same original file if you want to be strict:
        # if row['Original File Name'] == 'flag.txt':
        nums.append(int(row['Size (Bytes)']))

# The data is tripled per symbol. Collapse by taking every 3rd starting at index 1 (middle of each triplet)
collapsed = [nums[i] for i in range(1, len(nums), 3)]
flag = ''.join(map(chr, collapsed))

print(flag)
```

You’ll get:

```
flag{1d2b2b05671ed1ee5812678850d5e329}
```

---

## Alternative: no CSV, parse $I files directly
If you don’t want to rely on a tool, here’s a minimal reader for `$I` (Windows 10/11 style). The structure we care about:

- `0x00–0x07` → unknown/signature (varies by version; often 0x01 marker)
- `0x08–0x0F` → **original file size** (QWORD LE)
- `0x10–0x17` → **deletion time** (FILETIME)
- `0x18–…`   → **original path** (UTF-16LE, NUL-terminated)

```python
import glob, struct

sizes = []
for p in glob.glob('$I*.txt'):
    with open(p, 'rb') as f:
        b = f.read()
        if len(b) >= 0x18:
            size = struct.unpack_from('<Q', b, 0x08)[0]  # 8 bytes LE
            sizes.append(size)

# same collapse trick
collapsed = [sizes[i] for i in range(1, len(sizes), 3)]
print(''.join(map(chr, collapsed)))
```

---

## Answer
**Flag:** `flag{1d2b2b05671ed1ee5812678850d5e329}`

---

## Takeaways
- When a prompt hints that “metadata isn’t what it should be,” look for **encoded data in secondary fields**—sizes, timestamps, counts.
- The Recycle Bin’s `$I` sidecars are a goldmine. Even if content is gone, the `$I` files still leak paths, times, and (here) **weaponized numeric fields**.
- Pattern recognition matters: tripled values → dedupe/collapse before decoding.
