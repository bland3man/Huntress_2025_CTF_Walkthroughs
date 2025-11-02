# Day 03 — **SANDY** (Windows / AutoIt / Multi‑stage Decode)

**Me:** I took Sandy’s “wallet protection” program at face value—until a quick triage showed it’s a packed Windows binary that unrolls into AutoIt, then into base64‑stuffed PowerShell. Classic multi‑stage obfuscation. Here’s exactly how I peeled it and where the flag appears.

---

## TL;DR
- The EXE is **UPX‑packed** → unpack with `upx -d`.
- The unpacked image contains an **AutoIt** stub → rip the embedded script.
- Inside the AutoIt, there’s a **large array of base64 chunks** → decode them as **UTF‑16LE** text (Windows/AutoIt use UTF‑16).
- That reveals a **PowerShell** that base64‑decodes another blob and runs it with `Invoke‑Expression` → switch that to **`Write-Host`** to print the payload instead of executing.
- Grep the printed payload for `flag{…}` → **flag recovered.**

Flag observed in the decoded content:
```
{
  "name": "Flag",
  "path": "flag{27768419fd176648b335aa92b8d2dab2}"
}
```

> Intentional “wallet security” cover story + extension noise; this is just a staged loader chain.

---

## 1) Rapid triage (strings & packing)

On first pass I run `strings` looking for low‑hanging fruit and signatures:

```bash
# Linux / WSL
strings target.exe | head -n 50
strings target.exe | grep -E "UPX[0-9]|AutoIt|AUScript|Invoke-Expression" -n
```

The hits `UPX0`/`UPX1` suggest **UPX** packing. Unpack:

```bash
upx -d -o unpacked.exe target.exe
# sanity check
strings unpacked.exe | head -n 40
strings unpacked.exe | grep -i autoit -n
```

If you prefer GUI classification, **Detect It Easy (DIE)** or **PEiD** will also call out UPX/AutoIt.

---

## 2) Extract the embedded AutoIt script

AutoIt‑packed EXEs often embed a compiled script you can rip. I used an AutoIt ripper (any of the common ones works; e.g., `AutoIt-Ripper.py` / `myAut2Exe`‑style tools). Typical usage:

```bash
# Example (adjust to your ripper’s CLI):
python3 AutoIt-Ripper.py -s unpacked.exe -o ripped_script.au3
# or it may dump multiple files next to the EXE; check the output folder
ls -l
```

Open the ripped `.au3`/decompiled script. You should see **a huge array/list of base64 strings** being concatenated and later executed.

---

## 3) Stage‑2: decode the AutoIt base64 array (UTF‑16LE)

AutoIt strings are typically **UTF‑16LE**. If you decode base64 to UTF‑8 you’ll see “random” bytes between characters. Decode to UTF‑16LE to reconstruct the intended text.

Minimal Python to process an array named `chunks` (copied out of the AutoIt and pasted into Python syntax):

```python
# decode_autoit_chunks.py
import base64

# paste the AutoIt string array here after converting it to a Python list:
# chunks = ["<b64_0>", "<b64_1>", ...]
chunks = [
    # "..."
]

stage2 = ""
for idx, chunk in enumerate(chunks):
    try:
        stage2 += base64.b64decode(chunk).decode("utf-16-le", errors="ignore")
    except Exception as e:
        print(f"[!] chunk {idx} error: {e}")

open("stage2.ps1", "w", encoding="utf-8").write(stage2)
print("[+] wrote stage2.ps1")
```

Run it:
```bash
python3 decode_autoit_chunks.py
wc -c stage2.ps1
head -n 40 stage2.ps1
```

You should see a **PowerShell** script. In mine it constructed `$encodedScript` and did:

```powershell
$decodedScript = [System.Text.Encoding]::Unicode.GetString(
  [System.Convert]::FromBase64String($encodedScript)
)
Invoke-Expression $decodedScript
```

---

## 4) Defang the PowerShell (print instead of execute)

I don’t execute unknown payloads. Replace **`Invoke-Expression $decodedScript`** with **`Write-Host $decodedScript`** (or `Out-File`), then run under a constrained environment to dump the deobfuscated content:

```powershell
# Windows PowerShell / pwsh
(Get-Content .\stage2.ps1 -Raw) -replace 'Invoke-Expression\s+\$decodedScript',
                                      'Write-Host $decodedScript' |
  Set-Content .\stage2_print.ps1

# print the next-stage payload without running it
powershell.exe -ExecutionPolicy Bypass -File .\stage2_print.ps1 > stage3_dump.txt
```

Now search for flags / IoCs:

```bash
grep -nE 'flag\{|wallet|chrome|extension|b64|gzip|inflate|xor|url' stage3_dump.txt | sed -n '1,80p'
```

In my dump the flag is exposed in a small JSON‑ish fragment:

```json
{
  "name": "Flag",
  "path": "flag{27768419fd176648b335aa92b8d2dab2}"
}
```

No need to execute the final stage at all—the author left the value in the decoded text.

---

## 5) Why the UTF‑16LE detail matters

- AutoIt and much of Windows script plumbing use **UTF‑16LE** internally.
- Decoding the chunks as UTF‑8 inserts nulls/garbage between characters, hiding the actual PowerShell.
- Once decoded as UTF‑16LE, the base64 string and the PowerShell logic are perfectly legible.

---

## 6) Optional hardening & verification

- **Static only:** Keep execution disabled; favor static decoding and string reconstruction.
- **Detonation safety:** If you must run anything, do it in an **offline VM** with no creds/browsers, and capture only stdout.
- **Chrome extension angle:** Given the challenge story, expect references to wallet/extension directories in `%LOCALAPPDATA%` or Chrome policies—but you shouldn’t need them for the flag.

---

## Commands Cheat‑Sheet

```bash
# 1) Unpack
upx -d -o unpacked.exe target.exe

# 2) Rip AutoIt
python3 AutoIt-Ripper.py -s unpacked.exe -o ripped_script.au3

# 3) Decode the array of chunks (convert to Python list first)
python3 decode_autoit_chunks.py

# 4) Defang & print next stage
pwsh -NoProfile -Command "(Get-Content stage2.ps1 -Raw) -replace 'Invoke-Expression\s+\$decodedScript','Write-Host $decodedScript' | Set-Content stage2_print.ps1"
powershell.exe -ExecutionPolicy Bypass -File .\stage2_print.ps1 > stage3_dump.txt

# 5) Find the flag
grep -n 'flag{' stage3_dump.txt
```

---

## Takeaways

- Packed Windows droppers that unravel into **AutoIt → PowerShell** are common in the wild (and CTFs). Build a quick pipeline for **UPX‑unpack → AutoIt‑rip → b64 decode (UTF‑16LE) → print**.
- Swap any actual “execution” calls (`Invoke‑Expression`, `Start-Process`, `IEX`) to **printing** calls during analysis.
- The story context (“Chrome/crypto extensions”) was there to distract; the **flag is available statically** after decoding.

**Flag:** `flag{27768419fd176648b335aa92b8d2dab2}`
