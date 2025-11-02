# Huntress 2025 — Day 01: Verify Your Human (Sanitized Write‑Up)

**Category:** Malware  
**Goal:** Understand the multi‑stage “CAPTCHA” lure and safely extract the flag **without** running untrusted code.

---

## ⚠️ Safety First (What’s intentionally omitted)

This write‑up **excludes** any live IoCs, runnable PowerShell/Python payloads, executable links, or byte blobs that could be repurposed. All potentially dangerous elements are redacted, summarized, or shown only as inert pseudocode. Use this document strictly for learning methodology.

---

## Scenario Summary

A fake “MS Teams update” prompt presents a “CAPTCHA” that instructs victims to press **Win+R**, paste clipboard content, and hit **Enter**. The clipboard holds a PowerShell one‑liner that would download and execute a second‑stage script. We analyzed artifacts **offline** and **in a VM snapshot** to keep the host safe.

**Key behavior (at a high level):**
- Stage 1: A PowerShell bootstrapper writes a temporary script and launches it.
- Stage 2: The script downloads a file masquerading as a PDF (actually an archive), extracts to a temp folder, and schedules execution of a bundled runtime (Python) with a bytecode file.
- Stage 3: The bytecode decrypts an embedded shellcode buffer (base64 + XOR), allocates RWX memory, copies the shellcode, and executes it.

All of this is classic “LOLBins + living off the land” + in‑memory execution trickery.

> **Note:** Exact commands, URLs, GUIDs, and byte sequences are **redacted** here to prevent misuse.

---

## Indicators & Artifacts (Redacted)

- **Clipboard Launcher:** A PowerShell one‑liner that downloads a script from a per‑instance URL (**redacted**) and executes it.
- **Masqueraded Archive:** A file with a “.pdf” extension that is actually a **ZIP**; extracted into the user’s LocalAppData temp path.
- **Staged Runtime:** A local Python runtime (e.g., `pythonw.exe`) plus libraries placed beside a small Python bytecode file.
- **Bytecode Role:** Decrypts a buffer and uses Win32 APIs to allocate and run it in memory.

> We deliberately do **not** include any functional code or live addresses.

---

## Analysis Method (Safe & Reproducible)

1. **Work in an isolated VM snapshot.** Take a snapshot before analysis. Never run unknown code on a host you care about.
2. **Treat the “.pdf” as a container.** Check magic bytes and open as ZIP in a hex editor or safe archive utility. Review file listing only.
3. **Static triage of the staged Python files.**
   - Decompile/recover readable text from the `.pyc` **without** executing it.
   - Look for patterns like: base64 blobs, XOR routines, and calls to memory APIs.
4. **Document the decryption logic without executing it.**
   - We observed: `decoded = XOR(Base64Decode(ciphertext), key)` then an in‑memory loader calling `VirtualAlloc`, `RtlMoveMemory`, etc.
   - **Do not** run the result. It is enough to understand the transformation.
5. **Recover the flag from the non‑network, non‑exec path.**
   - The challenge encodes a short data block (not the full payload) that, when **XOR’d with a single‑byte key** and **string‑reversed**, renders the flag text.
   - We reproduced this deterministically **off‑box** using a minimal, **non‑executable** reconstruction of the logic (pseudocode below).

---

## Pseudocode (Inert) for the Final Decode

> This is **not runnable code**; it explains the logic without shipping malicious content.

```text
INPUT: hex_bytes = "<redacted short blob>"
KEY = 0xA5  ; single-byte XOR key observed in the decoder loop

function xor_single_byte(data_hex, key):
    data = hex_to_bytes(data_hex)
    out = []
    for i in range(len(data)):
        out.append(data[i] XOR key)
    return bytes_to_ascii(out)

decoded = xor_single_byte(hex_bytes, KEY)
flag = reverse_string(decoded)

print(flag)
```

- We confirmed the decoder loop matched the shell stub’s behavior (XOR with `0xA5`, then treat result as ASCII and reverse).
- No network activity or memory execution is needed to derive the flag string from the small, embedded **data block** that the challenge targets.

---

## Detection & DFIR Notes

- **Process lineage:** `powershell.exe` launched via Run dialog, spawning child `powershell.exe` instances, then a sideloaded `pythonw.exe` from a temp path.
- **Masquerading:** Archive named as a PDF but extracts to a version‑pinned, self‑contained Python runtime.
- **Scheduled task:** A one‑time task configured for the current user to run the staged interpreter shortly after extraction.
- **Memory execution:** RWX allocation and copy—alert on `VirtualAlloc` + `RtlMoveMemory` patterns from userland interpreters.
- **Preventive controls:**
  - Constrain script execution policies and block clipboard‑launched PowerShell via ASR rules where possible.
  - Block execution from user‑writable temp directories.
  - Content inspection for archives with misleading extensions.
  - EDR detection for staged interpreters (Python/Node/PowerShell) launching within `AppData\Local`.

---

## Final Answer

**Flag:** `flag{d341b8d2c96e9cc96965afbf5675fc26}`

*(Provided as plain text; no extra punctuation.)*

---

## Credits & Ethics

Write‑up by **Blandman3**. This document is intentionally sanitized to avoid shipping weaponizable snippets. If you are testing in a lab, isolate, snapshot, and never run untrusted code on production hosts.
