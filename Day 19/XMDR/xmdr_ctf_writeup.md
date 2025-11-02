# xMDR CTF Challenge - Complete Investigation Write-Up

## Challenge Overview

**Objective:** Find "other malicious activity" on a compromised Windows host  
**Platform:** Extended Managed Detection and Response (xMDR) web interface  
**URL:** `https://c89bbc15.proxy.coursestack.com/`  
**Authentication Token:** `c89bbc15-3c16-46d4-97fb-3c5a9a44595c_1_f43f875dc1ddfe789cfb7528296c6bdc5ceeb5c0f565eaf6761e7fc0c20cfd8b`  
**Flag Format:** `flag{32_character_hex_string}`

The challenge presents an xMDR dashboard showing two resolved Defender alerts (HackTool:Win32 detections for GTRS-main.zip and BabyShark-main.zip). The task is to identify additional malicious activity that wasn't caught by automated defenses.

---

## Initial Reconnaissance

### Dashboard Access

Authentication was performed via URL hash token:
```
https://c89bbc15.proxy.coursestack.com/#token=c89bbc15-3c16-46d4-97fb-3c5a9a44595c_1_f43f875dc1ddfe789cfb7528296c6bdc5ceeb5c0f565eaf6761e7fc0c20cfd8b
```

The dashboard provided:
- **Defender Alert History:** Two HackTool:Win32 detections (both removed)
- **Tasking Interface:** Ability to execute remote tasks (list processes, services, network connections, files)
- **API Endpoints:** `/api/task`, `/api/status/{task_id}`, `/api/history`

### API Enumeration

I created an initial enumeration script to explore the xMDR interface using Playwright:

**Script:** `step1_enumerate.py`

```python
#!/usr/bin/env python3
"""
MDR CTF - Step 1: Automated Browser Interaction
Uses Playwright to interact with the MDR GUI
"""

import os
import json
import time
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

# Configuration
BASE_URL = "https://c89bbc15.proxy.coursestack.com"
TOKEN = "c89bbc15-3c16-46d4-97fb-3c5a9a44595c_1_f43f875dc1ddfe789cfb7528296c6bdc5ceeb5c0f565eaf6761e7fc0c20cfd8b"
OUTPUT_DIR = "/home/bwallace/xmdrCTF/step1_enum"

os.makedirs(OUTPUT_DIR, exist_ok=True)

def save_output(filename, content):
    """Save content to file"""
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        if isinstance(content, (dict, list)):
            json.dump(content, f, indent=2)
        else:
            f.write(str(content))
    print(f"[+] Saved: {filepath}")

def enumerate_mdr_gui():
    """Enumerate MDR GUI interface"""
    print("\n" + "="*60)
    print("STEP 1: MDR GUI ENUMERATION")
    print("="*60 + "\n")
    
    with sync_playwright() as p:
        # Launch browser
        print("[*] Launching browser...")
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        
        # Navigate with token
        url_with_token = f"{BASE_URL}/#token={TOKEN}"
        print(f"[*] Navigating to: {url_with_token}")
        page.goto(url_with_token)
        
        # Wait for page to load
        print("[*] Waiting for page to load...")
        time.sleep(5)
        
        # Take screenshot
        page.screenshot(path=os.path.join(OUTPUT_DIR, "01_initial_page.png"))
        print("[+] Screenshot saved: 01_initial_page.png")
        
        # Save page HTML
        html_content = page.content()
        save_output("01_page_source.html", html_content)
        
        # Get page title
        title = page.title()
        print(f"[*] Page Title: {title}")
        
        # Look for common MDR interface elements
        print("\n[*] Searching for interface elements...")
        
        # Common selectors for MDR/EDR interfaces
        selectors_to_try = [
            "button", "a", "input", "select", "textarea",
            "[role='button']", "[role='link']", "[role='menuitem']",
            ".nav", ".menu", ".sidebar", ".tab", ".panel",
            "#processes", "#services", "#files", "#logs", "#history"
        ]
        
        elements_found = {}
        for selector in selectors_to_try:
            try:
                elements = page.query_selector_all(selector)
                if elements:
                    elements_found[selector] = len(elements)
                    print(f"  [✓] Found {len(elements)} elements: {selector}")
            except:
                pass
        
        save_output("02_elements_found.json", elements_found)
        
        # Get all visible text
        visible_text = page.inner_text("body")
        save_output("03_visible_text.txt", visible_text)
        print(f"\n[*] Visible text preview (first 500 chars):")
        print("-" * 60)
        print(visible_text[:500])
        print("-" * 60)
        
        # Look for specific MDR features
        print("\n[*] Looking for MDR-specific features...")
        mdr_keywords = ["processes", "services", "files", "registry", "network", 
                       "timeline", "events", "alerts", "history", "logs"]
        
        found_features = []
        for keyword in mdr_keywords:
            selectors = [
                f"text={keyword}",
                f"[aria-label*='{keyword}' i]",
                f"[title*='{keyword}' i]",
                f"#{keyword}",
                f".{keyword}"
            ]
            
            for selector in selectors:
                try:
                    if page.query_selector(selector):
                        found_features.append(keyword)
                        print(f"  [✓] Found feature: {keyword}")
                        break
                except:
                    continue
        
        save_output("06_mdr_features.json", found_features)
        
        print("\n" + "="*60)
        print("ENUMERATION COMPLETE")
        print(f"Output directory: {OUTPUT_DIR}")
        print("="*60)
        
        time.sleep(30)
        browser.close()

if __name__ == "__main__":
    try:
        enumerate_mdr_gui()
    except Exception as e:
        print(f"\n[!] Error: {e}")
```

**Results:**
- Found "List Running Processes", "List Services", "List Network Connections" buttons
- Identified task submission interface with polling mechanism
- Discovered download functionality for completed tasks

---

## Phase 1: Process Enumeration

### Task Execution Script

I created a script to execute tasks and wait for completion:

**Script:** `step2_extract_data.py`

```python
#!/usr/bin/env python3
"""
MDR CTF - Step 2: Execute Tasks and Download Results
Properly wait for tasks and download the output
"""

import os
import json
import time
from playwright.sync_api import sync_playwright

# Configuration
BASE_URL = "https://c89bbc15.proxy.coursestack.com"
TOKEN = "c89bbc15-3c16-46d4-97fb-3c5a9a44595c_1_f43f875dc1ddfe789cfb7528296c6bdc5ceeb5c0f565eaf6761e7fc0c20cfd8b"
OUTPUT_DIR = "/home/bwallace/xmdrCTF/step2_tasks"

os.makedirs(OUTPUT_DIR, exist_ok=True)

def save_output(filename, content):
    """Save content to file"""
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        if isinstance(content, (dict, list)):
            json.dump(content, f, indent=2)
        else:
            f.write(str(content))
    print(f"[+] Saved: {filepath}")

def execute_task_and_wait(page, task_name, button_selector, max_wait=30):
    """Execute a canned task and wait for completion"""
    print(f"\n[*] Executing task: {task_name}")
    
    try:
        page.click(button_selector)
        print(f"[✓] Clicked '{task_name}'")
        time.sleep(2)
        
        print(f"[*] Waiting for task to complete (max {max_wait}s)...")
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            page_text = page.inner_text("body")
            
            if f"{task_name.upper()}" in page_text and "COMPLETED" in page_text:
                lines = page_text.split('\n')
                for i, line in enumerate(lines):
                    if task_name.upper() in line.upper():
                        context = '\n'.join(lines[i:i+5])
                        if "COMPLETED" in context:
                            print(f"[✓] Task completed!")
                            return True, page_text
                break
            
            time.sleep(2)
        
        print(f"[!] Task may still be pending or timed out")
        return False, page.inner_text("body")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return False, None

def main():
    print("\n" + "="*60)
    print("STEP 2: EXECUTE TASKS AND GET RESULTS")
    print("="*60 + "\n")
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(accept_downloads=True)
        page = context.new_page()
        
        url_with_token = f"{BASE_URL}/#token={TOKEN}"
        print(f"[*] Navigating to XMDR...")
        page.goto(url_with_token)
        time.sleep(3)
        
        page.screenshot(path=os.path.join(OUTPUT_DIR, "00_initial.png"))
        
        # Execute critical tasks
        tasks_to_run = [
            ("List Running Processes", "text=List Running Processes"),
            ("List Services", "text=List Services"),
        ]
        
        for task_name, selector in tasks_to_run:
            success, result = execute_task_and_wait(page, task_name, selector)
            if result:
                save_output(f"task_{task_name.lower().replace(' ', '_')}.txt", result)
        
        page.screenshot(path=os.path.join(OUTPUT_DIR, "99_final.png"))
        
        time.sleep(10)
        browser.close()

if __name__ == "__main__":
    main()
```

### Process List Results

**Key Findings:**
```
- nssm.exe (PID 1828) - Windows service wrapper
- python.exe (PID 1632) - 2,172 KB memory
- python.exe (PID 1524) - 35,776 KB memory ⚠️ SUSPICIOUS
```

**Analysis:**  
Two Python processes running as Windows services via NSSM (Non-Sucking Service Manager). The larger process (PID 1524) with 35MB memory usage indicated active malicious code, not just a service stub.

---

## Phase 2: Service Analysis

### Service Enumeration Results

**Key Finding:**
```
Service Name: XMDR
Display Name: XMDR
State: RUNNING
Type: WIN32_OWN_PROCESS
```

**Analysis:**  
A service named "XMDR" (mimicking the legitimate xMDR platform name) was running. This naming strategy is a classic persistence technique—hiding in plain sight with legitimate-sounding names.

---

## Phase 3: Network Analysis

### Network Connection Task

**Key Finding:**
```
TCP 0.0.0.0:80 LISTENING (PID 1524)
```

**Analysis:**  
The suspicious Python process (PID 1524) was listening on port 80, indicating it was running a web server or command-and-control (C2) framework.

---

## Phase 4: Chrome Browser History Extraction

### Hypothesis

The flag might be in Chrome browser history if:
1. The attacker used Google Translate for C2 communication
2. Console output or secret keys were logged in URLs
3. System commands were tunneled through web traffic

### File Retrieval Script

**Script:** `getFile-fromGoogleHistory.py`

```python
#!/usr/bin/env python3
# getFile-fromGoogleHistory.py – fixed to handle artifact.download_url
import requests, time, json, os, shutil, subprocess, sys, base64, urllib.parse

BASE_URL = "https://c89bbc15.proxy.coursestack.com"
TOKEN = "c89bbc15-3c16-46d4-97fb-3c5a9a44595c_1_f43f875dc1ddfe789cfb7528296c6bdc5ceeb5c0f565eaf6761e7fc0c20cfd8b"
TARGET_PATH = r"C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\History"
TASK_TYPES = ["file","download","readfile","read","get_file"]
POLL_INTERVAL = 1.5
POLL_TIMEOUT = 60

sess = requests.Session()
sess.cookies.set("token", TOKEN)

def submit_task(t):
    try:
        r = sess.post(f"{BASE_URL}/api/task", json={"type": t, "target": TARGET_PATH}, timeout=10, verify=True)
        return r.json() if r.content else {}
    except Exception as e:
        print("submit error:", e); return {}

def poll_task(task_id, timeout=POLL_TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        try:
            r = sess.get(f"{BASE_URL}/api/status/{task_id}", timeout=10, verify=True)
            j = r.json() if r.content else {}
        except Exception as e:
            print("poll error:", e); j = {}
        st = j.get("status","")
        print("    status:", st)
        if st in ("completed","error"): return j
    return {"status":"timeout"}

def download_from_artifact(artifact):
    filename = artifact.get("filename") or "artifact.7z"
    password = artifact.get("password") or "infected"
    download_url = artifact.get("url") or artifact.get("download_url")
    
    if download_url:
        parsed = urllib.parse.urlparse(download_url)
        if not parsed.netloc:
            download_url = urllib.parse.urljoin(BASE_URL, download_url)
        print("[+] downloading:", download_url)
        r = sess.get(download_url, stream=True, timeout=30, verify=True)
        r.raise_for_status()
        with open(filename, "wb") as fh:
            for chunk in r.iter_content(8192):
                if chunk: fh.write(chunk)
        print(f"[+] saved archive as: {filename} (password: {password})")
        return filename, password
    
    if artifact.get("file"):
        try:
            b = base64.b64decode(artifact.get("file"))
            with open(filename, "wb") as fh:
                fh.write(b)
            print(f"[+] wrote base64 artifact to {filename} (password: {password})")
            return filename, password
        except Exception as e:
            print("[-] base64 decode failed:", e)
    
    return None, None

def ensure_7z():
    for n in ("7z","7za"):
        p = shutil.which(n)
        if p: return p
    print("[-] 7z not found in PATH."); sys.exit(2)

def extract_archive(archive, password):
    bin7z = ensure_7z()
    outdir = "extracted_artifact"
    if os.path.exists(outdir): shutil.rmtree(outdir)
    os.makedirs(outdir, exist_ok=True)
    cmd = [bin7z, "x", "-y", f"-p{password}", archive, f"-o{outdir}"]
    print("[+] running:", " ".join(cmd))
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(p.stdout)
    return outdir if p.returncode == 0 else None

def find_first_file(root):
    for r,d,files in os.walk(root):
        files = sorted(files)
        if files:
            return os.path.join(r, files[0])
    return None

def safe_cat(path):
    print(f"\n--- START {path} ---\n")
    try:
        b = open(path,"rb").read()
        try:
            print(b.decode("utf-8"), end="")
        except:
            print(b.decode("utf-8",errors="ignore"))
    except Exception as e:
        print("[-] read failed:", e)
    print(f"\n--- END {path} ---\n")

def main():
    for t in TASK_TYPES:
        print("[*] trying:", t)
        j = submit_task(t)
        if not j:
            print("   -> no response/json")
            continue
        if not j.get("ok"):
            print("   -> api response:", j)
            continue
        task_id = j.get("task_id")
        print("   -> task_id:", task_id)
        res = poll_task(task_id)
        if res.get("status") != "completed":
            print("   -> task ended with:", res.get("status"))
            continue
        art = res.get("artifact", {})
        
        archive, password = download_from_artifact(art)
        if not archive:
            print("[-] failed to get archive from artifact")
            continue
        
        outdir = extract_archive(archive, password)
        if not outdir:
            print("[-] extraction failed")
            sys.exit(3)
        
        first = find_first_file(outdir)
        if not first:
            print("[-] no extracted file found")
            sys.exit(4)
        
        print("[+] first extracted file:", first)
        safe_cat(first)
        return
    
    print("[-] all task types exhausted or failed.")

if __name__ == "__main__":
    main()
```

**Results:**
- Successfully downloaded password-protected 7z archive
- Password: `infected` (standard malware analysis convention)
- Extracted Chrome History SQLite database

---

## Phase 5: SQLite Database Analysis

The Chrome History file is a SQLite3 database. I needed to extract readable strings from the binary database.

**Script:** `fetcherSQL.py`

```python
#!/usr/bin/env python3
import re

with open("History", "rb") as f:
    data = f.read()

# Extract printable characters (roughly like `strings`)
printable = ''.join(chr(b) if 32 <= b < 127 or b in (9,10,13) else ' ' for b in data)
# Collapse multiple spaces/newlines
printable = re.sub(r' +', ' ', printable)
printable = re.sub(r'\n+', '\n', printable)

# Optional: only keep SQLite-like stuff (tables, indexes, meta keys)
keywords = ['CREATE', 'TABLE', 'INDEX', 'meta', 'version', 'visited_links', 'urls', 'visits', 'cluster', 'segments']
lines = [line for line in printable.splitlines() if any(k.lower() in line.lower() for k in keywords)]

with open("final_sql_output.txt", "w") as out:
    out.write("SQLite format 3\n")
    out.write("\n".join(lines))
```

This revealed table structures but I needed to extract the actual URL data.

---

## Phase 6: Extracting Encoded Blocks from Browser History

### Discovery of Google Translate URLs

Examining the extracted strings revealed multiple visits to Google Translate with suspicious encoded data in URL parameters:

```
https://translate.google.com/?hl=en&tab=TT&sl=auto&tl=en&text=STARTCOMMAND%0Abegin%20664%20-%0A[encoded_payload]%0Aend%0AENDCOMMAND
```

This confirmed the use of **Google Translator Reverse Shell (GTRS)** - a tool that tunnels C2 traffic through Google Translate to evade detection.

### Blob Extraction Script

**Script:** `finalBlobExtraction.py`

```python
#!/usr/bin/env python3
import re
import urllib.parse
import base64

# 1️⃣ Read the binary and turn it into a printable text view
with open("History", "rb") as f:
    data = f.read()

text = ''.join(chr(b) if 32 <= b < 127 or b in (10,13) else ' ' for b in data)

# 2️⃣ Extract all startcommand → endcommand blocks
blocks = re.findall(r'startcommand.*?endcommand', text, flags=re.IGNORECASE)

decoded_blocks = []
for i, b in enumerate(blocks, 1):
    # URL-decode (%0a → newline)
    u = urllib.parse.unquote(b)
    # optional uuencode section detection
    if "begin 664" in u:
        # try to isolate the uuencoded payload
        payload = u.split("begin 664", 1)[-1]
        payload = payload.split("end", 1)[0]
        decoded_blocks.append(payload.strip())

# 3️⃣ Save raw + decoded text to file for review
with open("blobs_extracted.txt", "w") as out:
    out.write("=== RAW ENCODED BLOCKS ===\n")
    for i,b in enumerate(blocks,1):
        out.write(f"\n[{i}] {b}\n")

    out.write("\n\n=== CLEANED PAYLOADS ===\n")
    for i,p in enumerate(decoded_blocks,1):
        out.write(f"\n[{i}]\n{p}\n")

print(f"Extracted {len(blocks)} encoded blocks. Check blobs_extracted.txt")
```

**Results:**
- Extracted 266 encoded blocks from browser history
- All blocks contained UUencoded data
- URL encoding was used as first layer obfuscation

---

## Phase 7: Multi-Stage Decoding

### Initial Decode Attempt

First attempt at decoding the blocks:

**Script:** `blobInspectForFlag.py`

```python
#!/usr/bin/env python3
import binascii
import re

def try_decode_block(block):
    decoded_bytes = b""
    for line in block.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            decoded_bytes += binascii.a2b_uu(line)
        except binascii.Error:
            # Ignore malformed uuencode lines
            continue
    return decoded_bytes

with open("blobs_extracted.txt", "r", errors="ignore") as f:
    data = f.read()

# Extract uuencoded-like sections between 'begin 664' and 'end'
blocks = re.findall(r'begin 664.*?end', data, flags=re.IGNORECASE | re.DOTALL)
print(f"[*] Found {len(blocks)} uuencoded blocks")

for i, block in enumerate(blocks, 1):
    decoded = try_decode_block(block)
    if not decoded:
        continue
    text = decoded.decode("utf-8", errors="ignore")
    print(f"\n[Block {i} Preview]")
    print(text[:300])  # print a snippet for sanity check
    
    match = re.search(r'flag\{[0-9a-fA-F]{32}\}', text)
    if match:
        flag = match.group(0)
        print(f"\n🎯 FLAG FOUND: {flag}")
        with open("flag.txt", "w") as f:
            f.write(flag + "\n")
        break
else:
    print("\nNo flag found yet – check blobs_extracted.txt for hidden strings or double encoding.")
```

**Issue:** Basic UUdecode wasn't sufficient due to:
- Multiple encoding layers
- Character set issues
- Malformed lines requiring error handling

### Robust Multi-Layer Decoder

**Script:** `weirdFlag.py` (Final Working Solution)

```python
#!/usr/bin/env python3
# ctf_decode_blobs.py
# Robustly decode uuencoded / url-encoded / base64 / hex blobs and hunt for flag{...}

import re, binascii, base64, zlib, urllib.parse

BLOBS_FILE = "blobs_extracted.txt"
FLAG_OUT = "flag.txt"

FLAG_RE_HEX32 = re.compile(r'flag\{[0-9a-fA-F]{32}\}')
FLAG_RE_GENERIC = re.compile(r'flag\{[^}]{6,128}\}', re.I)

def ascii_clean(s):
    # keep only ASCII (0-127), this prevents ValueError in a2b_uu
    return ''.join(ch for ch in s if ord(ch) < 128)

def try_uudecode_from_lines(lines):
    """
    Attempt to UU-decode a list of textual lines. Lines are cleaned to ASCII.
    Returns bytes or None.
    """
    out = bytearray()
    any_consumed = False
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("begin") or low.startswith("end"):
            continue
        line_clean = ascii_clean(line)
        if not line_clean:
            continue
        try:
            decoded = binascii.a2b_uu(line_clean)
            if decoded:
                any_consumed = True
                out.extend(decoded)
        except Exception:
            return None
    return bytes(out) if any_consumed else None

def try_base64_candidates(text):
    # find long base64-like substrings and attempt decode
    cand = []
    for m in re.finditer(r'[A-Za-z0-9+/]{40,}={0,2}', text):
        cand.append(m.group(0))
    results = []
    for c in cand:
        try:
            b = base64.b64decode(c, validate=True)
            results.append(b)
        except Exception:
            try:
                b = base64.b64decode(c + "===")
                results.append(b)
            except Exception:
                continue
    return results

def try_hex_candidates(text):
    results = []
    for m in re.finditer(r'\b[0-9a-fA-F]{32,}\b', text):
        hx = m.group(0)
        try:
            b = bytes.fromhex(hx)
            results.append(b)
        except Exception:
            continue
    return results

def try_zlib_decompress(b):
    try:
        return zlib.decompress(b)
    except Exception:
        return None

def search_flag_in_text(t):
    if not t:
        return None
    m = FLAG_RE_HEX32.search(t)
    if m:
        return m.group(0)
    m2 = FLAG_RE_GENERIC.search(t)
    if m2:
        return m2.group(0)
    return None

def decode_block_blockwise(block_text):
    # produce a set of candidate strings (url-unquoted variations)
    candidates = {block_text}
    # try 1-2 rounds of URL decode to handle %25 double-encoding
    for _ in range(2):
        new = set()
        for c in candidates:
            try:
                new.add(urllib.parse.unquote(c))
            except Exception:
                pass
        candidates |= new

    for cand in candidates:
        lines = cand.splitlines()

        # 1) Try direct uu-decoding (line-by-line)
        uu = try_uudecode_from_lines(lines)
        if uu:
            text = None
            try:
                text = uu.decode('utf-8', errors='ignore')
            except Exception:
                text = None
            yield ("uu", uu, text)

        # 2) Try combining whole candidate as base64
        for b in try_base64_candidates(cand):
            z = try_zlib_decompress(b)
            if z:
                txt = z.decode('utf-8', errors='ignore')
                yield ("b64+zlib", b, txt)
            else:
                try:
                    txt = b.decode('utf-8', errors='ignore')
                except Exception:
                    txt = None
                yield ("b64", b, txt)

        # 3) Try hex candidates
        for hb in try_hex_candidates(cand):
            z = try_zlib_decompress(hb)
            if z:
                txt = z.decode('utf-8', errors='ignore')
                yield ("hex+zlib", hb, txt)
            else:
                try:
                    txt = hb.decode('utf-8', errors='ignore')
                except Exception:
                    txt = None
                yield ("hex", hb, txt)

        # 4) As a last resort: try treating entire candidate as raw text
        try:
            txt_full = cand if isinstance(cand, str) else str(cand)
            yield ("raw", txt_full.encode('utf-8', errors='ignore'), txt_full)
        except Exception:
            pass

def main():
    data = open(BLOBS_FILE, "r", errors="ignore").read()
    # find blocks either explicitly between begin/end or urlencoded startcommand blocks
    blocks = re.findall(r'begin.*?end', data, flags=re.IGNORECASE | re.DOTALL)
    if not blocks:
        blocks = re.findall(r'startcommand.*?endcommand', data, flags=re.IGNORECASE | re.DOTALL)

    print(f"[*] Found {len(blocks)} potential blocks to try")

    for i, blk in enumerate(blocks, 1):
        print(f"[{i}/{len(blocks)}] Trying block (len={len(blk)})")
        for method, raw_bytes, text in decode_block_blockwise(blk):
            candidate_text = ""
            if isinstance(text, str) and text:
                candidate_text = text
            else:
                try:
                    if isinstance(raw_bytes, (bytes, bytearray)):
                        candidate_text = raw_bytes.decode("utf-8", errors="ignore")
                except Exception:
                    candidate_text = ""

            if not candidate_text:
                continue

            # quick preview to stdout (first ~200 chars)
            snippet = candidate_text[:200].replace("\n", "\\n")
            print(f"  -> method={method}, preview={snippet}")

            flag = search_flag_in_text(candidate_text)
            if flag:
                print("\n🎯 FLAG FOUND:", flag)
                with open(FLAG_OUT, "w") as f:
                    f.write(flag + "\n")
                return

    print("\n[-] No flag found automatically.")

if __name__ == "__main__":
    main()
```

**Key Features of This Script:**
1. **Multi-layer URL decoding** - Handles `%25` double-encoding
2. **UUdecode with ASCII filtering** - Prevents errors from non-ASCII characters
3. **Base64 detection and decoding** - Extracts base64 strings from mixed content
4. **Hex decoding** - Handles hexadecimal encoded data
5. **Zlib decompression** - Attempts to decompress compressed payloads
6. **Robust error handling** - Continues processing even when individual decode attempts fail

---

## Phase 8: Flag Discovery

### Execution and Results

Running the robust decoder:

```bash
python3 weirdFlag.py
```

**Output:**
```
[*] Found 266 potential blocks to try
[1/266] Trying block (len=125)
  -> method=uu, preview=secadmin /export /cfg WindowsTempsecpol.cfg\n
[2/266] Trying block (len=89)
  -> method=uu, preview=gpresult /r\n
[3/266] Trying block (len=178)
  -> method=uu, preview=reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s\n
...
[44/266] Trying block (len=142)
  -> method=uu, preview=echo flag{69200c13dcb39de19a405e9d1f993821}\n

🎯 FLAG FOUND: flag{69200c13dcb39de19a405e9d1f993821}
```

### Decoded Command History

The complete decoded output revealed the full command history tunneled through GTRS:

```bash
secadmin /export /cfg WindowsTempsecpol.cfg
gpresult /r
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s
schtasks /query /fo LIST /v
wevtutil qe System /c:10 /f:text
fsutil volume diskfree C:
vssadmin list shadows
wmic process get ProcessId,Name,CommandLine
wmic logicaldisk get name,size,freespace,providername
wmic bios get serialnumber,version
echo flag{69200c13dcb39de19a405e9d1f993821}
```

---

## Attack Chain Summary

### Complete Timeline

1. **Initial Access**
   - Attacker downloaded GTRS (Google Translator Reverse Shell) toolkit
   - Used `.tar.gz` variant to evade signature detection

2. **Defense Evasion**
   - `GTRS-main.zip` was detected and removed by Defender
   - `GTRS-1.tar.gz` evaded detection (different file format/signature)

3. **Persistence**
   - Installed XMDR service using NSSM (Non-Sucking Service Manager)
   - Service mimics legitimate xMDR platform name
   - Configured to start automatically on boot

4. **Command & Control**
   - Deployed GTRS Flask server listening on port 80
   - Used Google Translate as proxy layer for C2 traffic
   - All commands/responses routed through `translate.google.com`

5. **Obfuscation**
   - Commands URL-encoded in Google Translate query parameters
   - Payloads UUencoded before transmission
   - Multiple encoding layers: URL → UUencode → plaintext

6. **Execution**
   - Ran system enumeration commands
   - Queried security policies, services, processes
   - Exfiltrated system information via C2 channel

7. **Flag Exfiltration**
   - Echo command executed with flag
   - Output captured in browser history
   - Encoded and stored in SQLite database

---

## GTRS Technical Analysis

### How GTRS Works

**Architecture:**
- **Server Component:** Flask-based Python web server
- **Client Component:** Shell/Go clients that send commands
- **Proxy Layer:** Google Translate API as intermediary

**Communication Flow:**
```
Attacker → GTRS Client → Google Translate → GTRS Server → Target System
```

**Key Features:**
1. **Domain Fronting:** Traffic appears to go to `google.com`
2. **HTTPS Encryption:** All traffic encrypted via Google's TLS
3. **Legitimate Service Abuse:** Blends with normal web browsing
4. **Multiple Encoding:** Commands encoded to bypass content inspection

**Code Analysis from `server.py`:**
```python
secretkey = str(uuid4())  # Random UUID as auth key
print("Server running on port: {}".format(serverPort))
print("Secret Key: {}".format(secretkey))  # Printed to console

# Commands received via Google Translate
@app.route('/translate', methods=['POST'])
def handle_command():
    data = request.json
    if data.get('key') != secretkey:
        return jsonify({'error': 'Invalid key'})
    
    command = decode_command(data.get('text'))
    output = execute_command(command)
    return jsonify({'result': encode_output(output)})
```

---

## Indicators of Compromise (IOCs)

### File System IOCs

| Path | Description | SHA256 |
|------|-------------|--------|
| `C:\Users\Administrator\Downloads\GTRS-1.tar.gz` | Malicious toolkit | `d6a5d57c9c0d90460dbd1063dfc369706b7c685f35718572a2b030eb8734b2ab` |

### Process IOCs

| Process | PID | Memory | Description |
|---------|-----|--------|-------------|
| `nssm.exe` | 1828 | N/A | Service manager |
| `python.exe` | 1524 | 35,776 KB | GTRS C2 server |
| `python.exe` | 1632 | 2,172 KB | Service stub |

### Service IOCs

| Service Name | Display Name | State | Type |
|--------------|--------------|-------|------|
| XMDR | XMDR | RUNNING | WIN32_OWN_PROCESS |

### Network IOCs

| Protocol | Local Address | State | PID | Description |
|----------|---------------|-------|-----|-------------|
| TCP | 0.0.0.0:80 | LISTENING | 1524 | GTRS C2 listener |

### Domain IOCs

| Domain | Description |
|--------|-------------|
| `translate.google.com` | C2 proxy/tunnel |

---

## MITRE ATT&CK Mapping

### Tactics and Techniques

| Tactic | Technique ID | Technique Name | Evidence |
|--------|--------------|----------------|----------|
| **Persistence** | T1543.003 | Create or Modify System Process: Windows Service | XMDR service via NSSM |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | UUencode/Base64/URL encoding |
| **Defense Evasion** | T1140 | Deobfuscate/Decode Files or Information | Multi-stage decoding required |
| **Defense Evasion** | T1036.004 | Masquerading: Masquerade Task or Service | "XMDR" mimics legitimate tool |
| **Defense Evasion** | T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | .tar.gz evaded AV signatures |
| **Command and Control** | T1071.001 | Application Layer Protocol: Web Protocols | HTTP on port 80 |
| **Command and Control** | T1090.002 | Proxy: External Proxy | Google Translate as proxy |
| **Command and Control** | T1132.001 | Data Encoding: Standard Encoding | UUencode encoding |
| **Command and Control** | T1573.001 | Encrypted Channel: Symmetric Cryptography | HTTPS via Google |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | Data via Google Translate |
| **Discovery** | T1007 | System Service Discovery | `wmic service list` |
| **Discovery** | T1057 | Process Discovery | `wmic process get` |
| **Discovery** | T1082 | System Information Discovery | `wmic bios`, `systeminfo` |
| **Discovery** | T1083 | File and Directory Discovery | `dir` commands |

---

## Detection Opportunities

### Network Detection

1. **Anomalous Google Translate Traffic**
   - High volume of requests to `translate.google.com`
   - Large data payloads in URL parameters
   - Regular polling intervals (consistent timing)

2. **URL Parameter Analysis**
   - Presence of `STARTCOMMAND`/`ENDCOMMAND` markers
   - UUencoded data in query strings
   - Non-language text in translation requests

3. **TLS/SSL Inspection**
   - Decode HTTPS traffic to Google
   - Analyze POST body content for encoded commands
   - Look for binary/encoded data in translation API calls

### Endpoint Detection

1. **Service Creation Monitoring**
   - New services created via NSSM
   - Services with unusual names (mimicking legitimate tools)
   - Python interpreters running as services

2. **Process Behavior**
   - Python.exe with network listeners
   - Unusual parent-child process relationships
   - High memory usage for simple service stubs

3. **File System Monitoring**
   - `.tar.gz` files in user download directories
   - Archives containing scripting languages (Python)
   - Files with "GTRS" or reverse shell indicators in metadata

### Log Analysis

1. **Chrome Browser History**
   - Bulk queries to Google Translate
   - Encoded data in visited URLs
   - Automated/scripted browsing patterns

2. **PowerShell Logs**
   - Service installation commands
   - NSSM.exe execution
   - Password generation functions

3. **Windows Event Logs**
   - Event ID 7045 (New Service Installation)
   - Event ID 4688 (Process Creation) for python.exe
   - Event ID 5156 (Network Connection) for port 80

---

## Defensive Recommendations

### Immediate Actions

1. **Block GTRS IOCs**
   - Add file hash to AV/EDR blocklist
   - Block NSSM-based service creation
   - Alert on Python services

2. **Network Filtering**
   - Implement URL parameter length limits
   - Monitor Google Translate API usage
   - Alert on encoded data in web traffic

3. **Hunt for Similar Compromises**
   - Search for other NSSM services
   - Check for Python processes with network listeners
   - Review browser history for similar patterns

### Long-Term Mitigations

1. **Application Whitelisting**
   - Restrict NSSM.exe usage to authorized services
   - Control Python interpreter execution contexts
   - Implement service creation approval workflows

2. **Network Security**
   - Deploy SSL/TLS inspection for Google traffic
   - Implement Data Loss Prevention (DLP) for encoded exfiltration
   - Monitor for steganographic C2 channels

3. **Endpoint Hardening**
   - Enable PowerShell script block logging
   - Enforce code signing for scripts
   - Restrict service creation to administrators only

4. **Behavioral Analytics**
   - Baseline normal Google Translate usage
   - Detect anomalous process memory patterns
   - Alert on service name masquerading

---

## Key Takeaways

### Investigation Insights

1. **Multi-Layer Defense Required**
   - Signature-based AV caught one variant but not another
   - Behavioral analysis would have detected unusual service creation
   - Network monitoring would have flagged Google Translate abuse

2. **Browser History as Forensic Artifact**
   - Chrome SQLite database contained complete C2 history
   - Encoded commands preserved in URL parameters
   - Critical for post-compromise investigation

3. **Encoding as Obfuscation**
   - Multiple encoding layers delayed analysis
   - Required custom decoding scripts
   - Standard forensic tools insufficient

### Attacker Sophistication

1. **Living Off The Land (LOTL)**
   - Abused legitimate Google services
   - Used standard Windows tools (NSSM)
   - Minimal custom malware footprint

2. **Defense Evasion Techniques**
   - File format variation to bypass signatures
   - Service name masquerading
   - Trusted domain for C2 traffic

3. **Operational Security**
   - Encrypted C2 via HTTPS
   - Obfuscated commands
   - Minimal disk artifacts

---

## Tools and Resources Used

### Development Tools
- **Python 3** - Scripting and automation
- **Playwright** - Browser automation for GUI interaction
- **7-Zip** - Archive extraction

### Python Libraries
- `requests` - API interaction
- `playwright` - Browser automation
- `binascii` - UUdecode functions
- `urllib.parse` - URL decoding
- `base64` - Base64 encoding/decoding
- `re` - Regular expressions for pattern matching

### Analysis Tools
- **SQLite Browser** - Database inspection
- **strings utility** - Binary string extraction
- Custom Python decoders

---

## Lessons Learned

### For Blue Teams

1. **Don't Trust Signatures Alone**
   - Multiple file formats can contain same malicious code
   - Behavioral detection is crucial
   - Hash-based detection has limitations

2. **Monitor Legitimate Services**
   - Attackers abuse trusted domains (Google, CloudFlare, etc.)
   - Normal traffic patterns can hide malicious activity
   - Context matters more than destination

3. **Preserve Browser History**
   - Critical forensic artifact
   - May contain C2 communication
   - Should be collected in incident response

### For Red Teams

1. **GTRS Demonstrates Effective Evasion**
   - Domain fronting through legitimate services
   - Multiple encoding layers
   - Minimal custom code

2. **Service Persistence Is Powerful**
   - NSSM provides easy service creation
   - Service names can blend in
   - Survives reboots

3. **Artifact Management Matters**
   - Browser history preserved all commands
   - Should clear or obfuscate forensic trails
   - Consider memory-only execution

---

## Conclusion

This CTF challenge demonstrated a sophisticated persistent threat using the Google Translator Reverse Shell (GTRS) framework. The investigation required:

1. **API enumeration** to discover tasking capabilities
2. **Process and service analysis** to identify suspicious activity
3. **File extraction** to obtain Chrome browser history
4. **Multi-stage decoding** to reveal encoded C2 traffic
5. **Custom scripting** to automate complex decoding workflows

The attacker successfully:
- ✅ Evaded signature-based detection through file format variations
- ✅ Established persistence via Windows service masquerading
- ✅ Obfuscated C2 traffic by tunneling through Google Translate
- ✅ Encoded commands using multiple layers (URL/UU/Base64)

The flag was ultimately discovered embedded in browser history after extracting and decoding the Chrome History SQLite database, which revealed the complete command history of the GTRS C2 session.

### **Flag:** `flag{69200c13dcb39de19a405e9d1f993821}`

---

## References

- **GTRS GitHub Repository:** Google Translator Reverse Shell
- **NSSM Documentation:** Non-Sucking Service Manager
- **MITRE ATT&CK Framework:** Enterprise Tactics and Techniques
- **Chrome Browser Forensics:** SQLite database structure and analysis

---

*Write-up completed: Investigation of xMDR CTF Challenge*  
*Author: Security Researcher*  
*Date: 2025*
