# Webshellz CTF Challenge Writeup

## Challenge Overview
**Category:** Forensics/Incident Response  
**Points:** 9 (3 flags × 3 points each)  
**Difficulty:** Medium  

### Description
> The sysadmin reported that some unexpected files were being uploaded to the file system of their IIS servers. As a security analyst, you have been tasked with reviewing the Sysmon, HTTP, and network traffic logs to help us identify the flags!

### Files Provided
- `HTTP.log` - IIS HTTP server logs
- `Sysmon.evtx` - Windows Sysmon event logs
- `Traffic.pcapng` - Network packet capture

### Flags to Find
1. **Flag 1:** Account creation related (ends with '6')
2. **Flag 2:** Funky Random Program (ends with 'd')
3. **Flag 3:** Webshell access attempt (ends with 'e')

---

## Initial Reconnaissance

First, I extracted the archive using password `webshellz` and began analyzing the three files to understand the timeline and attack pattern.

### HTTP.log Analysis

The HTTP logs revealed suspicious activity involving:
- Upload attempts to `/revshell.aspx`
- Various encoded payloads in POST requests
- Unusual response times indicating potential command execution

Key findings from HTTP.log:
- Multiple POST requests to `/revshell.aspx` 
- Timestamp around 21:31:36 with a 23.5 second response time (suspicious!)
- Various base64 and URL-encoded parameters

---

## Flag 1: Suspicious Account Creation (ends with '6')
**Location:** `Sysmon.evtx`

### Approach
The hint mentioned "funky" account creation. I needed to parse Sysmon events looking for user account operations.

### Discovery Process
1. Parsed Sysmon.evtx for account creation events
2. Found suspicious username: `VJGSuERc6qYAYPdRc556JTHqxqWwLbPwzABc0XgIhgwYEWdQji1`
3. Recognized this as potential base62 encoding (62 chars, alphanumeric)
4. Decoded using base62 to reveal the flag

### Solution Script
```python
#!/usr/bin/env python3
# decode_base62_flag.py

def decode_base62(encoded_str):
    """Decode base62 encoded string"""
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    
    # Convert base62 to integer
    n = 0
    for char in encoded_str:
        n = n * 62 + alphabet.index(char)
    
    # Convert integer to bytes
    byte_data = n.to_bytes((n.bit_length() + 7) // 8, 'big') or b'\x00'
    
    print(f"Input: {encoded_str}")
    print(f"Hex: {byte_data.hex()}")
    
    try:
        decoded = byte_data.decode('utf-8')
        print(f"Decoded: {decoded}")
        return decoded
    except:
        print("Could not decode as UTF-8")
        return None

# The suspicious username from Sysmon
username = "VJGSuERc6qYAYPdRc556JTHqxqWwLbPwzABc0XgIhgwYEWdQji1"
flag1 = decode_base62(username)
```

**Flag 1:** `flag{[REDACTED]6}`

---

## Flag 2: Funky Random Program (ends with 'd')
**Location:** `Traffic.pcapng`

### Approach
Analyzed network traffic for encoded data, particularly focusing on HTTP POST requests containing the webshell traffic.

### Discovery Process
1. Used Wireshark to identify HTTP POST to `/revshell.aspx`
2. Found base32-encoded data in HTTP response
3. Extracted and decoded the base32 string

### Solution Script
```python
#!/usr/bin/env python3
# extract_pcap_flag.py

import base64
import re
import pyshark  # Alternative: use scapy

def find_base32_in_pcap(pcap_file):
    """Extract base32 encoded flags from PCAP"""
    
    # Read pcap file
    cap = pyshark.FileCapture(pcap_file, display_filter='http')
    
    base32_pattern = re.compile(r'[A-Z2-7]{16,}={0,6}')
    found_flags = []
    
    for packet in cap:
        try:
            # Check HTTP layer
            if hasattr(packet, 'http'):
                # Get HTTP response body if exists
                if hasattr(packet.http, 'file_data'):
                    data = packet.http.file_data
                    
                    # Find base32 patterns
                    matches = base32_pattern.findall(data)
                    
                    for match in matches:
                        try:
                            decoded = base64.b32decode(match)
                            decoded_str = decoded.decode('utf-8', errors='ignore')
                            
                            if 'flag{' in decoded_str.lower():
                                found_flags.append({
                                    'encoded': match,
                                    'decoded': decoded_str,
                                    'timestamp': packet.sniff_timestamp
                                })
                        except:
                            pass
        except:
            continue
    
    return found_flags

# Run extraction
flags = find_base32_in_pcap('Traffic.pcapng')
for flag in flags:
    print(f"Found flag: {flag['decoded']}")
```

**Flag 2:** `flag{[REDACTED]d}`

---

## Flag 3: Webshell Access Method (ends with 'e')
**Location:** HTTP objects exported from Wireshark

### Approach
Extracted all HTTP objects from the pcap file and searched for flags within uploaded/downloaded files.

### Discovery Process
1. Opened `Traffic.pcapng` in Wireshark
2. File → Export Objects → HTTP
3. Saved all objects to `WiresharkFindings/` directory
4. Scanned all exported files for flag patterns

### Solution Script
```python
#!/usr/bin/env python3
# scan_http_objects.py

import os
import base64
import re
from pathlib import Path

def scan_directory_for_flags(directory):
    """Scan all files in directory for flags"""
    
    flags_found = []
    path = Path(directory)
    
    for file_path in path.iterdir():
        if file_path.is_file():
            try:
                # Read file content
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                # Direct search for flag
                if b'flag{' in content:
                    text = content.decode('utf-8', errors='ignore')
                    flag_match = re.search(r'flag\{[^}]+\}', text)
                    if flag_match:
                        flags_found.append({
                            'file': file_path.name,
                            'flag': flag_match.group(),
                            'type': 'direct'
                        })
                
                # Try base64 decode
                text = content.decode('utf-8', errors='ignore')
                b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
                
                for match in b64_pattern.findall(text):
                    try:
                        decoded = base64.b64decode(match)
                        decoded_str = decoded.decode('utf-8', errors='ignore')
                        
                        if 'flag{' in decoded_str:
                            flag_match = re.search(r'flag\{[^}]+\}', decoded_str)
                            if flag_match:
                                flags_found.append({
                                    'file': file_path.name,
                                    'flag': flag_match.group(),
                                    'type': 'base64',
                                    'encoded': match[:50] + '...'
                                })
                    except:
                        pass
                        
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
    
    return flags_found

# Scan the exported objects directory
flags = scan_directory_for_flags('./WiresharkFindings')

for flag_info in flags:
    print(f"\nFound in {flag_info['file']}:")
    print(f"  Flag: {flag_info['flag']}")
    print(f"  Type: {flag_info['type']}")
    if 'encoded' in flag_info:
        print(f"  Encoded: {flag_info['encoded']}")
```

**Flag 3:** `flag{[REDACTED]e}`

---

## Comprehensive Analysis Tool

Here's an all-in-one Python script that automates the entire process:

```python
#!/usr/bin/env python3
# webshellz_solver.py
"""
Comprehensive solver for the Webshellz CTF challenge
Analyzes HTTP logs, Sysmon events, and PCAP files
"""

import base64
import re
import json
import subprocess
from pathlib import Path
from datetime import datetime

class WebshellzSolver:
    def __init__(self):
        self.flags = []
        
    def analyze_http_log(self, log_file):
        """Parse HTTP.log for suspicious activity"""
        print("[*] Analyzing HTTP.log...")
        
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        suspicious_requests = []
        for line in lines:
            if 'revshell.aspx' in line or 'ASPXSpy' in line:
                # Parse IIS log format
                parts = line.split()
                if len(parts) > 10:
                    suspicious_requests.append({
                        'timestamp': f"{parts[0]} {parts[1]}",
                        'method': parts[3],
                        'uri': parts[4],
                        'status': parts[11] if len(parts) > 11 else 'N/A',
                        'time_taken': parts[-1] if len(parts) > 14 else 'N/A'
                    })
        
        print(f"  Found {len(suspicious_requests)} suspicious requests")
        
        # Identify key timestamps
        for req in suspicious_requests:
            if float(req.get('time_taken', 0)) > 20000:  # >20 seconds
                print(f"  [!] Long-running request at {req['timestamp']}")
                print(f"      URI: {req['uri']}, Time: {req['time_taken']}ms")
        
        return suspicious_requests
    
    def parse_sysmon_events(self, evtx_file):
        """Extract suspicious account operations from Sysmon"""
        print("[*] Parsing Sysmon.evtx...")
        
        # Use evtx_dump or python-evtx
        try:
            import Evtx.Evtx as evtx
            import Evtx.Views as e_views
            
            with evtx.Evtx(evtx_file) as log:
                suspicious_users = []
                
                for record in log.records():
                    xml = record.xml()
                    
                    # Look for account creation patterns
                    if 'TargetUserName' in xml or 'AccountName' in xml:
                        # Extract username patterns
                        user_pattern = re.compile(r'<Data Name="TargetUserName">([^<]+)</Data>')
                        matches = user_pattern.findall(xml)
                        
                        for username in matches:
                            # Check if username looks encoded (long alphanumeric)
                            if len(username) > 30 and username.isalnum():
                                suspicious_users.append(username)
                                print(f"  [!] Suspicious username: {username}")
                                
                                # Try base62 decode
                                flag = self.try_base62_decode(username)
                                if flag and 'flag{' in flag:
                                    self.flags.append(('Sysmon', flag))
        except ImportError:
            print("  [!] python-evtx not installed, using alternative method")
            # Fallback to PowerShell extraction
            self.extract_with_powershell(evtx_file)
    
    def try_base62_decode(self, encoded):
        """Attempt base62 decoding"""
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        
        try:
            n = 0
            for char in encoded:
                n = n * 62 + alphabet.index(char)
            
            byte_data = n.to_bytes((n.bit_length() + 7) // 8, 'big')
            return byte_data.decode('utf-8', errors='ignore')
        except:
            return None
    
    def analyze_pcap(self, pcap_file):
        """Extract flags from network traffic"""
        print("[*] Analyzing Traffic.pcapng...")
        
        # Method 1: Direct binary search
        with open(pcap_file, 'rb') as f:
            data = f.read()
        
        # Look for base32 patterns
        base32_pattern = re.compile(b'[A-Z2-7]{16,}={0,6}')
        matches = base32_pattern.findall(data)
        
        for match in set(matches):
            try:
                decoded = base64.b32decode(match)
                decoded_str = decoded.decode('utf-8', errors='ignore')
                
                if 'flag{' in decoded_str:
                    print(f"  [!] Found base32 flag: {decoded_str}")
                    self.flags.append(('PCAP', decoded_str))
            except:
                pass
    
    def extract_http_objects(self, pcap_file, output_dir):
        """Extract HTTP objects using tshark"""
        print("[*] Extracting HTTP objects...")
        
        Path(output_dir).mkdir(exist_ok=True)
        
        try:
            # Use tshark to export HTTP objects
            cmd = ['tshark', '-r', pcap_file, '--export-objects', f'http,{output_dir}']
            subprocess.run(cmd, check=True, capture_output=True)
            
            # Scan extracted files
            for file_path in Path(output_dir).iterdir():
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                # Direct flag search
                if b'flag{' in content:
                    text = content.decode('utf-8', errors='ignore')
                    flag_match = re.search(r'flag\{[^}]+\}', text)
                    if flag_match:
                        print(f"  [!] Found flag in {file_path.name}: {flag_match.group()}")
                        self.flags.append(('HTTP Object', flag_match.group()))
        except:
            print("  [!] tshark not available, please extract manually in Wireshark")
    
    def solve(self):
        """Run all analysis methods"""
        print("="*60)
        print("WEBSHELLZ CTF SOLVER")
        print("="*60)
        
        # Analyze each component
        self.analyze_http_log('HTTP.log')
        print()
        
        self.parse_sysmon_events('Sysmon.evtx')
        print()
        
        self.analyze_pcap('Traffic.pcapng')
        print()
        
        self.extract_http_objects('Traffic.pcapng', 'http_objects')
        print()
        
        # Summary
        print("="*60)
        print("FOUND FLAGS:")
        print("="*60)
        
        for source, flag in self.flags:
            # Determine which flag based on ending
            if flag.endswith('6}'):
                flag_num = 1
            elif flag.endswith('d}'):
                flag_num = 2
            elif flag.endswith('e}'):
                flag_num = 3
            else:
                flag_num = '?'
            
            print(f"Flag {flag_num} ({source}): {flag}")

if __name__ == "__main__":
    solver = WebshellzSolver()
    solver.solve()
```

---

## Timeline of Attack

Based on the log analysis:

1. **Initial Reconnaissance**: Attacker probes the IIS server
2. **Webshell Upload**: ASPXSpy/revshell.aspx uploaded to server
3. **Command Execution**: POST requests to webshell with encoded commands
4. **Persistence**: Creation of backdoor account with base62-encoded name
5. **Data Exfiltration**: Various encoded responses containing flags

## Key Lessons Learned

1. **Multi-layer Encoding**: Attackers used various encoding schemes (base32, base62, base64)
2. **Log Correlation**: Need to correlate HTTP logs, Sysmon events, and network traffic
3. **Response Time Analysis**: Unusually long HTTP response times indicate command execution
4. **Artifact Extraction**: Wireshark's HTTP object export is crucial for webshell analysis

## Tools Used

- **Wireshark**: Network traffic analysis and HTTP object extraction
- **Python**: Custom scripts for automated flag extraction
- **PowerShell**: Sysmon event parsing (Windows)
- **tshark**: Command-line packet analysis

## Defense Recommendations

1. Monitor for suspicious file uploads to web directories
2. Alert on unusually long HTTP response times
3. Implement strict input validation on web applications
4. Monitor for unusual account creation patterns
5. Enable comprehensive Sysmon logging with proper retention

---

*Challenge completed successfully - all 3 flags captured!*