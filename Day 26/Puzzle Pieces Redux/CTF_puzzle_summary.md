# CTF Binary Flag Extraction - Complete Solution Guide

## Challenge Overview
- 16 `.bin` files (Windows PE executables)
- Each contains a flag part identifier (`flag_part_X.pdb`)
- 2 files per part (8 parts total: 0-7)
- Need to execute binaries and assemble output into `flag{32-hex}`

---

## Phase 1: Discovery and Mapping

### Step 1: Discover the Flag Parts

Run this command to find which files contain which parts:
```bash
for f in *.bin; do
    strings -a "$f" | grep -i 'flag_part_' && echo "Source: $f"
done
```

**Key Finding:** Each file contains a PDB debug string like `flag_part_0.pdb`, `flag_part_1.pdb`, etc.

### Step 2: Create the File-to-Part Mapping

Save this as `map_parts.py`:
```python
#!/usr/bin/env python3
"""
map_parts.py - Maps .bin files to their flag part numbers
Outputs: part_mapping.txt with files organized by part number
"""

import subprocess
import re
from pathlib import Path

def find_part_number(bin_file):
    """Extract part number from binary using strings command"""
    try:
        result = subprocess.run(
            ['strings', '-a', str(bin_file)],
            capture_output=True,
            text=True,
            timeout=5
        )
        match = re.search(r'flag_part_(\d+)\.pdb', result.stdout)
        if match:
            return int(match.group(1))
    except Exception as e:
        print(f"Error analyzing {bin_file}: {e}")
    return None

def main():
    print("="*60)
    print("CTF Flag Part Mapper")
    print("="*60)
    print()
    
    # Scan all .bin files
    bin_files = sorted(Path('.').glob('*.bin'))
    
    if not bin_files:
        print("[!] No .bin files found in current directory")
        return
    
    print(f"[*] Found {len(bin_files)} .bin files")
    print("[*] Analyzing...\n")
    
    # Map files to parts
    part_map = {}
    for bin_file in bin_files:
        part_num = find_part_number(bin_file)
        if part_num is not None:
            if part_num not in part_map:
                part_map[part_num] = []
            part_map[part_num].append(bin_file.name)
            print(f"  {bin_file.name} -> Part {part_num}")
    
    # Save mapping to file
    with open('part_mapping.txt', 'w') as f:
        f.write("Flag Part to File Mapping\n")
        f.write("="*60 + "\n\n")
        
        for part_num in sorted(part_map.keys()):
            f.write(f"Part {part_num}:\n")
            for idx, filename in enumerate(part_map[part_num]):
                f.write(f"  Candidate {idx}: {filename}\n")
            f.write("\n")
    
    print(f"\n[+] Mapping saved to part_mapping.txt")
    print(f"[+] Found {len(part_map)} parts (0-{max(part_map.keys())})")
    print(f"[+] Total candidates: {sum(len(files) for files in part_map.values())}")
    
    # Display summary
    print("\n" + "="*60)
    print("Summary by Part:")
    print("="*60)
    for part_num in sorted(part_map.keys()):
        files = part_map[part_num]
        print(f"Part {part_num}: {len(files)} file(s)")
        for idx, f in enumerate(files):
            print(f"  [{idx}] {f}")

if __name__ == '__main__':
    main()
```

**Run it:**
```bash
python3 map_parts.py
```

**Output:** Creates `part_mapping.txt` showing which files map to which parts.

---

## Phase 2: Execute Binaries and Capture Output

### Step 3: Rename Files and Execute

These are Windows PE executables. You need to:
1. Rename `.bin` to `.exe`
2. Execute them (Windows or Wine on Linux)
3. Capture the output

**On Windows (PowerShell):**
```powershell
# Create output file
"Flag Part Outputs" | Out-File extracted_data.txt

# Execute each binary in the order from part_mapping.txt
$files = @(
    '945363af.bin', 'c8c5833b33584.bin',  # Part 0
    '5e47.bin', '8208.bin',                # Part 1
    '4fb72a1a24.bin', '7b217.bin',         # Part 2
    '5fa.bin', 'e1204.bin',                # Part 3
    '8c14.bin', 'a4c71d6229e19b0.bin',     # Part 4
    '24b429c2b4f4a3c.bin', 'aa60783e.bin', # Part 5
    '53bc247952f.bin', 'f12f.bin',         # Part 6
    'c54940df1ba.bin', 'd2f7.bin'          # Part 7
)

$part = 0
$candidate = 0
foreach ($file in $files) {
    $exe = $file -replace '\.bin$', '.exe'
    Copy-Item $file $exe
    
    "---- $exe (part $part) ----" | Out-File extracted_data.txt -Append
    $output = & ".\$exe" 2>&1
    $output | Out-File extracted_data.txt -Append
    "" | Out-File extracted_data.txt -Append
    
    Remove-Item $exe
    
    $candidate++
    if ($candidate -eq 2) {
        $candidate = 0
        $part++
    }
}
```

**On Linux with Wine:**
```bash
#!/bin/bash
# execute_binaries.sh

echo "Flag Part Outputs" > extracted_data.txt

# Array of files in order from part_mapping.txt
files=(
    "945363af.bin" "c8c5833b33584.bin"
    "5e47.bin" "8208.bin"
    "4fb72a1a24.bin" "7b217.bin"
    "5fa.bin" "e1204.bin"
    "8c14.bin" "a4c71d6229e19b0.bin"
    "24b429c2b4f4a3c.bin" "aa60783e.bin"
    "53bc247952f.bin" "f12f.bin"
    "c54940df1ba.bin" "d2f7.bin"
)

part=0
candidate=0

for file in "${files[@]}"; do
    exe="${file%.bin}.exe"
    cp "$file" "$exe"
    
    echo "---- $exe (part $part) ----" >> extracted_data.txt
    WINEDEBUG=-all wine "$exe" >> extracted_data.txt 2>&1 || echo "[ERROR]" >> extracted_data.txt
    echo "" >> extracted_data.txt
    
    rm -f "$exe"
    
    ((candidate++))
    if [ $candidate -eq 2 ]; then
        candidate=0
        ((part++))
    fi
done

echo "Done! Check extracted_data.txt"
```

**Expected `extracted_data.txt` format:**
```
---- 945363af.exe (part 0) ----
f9f73

---- c8c5833b33584.exe (part 0) ----
flag{

---- 5e47.exe (part 1) ----
88a2d

---- 8208.exe (part 1) ----
be7a1
...
```

---

## Phase 3: Assemble the Flag

### Step 4: Try All Combinations

Save this as `assemble_flag.py`:
```python
#!/usr/bin/env python3
"""
assemble_flag.py - Assembles flag from extracted binary outputs
Reads: extracted_data.txt (output from Phase 2)
Writes: final_flag.txt (the discovered flag)
"""

from pathlib import Path
import re
import itertools

# Regex patterns
PART_HEADER_RE = re.compile(r"^----\s+(.+?)\s+\(part\s+(\d+)\)\s+----\s*$")
FLAG_RE = re.compile(r"^flag\{[0-9a-fA-F]{32}\}$")

def parse_extracted_file(filepath):
    """Parse extracted_data.txt into parts map"""
    parts_map = {}
    
    if not filepath.exists():
        print(f"[!] {filepath} not found")
        return parts_map
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.rstrip('\n') for line in f]
    
    i = 0
    while i < len(lines):
        match = PART_HEADER_RE.match(lines[i])
        if match:
            filename = match.group(1).strip()
            part_num = int(match.group(2))
            
            # Next non-empty line is the output
            j = i + 1
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            
            output = lines[j].strip() if j < len(lines) else ""
            
            # Store in parts map (preserving order)
            if part_num not in parts_map:
                parts_map[part_num] = []
            parts_map[part_num].append(output)
            
            print(f"  Part {part_num}, candidate {len(parts_map[part_num])-1}: {output[:30]}")
            
            i = j + 1
        else:
            i += 1
    
    return parts_map

def try_combinations(parts_map):
    """Try all combinations of candidates to find valid flag"""
    parts_keys = sorted(parts_map.keys())
    
    # Build candidate lists (up to 2 per part)
    candidate_lists = []
    for part_num in parts_keys:
        candidates = parts_map[part_num][:2]  # Max 2 candidates
        candidate_lists.append(candidates)
    
    print(f"\n[*] Trying combinations...")
    print(f"    Parts: {len(candidate_lists)}")
    print(f"    Combinations: {2**len(candidate_lists)}\n")
    
    found_flags = []
    
    # Try all combinations
    for combo in itertools.product(*[range(len(lst)) for lst in candidate_lists]):
        pieces = []
        for part_idx, candidate_idx in enumerate(combo):
            piece = candidate_lists[part_idx][candidate_idx]
            pieces.append(piece)
        
        assembled = ''.join(pieces)
        
        # Check if valid flag
        if FLAG_RE.match(assembled):
            found_flags.append(assembled)
            print(f"[+] FOUND: {assembled}")
            print(f"    Combination: {combo}")
    
    return found_flags

def main():
    print("="*60)
    print("CTF Flag Assembler")
    print("="*60)
    print()
    
    # Parse extracted data
    print("[*] Parsing extracted_data.txt...")
    parts_map = parse_extracted_file(Path('extracted_data.txt'))
    
    if not parts_map:
        print("[!] No data found. Run Phase 2 first.")
        return
    
    print(f"\n[+] Parsed {len(parts_map)} parts")
    
    # Try combinations
    flags = try_combinations(parts_map)
    
    # Save result
    if flags:
        with open('final_flag.txt', 'w') as f:
            for flag in flags:
                f.write(flag + '\n')
        
        print(f"\n[+] Flag saved to final_flag.txt")
    else:
        print("\n[!] No valid flag found")
        print("    Check extracted_data.txt for errors")

if __name__ == '__main__':
    main()
```

**Run it:**
```bash
python3 assemble_flag.py
```

---

## Solution Summary

**Final Flag:**
```
flag{be7a1e6817d85d549f8b5abfaf18ba02}
```

**Winning Combination (candidate per part):**
- Part 0: Candidate 1 (`c8c5833b33584.exe`) → `flag{`
- Part 1: Candidate 1 (`8208.exe`) → `be7a1`
- Part 2: Candidate 1 (`7b217.exe`) → `e6817`
- Part 3: Candidate 1 (`e1204.exe`) → `d85d5`
- Part 4: Candidate 1 (`a4c71d6229e19b0.exe`) → `49f8b`
- Part 5: Candidate 0 (`24b429c2b4f4a3c.exe`) → `5abfa`
- Part 6: Candidate 0 (`53bc247952f.exe`) → `f18ba`
- Part 7: Candidate 0 (`c54940df1ba.exe`) → `02}`

---

## Complete Workflow
```bash
# Phase 1: Map files to parts
python3 map_parts.py

# Phase 2: Execute binaries (Windows or Linux with Wine)
# On Windows: Run PowerShell script above
# On Linux: bash execute_binaries.sh

# Phase 3: Assemble the flag
python3 assemble_flag.py

# Result:
cat final_flag.txt
```

**Key Insight:** The flag parts weren't in the filenames or embedded data - they were the **runtime output** of executing the binaries.