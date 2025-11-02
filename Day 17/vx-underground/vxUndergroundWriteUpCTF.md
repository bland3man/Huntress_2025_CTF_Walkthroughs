# Write up for the vx-underground Challenge

# First download and unzip the file ( I chose to create a directory /home/bwallace/vxCTF) cd vxCTF and then run:
7z -e vx-underground.zip

''' (I think they must have updated the way it unarchives, because I tried this again and it went direct into current directory this time)
cd ~/vxCTF
exiftool "'Cat Archive'"/*.jpg "'Cat Archive'"/*.JPG "'Cat Archive'"/*.jpeg 2>/dev/null | grep -A1 "File Name" | grep -E "(File Name|User Comment)" > all_comments.txt
cat all_comments.txt
'''
cd /home/bwallace/vxCTF
exiftool *.jpg *.JPG *.jpeg 2>/dev/null | grep -E "(File Name|User Comment)" > all_comments.txt
head -100 all_comments.txt

# There is also a separate picture called prime_mod.jpg
cd ~/vxCTF

# Extract all strings from the image
strings prime_mod.jpg > prime_mod_strings.txt

# Show the contents
cat prime_mod_strings.txt

# Or check for any Python/script content
strings prime_mod.jpg | grep -A20 -B5 "python\|def\|import\|decode\|#!/"

# Also check EXIF thoroughly
exiftool -a prime_mod.jpg

# From the prime_mod_strings.txt we know what our modulus key is for later
# Now, let's go ahead and put all of those messages from each picture in order for decoding later:
#!/usr/bin/env python3

data = {}

with open('all_comments.txt', 'r') as f:
    for line in f:
        if 'User Comment' in line and '-' in line:
            comment = line.split('User Comment')[-1].replace(':', '').strip()
            if '-' in comment:
                num_part, hex_part = comment.split('-', 1)
                if num_part.isdigit():
                    data[int(num_part)] = hex_part.strip()

# Sort by numeric key
ordered = sorted(data.items())

with open('combinedMessages.txt', 'w') as f:
    for num, hex_val in ordered:
        f.write(f"{num}-{hex_val}\n")

print(f"Wrote {len(ordered)} lines (sorted).")
print(f"First line: {ordered[0]}")
print(f"Last line: {ordered[-1]}")

# We will now have our combinedMessages.txt file to start decoding!
# Let's decrypt our combinedMessages.txt (only I didn't realize we didn't need the actual sequence number with hyphen, so I changed the script)
#!/usr/bin/env python3
from functools import reduce

shares = {}

with open("combinedMessages.txt", "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        if '-' in line:
            idx_str, hex_val = line.split('-', 1)
            idx = int(idx_str)
            shares[idx] = int(hex_val, 16)
        else:
            # Fallback if line is hex only
            shares[len(shares) + 1] = int(line, 16)

prime = int("010000000000000000000000000000000000000000000000000000000000000129", 16)

def modinv(a, p):
    return pow(a, -1, p)

def recover_secret(shares, prime):
    keys = sorted(shares.keys())
    secret = 0
    for i in keys:
        xi, yi = i, shares[i]
        num = 1
        den = 1
        for j in keys:
            if j != i:
                num = (num * -j) % prime
                den = (den * (xi - j)) % prime
        term = yi * num * modinv(den, prime)
        secret = (secret + term) % prime
    return secret

secret = recover_secret(shares, prime)
secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, "big")

print("Recovered secret (hex):", hex(secret))
print("Recovered secret (bytes):", secret_bytes)

# Then we finally get our password for our flag.zip file:
└─$ python3 decryptMessage.py 
Recovered secret (hex): 0x2a5a49502070617373776f72643a20464170656b4a21794a363959616a5773
Recovered secret (bytes): b'*ZIP password: FApekJ!yJ69YajWs'

# Now that we have our password we can use 7z:
7z x -p'FApekJ!yJ69YajWs' flag.zip -o./flag_contents -y

# OR use this instead if that yields a failure:
7z x flag.zip -o./flag_contents
# When prompted, paste: FApekJ!yJ69YajWs

# I used this script to decode, but I am pretty sure there is a decoder online
# This will literally count all of the MeoW and put them into binary form of 10100110 for example, which then decodes from that to text
#!/usr/bin/env python3
from pathlib import Path

def decode_meowmeow(code):
    """
    MeowMeow esoteric language decoder
    Meow = instruction separator
    ; = statement separator
    Number of 'Meow's = different instructions
    """
    statements = code.split(';;')
    output = []
    
    for statement in statements:
        parts = statement.split(';')
        if len(parts) >= 2:
            meow_count = parts[1].count('Meow') // 4  # Count groups of 'Meow'
            if meow_count > 0:
                output.append(chr(meow_count))
    
    return ''.join(output)


def simple_meow_decode(code):
    """Count 'Meow' occurrences between semicolons"""
    parts = code.split(';;')
    result = []
    
    for part in parts:
        sections = part.split(';')
        for section in sections:
            if section.strip():
                count = section.count('Meow')
                if 32 <= count <= 126:  # Printable ASCII range
                    result.append(chr(count))
    
    return ''.join(result)


# Use pathlib for a safe, cross-platform path
file_path = Path.cwd() / 'flag_contents' / 'cute-kitty-noises.txt'

with file_path.open('r') as f:
    meow_code = f.read()

print("[*] Decoding MeowMeow language...")

decoded = simple_meow_decode(meow_code)
print(f"[+] Decoded password: {decoded}")

# Voila, we get the flag:
┌──(bwallace㉿kali)-[~/vxCTF]
└─$ python3 decodeMeow.py                                                                                               
[*] Decoding MeowMeow language...
[+] Decoded password: malware is illegal and for nerdscats are cool and badassflag{35dcba13033459ca799ae2d990d33dd3}