# Bussing Around - Quick Solution

### 1. Extract TCP Payloads
tshark -r bussing_around.pcapng -Y "tcp.srcport == 55995 and tcp.len > 0" -T fields -e tcp.payload > payloads.txt

### 2. Parse Register 0 Values
# parse_register0.py
reg0_values = []
with open('payloads.txt', 'r') as f:
    for line in f:
        payload = line.strip()
        if len(payload) >= 24:
            func_code = int(payload[14:16], 16)
            if func_code == 6:  # Write Single Register
                addr = int(payload[16:20], 16)
                value = int(payload[20:24], 16)
                if addr == 0:  # Register 0
                    reg0_values.append(value)

# Output the values to a file
with open('register0_values.txt', 'w') as f:
    for val in reg0_values:
        f.write(f"{val}\n")

print(f"Extracted {len(reg0_values)} values from Register 0")


### 3. Convert Binary to Bytes
# decode_binary.py
# Read the binary bits (0s and 1s)
with open('register0_values.txt', 'r') as f:
    bits = ''.join(line.strip() for line in f)

print(f"Total bits: {len(bits)}")

# Convert binary string to bytes
bytes_data = bytearray()
for i in range(0, len(bits), 8):
    if i + 8 <= len(bits):
        byte = int(bits[i:i+8], 2)
        bytes_data.append(byte)

# Save to file
with open('flag.zip', 'wb') as f:
    f.write(bytes_data)

print(f"Wrote {len(bytes_data)} bytes to flag.zip")
print(f"First 16 bytes (hex): {bytes_data[:16].hex()}")
print(f"ZIP magic bytes: {bytes_data[:4].hex()} (should be 504b0304 for ZIP)")

### 4. Extract ZIP File
```bash
# List contents (password is in the comment!)
unzip -l flag.zip

# Output shows:
# The password is 5939f3ec9d820f23df20948af09a5682

# Extract with password
unzip -P 5939f3ec9d820f23df20948af09a5682 flag.zip

# Read flag
cat flag.txt
```

---

## Flag
```
flag{4d2a66c5ed8bb8cd4e4e1ab32c71f7a3}
```

---

## Key Points

1. **Modbus TCP** - Industrial protocol used in HMI/PLC communication
2. **Register 0** - Contains binary data (0 and 1 values)
3. **2264 bits** → 283 bytes → ZIP file
4. **Password** - Self-documented in ZIP comment
5. **Don't overthink!** - Flag was in the simplest register, not the complex ASCII85 data in registers 4 & 10

---
