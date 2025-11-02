import re, struct, subprocess
from pathlib import Path
from pwn import log

OBJ_START = "0x1400019c5"
OBJ_STOP = "0x140003200"

def extract_blob(binary):
    log.info("dumping movb immediates from %s", binary)
    text = subprocess.check_output(
        ["objdump", "-D", f"--start-address={OBJ_START}", f"--stop-address={OBJ_STOP}", str(binary)],
        text=True,
    )
    pairs = re.findall(r"movb\s+\$0x([0-9a-f]+),0x([0-9a-f]+)\(%rbp\)", text)
    blob = bytearray(max(int(off, 16) for _, off in pairs) + 1)
    for val, off in pairs:
        blob[int(off, 16)] = int(val, 16)
    log.success("extracted %d bytes", len(blob))
    return bytes(blob)

def parse_table(decoded):
    if decoded[:4] != b"HNTS":
        raise ValueError("bad magic")
    count = struct.unpack_from("<I", decoded, 4)[0]
    log.success("found header HNTS with %d entries", count)
    for idx in range(count):
        yield struct.unpack_from("<IIII", decoded, 8 + 16 * idx)

def lcg(seed, data):
    A, B, C, D, M = 0x19660D, 0x3C6EF35F, 0x17385CA9, 0x47502932, 0xFFFFFFFF
    buf = bytearray(data)
    i = 0
    while i + 1 < len(buf):
        tmp = (seed * A + B) & M
        buf[i] ^= (tmp >> 24) & 0xFF
        seed = (seed * C + D) & M
        buf[i + 1] ^= (seed >> 24) & 0xFF
        i += 2
    if i < len(buf):
        tmp = (seed * A + B) & M
        buf[i] ^= (tmp >> 24) & 0xFF
    return bytes(buf)

binary = Path("rust-tickler-2.exe")
blob = extract_blob(binary)

log.info("XORing blob with 0x33")
decoded = bytes(b ^ 0x33 for b in blob)

log.info("parsing entry table")
entries = list(parse_table(decoded))

targets = {
    0xAAAA: "favorite cat",
    0x83: "hint",
    0x7F: "flag",
    0xAAAAAA: "failure",
    0x0AAAAA: "entry_0",
    0x8F: "entry_1",
    0x51: "entry_5",
    0x63: "entry_6",
    0xAAAAAAAA: "entry_7",
    0x40: "entry_8",
    0xA9: "entry_9",
    0x9F: "entry_11",
    0xA1: "entry_12"
}
log.info("decrypting %d target entries (all)", len(targets))

for entry_id, offset, seed, length in entries:
    if entry_id not in targets:
        log.warning("unknown entry_id=0x%08x (skipping)", entry_id)
        continue
    
    payload = decoded[offset:offset + length]
    plain = lcg(seed & 0xFFFFFFFF, payload)
    log.info("id=0x%08x (%s)", entry_id, targets[entry_id])
    log.info("  cipher : %s", payload.hex())
    log.info("  text   : %s", plain.decode("utf-8", "replace"))
    log.info("  hex    : %s", plain.hex())