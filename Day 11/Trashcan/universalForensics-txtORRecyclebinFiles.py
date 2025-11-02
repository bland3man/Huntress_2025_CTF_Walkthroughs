
import os, struct, itertools, re, binascii, base64, codecs
EX_DIR = "/mnt/data/trashcan_extracted"
REJECT = "flag{1d2b2b05671ed1e581267850d5e329}"
records = []
for fname in sorted(os.listdir(EX_DIR)):
    if not fname.startswith('$I'): continue
    path = os.path.join(EX_DIR, fname)
    data = open(path,'rb').read()
    if len(data) < 16: continue
    size0 = struct.unpack_from('<Q', data, 0)[0]
    filetime_raw = struct.unpack_from('<Q', data, 8)[0]
    pat = b'C\x00:\x00\\\x00U\x00s\x00e\x00r\x00s\x00'
    idx = data.find(pat)
    key_before = None
    if idx != -1:
        before12 = data[max(0, idx-12):idx]
        if len(before12) >= 4:
            key_before = struct.unpack_from('<I', before12, 0)[0]
    val = struct.unpack_from('<Q', data, 8)[0]
    b = val if val <= 255 else val % 256
    ch = chr(b) if 32 <= b <= 126 else None
    records.append({'fname': fname, 'path': path, 'size0': size0, 'filetime_raw': filetime_raw, 'key_before': key_before, 'val': val, 'b': b, 'ch': ch, 'raw': data})

flag_re = re.compile(r"flag\{[0-9A-Fa-f_:\-]{8,}\}")
def find_flags_in(s):
    return flag_re.findall(s)

candidates = set()
notes = []

sorted_by_key = sorted([r for r in records if r['key_before'] is not None], key=lambda x: x['key_before'])
full = ''.join((r['ch'] if r['ch'] else '?') for r in sorted_by_key)
def collapse_runs(s): return ''.join(k for k,_ in itertools.groupby(s))
def first_of_runs(s): return ''.join(next(g) for k,g in itertools.groupby(s))
def take_step(s,step,off=0): return s[off::step]
strategies = {
    'full': full,
    'collapse': collapse_runs(full),
    'first_runs': first_of_runs(full),
    'step2': take_step(full,2),
    'step3': take_step(full,3),
    'step4': take_step(full,4)
}
for name, s in strategies.items():
    for m in find_flags_in(s):
        if m != REJECT:
            candidates.add((m, f"key_before::{name}"))
bseq = bytes([r['b'] for r in sorted_by_key if r['b'] is not None])
s_bseq = ''.join(chr(x) if 32<=x<=126 else '.' for x in bseq)
for m in find_flags_in(s_bseq):
    if m != REJECT: candidates.add((m, "bseq_ascii"))
hex_bs = binascii.hexlify(bseq).decode()
for m in find_flags_in(hex_bs):
    if m != REJECT: candidates.add((m, "bseq_hex"))
try:
    decoded = binascii.unhexlify(hex_bs)
    try_s = decoded.decode('utf-8', errors='ignore')
    for m in find_flags_in(try_s):
        if m != REJECT: candidates.add((m, "bseq_hex->ascii"))
except Exception:
    pass

valbytes = b''.join(struct.pack('<Q', r['val']) for r in sorted_by_key)
for s in re.findall(rb'[\x20-\x7e]{6,}', valbytes):
    try:
        ss = s.decode('utf-8')
        for m in find_flags_in(ss):
            if m != REJECT: candidates.add((m, "valbytes_printable"))
    except: pass

for N in [2,3,4,5,6,7,8,9,10,11,12,16,32]:
    sortedN = sorted(records, key=lambda r: (r['key_before'] % N) if r['key_before'] is not None else 0)
    sN = ''.join(r['ch'] if r['ch'] else '?' for r in sortedN)
    for variant in [sN, collapse_runs(sN), first_of_runs(sN), sN[::2], sN[::3]]:
        for m in find_flags_in(variant):
            if m != REJECT: candidates.add((m, f"keymod{N}"))

def xor_bytes(bs, key):
    return bytes([b ^ key for b in bs])
for key in range(1,256):
    xs = xor_bytes(bseq, key)
    for s in re.findall(rb'[\x20-\x7e]{8,}', xs):
        try:
            ss = s.decode('utf-8')
        except:
            ss = None
        if ss:
            for m in find_flags_in(ss):
                if m != REJECT: candidates.add((m, f"xor_bseq_{key}"))
    hx = binascii.hexlify(xs)
    try:
        dec = binascii.unhexlify(hx)
        try:
            txt = dec.decode('utf-8', errors='ignore')
            for m in find_flags_in(txt):
                if m != REJECT: candidates.add((m, f"xor_bseq_hex_{key}"))
        except: pass
    except: pass

ftseq = bytes([ (r['filetime_raw'] % 256) for r in sorted_by_key ])
for s in re.findall(rb'[\x20-\x7e]{6,}', ftseq):
    try:
        ss = s.decode('utf-8')
        for m in find_flags_in(ss):
            if m != REJECT: candidates.add((m, "filetime_ascii"))
    except: pass

full_runs = [(k, len(list(g))) for k,g in itertools.groupby(full)]
triple_chars = [k for k,l in full_runs if l>=3]
triple_seq = ''.join(triple_chars)
for m in find_flags_in(triple_seq):
    if m != REJECT: candidates.add((m, "triples_chars"))

for off in range(3):
    s3 = full[off::3]
    for m in find_flags_in(s3):
        if m != REJECT: candidates.add((m, f"full_every3_off{off}"))

for shift in range(1,6):
    s_plus = ''.join(chr(((x+shift) % 256)) if 32<=((x+shift)%256)<=126 else '.' for x in bseq)
    s_minus = ''.join(chr(((x-shift) % 256)) if 32<=((x-shift)%256)<=126 else '.' for x in bseq)
    for m in find_flags_in(s_plus):
        if m != REJECT: candidates.add((m, f"bseq_plus{shift}"))
    for m in find_flags_in(s_minus):
        if m != REJECT: candidates.add((m, f"bseq_minus{shift}"))
try:
    b64 = base64.b64encode(bseq)
    for m in find_flags_in(b64.decode('utf-8', errors='ignore')):
        if m != REJECT: candidates.add((m, "b64_bseq"))
    try:
        dec = base64.b64decode(bseq, validate=False)
        for s in re.findall(rb'[\x20-\x7e]{6,}', dec):
            try:
                ss = s.decode('utf-8')
                for m in find_flags_in(ss):
                    if m != REJECT: candidates.add((m, "bseq_b64dec"))
            except: pass
    except: pass
except: pass

combo1 = bytes([ ((r['key_before'] & 0xff) ^ r['b']) for r in sorted_by_key if r['key_before'] is not None ])
for s in re.findall(rb'[\x20-\x7e]{6,}', combo1):
    try:
        ss = s.decode('utf-8')
        for m in find_flags_in(ss):
            if m != REJECT: candidates.add((m, "combo_keylow_xor_b"))
    except: pass

cand_list = sorted(list(candidates))
print("Candidates found (excluding user-rejected):", len(cand_list))
for c in cand_list:
    print(c)

print("\n--- Debug strings ---")
print("full (first 400):", full[:400])
print("collapsed:", collapse_runs(full))
print("first_runs:", first_of_runs(full))
print("bseq length:", len(bseq))
print("bseq sample (first200):", ''.join(chr(x) if 32<=x<=126 else '.' for x in bseq[:200]))
print("valbytes printable snippets:")
for s in re.findall(rb'[\x20-\x7e]{6,}', valbytes):
    try:
        print(s.decode('utf-8'))
    except: pass

open("/mnt/data/transform_candidates.txt","w").write("\n".join([str(x) for x in cand_list]))
open("/mnt/data/debug_strings.txt","w").write("full:\n"+full+"\n\ncollapsed:\n"+collapse_runs(full)+"\n\nfirst_runs:\n"+first_of_runs(full)+"\n")
