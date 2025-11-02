# decode_maxicode.py
# run this: python3 maxiCodeDecoder.py maximum_sound.png
import sys, subprocess, shutil, os

def die(msg, code=1):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)

if len(sys.argv) != 2:
    die(f"Usage: {sys.argv[0]} <image.png>")

img = sys.argv[1]
if not os.path.isfile(img):
    die(f"Input file not found: {img}")

# Look for ZXing jars in CWD
core = next((f for f in os.listdir('.') if f.startswith('zxing-core') and f.endswith('.jar')), None)
javase = next((f for f in os.listdir('.') if f.startswith('zxing-javase') and f.endswith('.jar')), None)
if not core or not javase:
    die("Place zxing-core-*.jar and zxing-javase-*.jar in this directory.")

java = shutil.which('java')
if not java:
    die("Java runtime not found in PATH.")

# Build classpath and call ZXing CommandLineRunner
cp = f"{core}:{javase}"
cmd = [java, "-cp", cp, "com.google.zxing.client.j2se.CommandLineRunner", img]

try:
    out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=20)
    text = out.decode(errors="replace")
except subprocess.CalledProcessError as e:
    text = e.output.decode(errors="replace")
except subprocess.TimeoutExpired:
    die("ZXing timed out (20s).")

# Extract decoded payload lines (ZXing prints path + format + text)
lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
payload = []
for ln in lines:
    if ln.startswith("Raw result:"):
        payload.append(ln.split("Raw result:",1)[1].strip())
    elif ln.startswith("Parsed result:"):
        # Next lines may contain the parsed text; include until a blank or separator
        payload.append(ln.split("Parsed result:",1)[1].strip())
    elif ln and not any(ln.startswith(p) for p in ("file:", "Found", "format:", "Type", "ECLevel", "Timestamp", "Orientation", "Position")):
        payload.append(ln)

decoded = "\n".join([p for p in payload if p])
if not decoded:
    die("No payload extracted. ZXing output:\n" + text, code=2)

print(decoded)
with open("decoded.txt", "w", encoding="utf-8") as f:
    f.write(decoded + "\n")
print("[+] Wrote decoded.txt")
