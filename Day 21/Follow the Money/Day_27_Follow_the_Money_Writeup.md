
# Day 27 — **Follow the Money** (Forensics / Phishing / OSINT)

**Me:** Quiet IR assist for Harbor Line Bank. A down‑payment wire looked off; we were asked to **passively** review emails and infrastructure without tipping anyone off. A temporary address was provided for Evelyn since her primary mailbox might be burned: `evelyn.carter@51tjxh.onmicrosoft.com`.  
**Archive password:** `follow_the_money`

---

## Contents
```
.
├── email 1 - FTM.eml
├── email 2 - FTM.eml
├── email 3 - FTM.eml
├── email 4 - FTM.eml
└── email 5 - FTM.eml
```
I parsed each `.eml` and extracted all URLs/domains for pivoting.

---

## 1) Parse the emails & harvest URLs

I used a lightweight email parser (Smasher/regex/CLI) and scanned the headers/body. The interesting hits (normalized):

- **Look‑alike domain:** `https://evergatetltle.netlify.app/` ← **typo** of the legit brand (`evergatetitle` → **tltle**).  
- Also referenced: `https://harbor-line-bank.netlify.app/` (brand spoof).  
- Multiple `lh3.googleusercontent.com/sitesv/...` assets (hosted images).
- Legit‑looking From/To with Outlook routes in headers (common for BEC‑style staging).

Observations:
- Classic **typo‑squatting** to funnel victims into a fake wire workflow.
- Netlify hosting for both victim brand and “bank” facsimiles.

---

## 2) Visit the fake site & trigger the next pivot

On the **fake Evergate** site the “Transfer” flow accepted junk data and returned a Base64 value:

```
aHR0cHM6Ly9uMHRydXN0eC1ibG9nLm5ldGxpZnkuYXBwLw==
```

Decode:
```bash
echo 'aHR0cHM6Ly9uMHRydXN0eC1ibG9nLm5ldGxpZnkuYXBwLw==' | base64 -d
# https://n0trustx-blog.netlify.app/
```

Landing there exposed the actor **username**: **`N0TrustX`** ✅ (answer: “What is the username of the hacker?”).

---

## 3) Actor OSINT → GitHub repo → embedded payload

From the blog there was a link to a GitHub profile with a single repo. Inside, `spectre.html` contained a “payload modal” with a hidden Base64 blob:

```html
<div id="encodedPayload" class="hidden">
  ZmxhZ3trbDF6a2xqaTJkeWNxZWRqNmVmNnltbHJzZjE4MGQwZn0=
</div>
```

Decode:
```bash
echo "ZmxhZ3trbDF6a2xqaTJkeWNxZWRqNmVmNnltbHJzZjE4MGQwZn0=" | base64 -d
# flag{kl1zklji2dycqedj6ef6ymlrsf180d0f}
```

**Flag:** `flag{kl1zklji2dycqedj6ef6ymlrsf180d0f}`

> Note: This matched the CTF question ordering—EML → spoof site → blog pivot → GitHub → HTML payload → Base64 flag.

---

## 4) What was going on (threat flow)

1. Target receives phish thread (**five** EMLs) referencing a property (`200 E. Wharf Drive`) and bank/titling brands.  
2. Victim is funneled to a **typo‑squatted Netlify** page (`evergatetltle`), styled to look legit.  
3. “Transfer” submission returns a Base64 that redirects to the actor’s **Netlify blog**.  
4. The blog exposes the handle **`N0TrustX`** and links to a **GitHub** repo.  
5. The repo’s HTML (`spectre.html`) hides a Base64 object that contains the **flag**.

This is a textbook **brand‑impersonation → off‑platform landing → OSINT‑based lure**, with the payload split across multiple commodity services (Netlify, Googleusercontent, GitHub).

---

## 5) IOCs & Artifacts

**Domains/URLs**
- `https://evergatetltle.netlify.app/` (**typo‑squat** of the title company)  
- `https://harbor-line-bank.netlify.app/` (bank spoof)  
- `https://n0trustx-blog.netlify.app/` (actor blog)  
- `https://lh3.googleusercontent.com/sitesv/<...>` (image hosting)
- GitHub profile/repo referenced by the blog (name omitted here; visible via the blog link)

**Actor**
- Handle: **`N0TrustX`**

**Files**
- `email N - FTM.eml` x5 (source evidence)
- `spectre.html` (GitHub) with embedded Base64 payload

**Decoded payload flag**
- `flag{kl1zklji2dycqedj6ef6ymlrsf180d0f}`

---

## 6) Defensive notes (what I’d recommend in a real IR)

- Block/submit Netlify abuse for the typo‑squatted domains.  
- Search mailflow for other deliveries from the sending infra and subjects matching the thread (M365: `Subject:"200 E. Wharf Drive"` etc.).  
- Add detections for external “payment portal” links redirecting to Netlify with brand keywords.  
- Hunt for **device/browser beacons** to the listed Netlify domains in proxy/EDR logs.  
- Train staff on **“one‑letter typos”** in payment flows; require out‑of‑band verification.

---

## Answers (per challenge prompts)

- **Hacker username:** `N0TrustX`  
- **Final flag:** `flag{kl1zklji2dycqedj6ef6ymlrsf180d0f}`

---

## Commands used (quick ref)

```bash
# decode pivot link from the fake “Transfer” page
echo 'aHR0cHM6Ly9uMHRydXN0eC1ibG9nLm5ldGxpZnkuYXBwLw==' | base64 -d

# decode hidden payload in spectre.html
echo "ZmxhZ3trbDF6a2xqaTJkeWNxZWRqNmVmNnltbHJzZjE4MGQwZn0=" | base64 -d
```

**Done.** Clean, passive, all in-browser pivots—no need to touch the client’s infra.
