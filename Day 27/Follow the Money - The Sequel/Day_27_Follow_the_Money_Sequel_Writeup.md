
# Day 27 — **Follow the Money: The Sequel** (OSINT / Attribution via Social + Mapping)

**Me:** We previously attributed the handle **`N0TrustX`** from the wire-fraud phish chain. This phase was to passively enrich that handle and determine **the town** they live in—no contact, no active probing. Pure OSINT, reproducible, and defensible.

---

## TL;DR
- Pivoted from `N0TrustX` → found a **Twitter/X** profile.
- Bio included an octal-encoded string → `I am the one who knocks` (noise, not a pivot key).
- Scanned the media timeline; saved all posted photos.
- **EXIF was stripped**, so we used **visual landmarks** + **reverse image search**.
- Landmarks led to **Wytheville** (street décor + signage match).
- Cross-referenced posts mentioning **coffee / “Grind”** with Wytheville businesses → **The Grind**.
- On The Grind’s Google reviews/“Opinions” view, a reviewer dropped the CTF **flag**.
- **Answer (Town):** `Wytheville`  
- **Flag:** `Flag{this_is_good_java}`

---

## 1) Enumerate the handle across platforms

I started wide (you can replicate with *Sherlock*, *WhatsMyName*, or simple dorking). Sherlock struck out; direct platform searches worked.

**Search operators (examples):**
```text
site:twitter.com "N0TrustX"
site:x.com "N0TrustX" OR "@N0TrustX"
"by N0TrustX" blog netlify github
```

**Hit:** A Twitter/X profile with handle `N0TrustX`. The bio carried an octal teaser:

```
111 40 141 155 40 164 150 145 40 157 156 145 40 167 150 157 40 153 156 157 143 153 163
```

**Decode (octal → ASCII):**
```python
s = "111 40 141 155 40 164 150 145 40 157 156 145 40 167 150 157 40 153 156 157 143 153 163"
print(''.join(chr(int(o,8)) for o in s.split()))
# I am the one who knocks
```
Cool easter egg, **not** a path forward.

---

## 2) Pull the media; check EXIF; attempt reverse image

I bulk-saved the media from the profile (right-click save is fine; no automation needed). First stop is EXIF for any GPS crumbs:

```bash
exiftool *.jpg | egrep -i 'gps|lat|lon|city|location' || echo "no gps fields"
# EXIF stripped in my set
```

With EXIF dead, we pivot to **visual OSINT**. Two quick tools:

- **Google Lens / Images**: drag & drop the photo, check “Visually similar” and “Pages with matching images.”
- **Yandex / Bing** reverse image: sometimes surfaces regional blogs or business sites faster.

**Clues collected from timeline photos:**
- Distinct streetlamp banners and color scheme.
- Visible partial sign characters and brick façade pattern.
- Seasonal decoration style that’s consistent in a known region.

These were enough to narrow down to **Wytheville** on image hits (street banners + storefronts matched in open web photos of Wytheville’s downtown).

> Tip: When EXIF is absent, build a *feature list* per photo (materials, brick patterns, typefaces, pole heights, banner crop shapes, rooflines). Small-town downtowns have unique combinations.

---

## 3) Correlate content theme (coffee) to local venues

The profile tone made repeated references to ***java*** (coffee), and there were captions hinting at “grind.” With **Wytheville** hypothesized, I enumerated coffee shops there.

- Google Maps → `Wytheville coffee` → **The Grind** surfaces.
- The handle’s mentions lined up nicely with that brand name (“Grind”).

At this point, it’s a clean, non-intrusive cross-check to scan public **reviews** for easter eggs.

---

## 4) Find the flag in public reviews (“Opinions”)

On The Grind’s listing (Google), I searched the reviews/opinions panel for **flag** (and skimmed recent entries). A reviewer had buried the CTF string right there.

**Flag:** `Flag{this_is_good_java}` ✅

> Why this works in CTFs: actors (or the challenge author) often leave breadcrumbs on high-visibility, low-friction surfaces like public review text, social bios, or pinned posts.

---

## 5) Answer (Town)

**`Wytheville`**

---

## 6) Replicable workflow (copy/paste)

```bash
# 1) Quick dorks
# (Use your browser; these are reference strings)
# site:twitter.com "N0TrustX"
# site:x.com "@N0TrustX"

# 2) Decode the octal hint
python3 - <<'PY'
s = "111 40 141 155 40 164 150 145 40 157 156 145 40 167 150 157 40 153 156 157 143 153 163"
print(''.join(chr(int(o,8)) for o in s.split()))
PY

# 3) Try EXIF (likely stripped)
exiftool *.jpg | egrep -i 'gps|lat|lon|city|location' || true

# 4) Visual OSINT
# - Google Images/Lens drag-and-drop
# - Yandex Images
# - Look for signage/banners → "Wytheville" match

# 5) Map correlation
# Google Maps → "Wytheville coffee"
# Check "The Grind" → open reviews/Opinions → search "flag"
```

---

## 7) Notes & ethics
- Stayed **passive**: no DMs, no friend requests, no link-clicking beyond public content.
- **No doxxing**: Town-level attribution only, grounded in open, publicly posted materials.
- Kept a **local evidence pack**: raw screenshots, page URLs, timestamps, hashes of images for chain-of-custody if required.

---

## Artifacts
- Handle: `N0TrustX`
- Platform: Twitter/X (one matching account)
- Geo: **Wytheville**
- Business pivot: **The Grind** (Wytheville coffee shop)
- Final: `Flag{this_is_good_java}`
