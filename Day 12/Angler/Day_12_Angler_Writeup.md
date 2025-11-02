
# Day 12 — **Angler** (Misc / Cloud OSINT / Crypto-ish)

**Me:** The note looked like nonsense scribbles, plus a line of hex: `42 6c 6f 77 66 69 73 68`. The drunk-fisherman hint about a “fishing pole,” *murlocs in Entra*, and **CyberChef** was the roadmap. It turned out to be a short crypto layer that pivoted into an **Azure / Entra** hunt with multiple bonus flags and a final twist that required **actually sending an email**.

---

## TL;DR
- Hex `42 6c 6f 77 66 69 73 68` → ASCII “**Blowfish**”. Use that **as the key/IV seed** for the provided `scribbles.dat`.  
- Decrypting yields binary that **looks like junk** until you let **CyberChef’s “Magic”** hint **reversed Base64**. Reverse → base64‑decode → optional (de)compression → plaintext with **Entra login context**.
- Log into the provided Entra tenant (device code flow) with the **phisher** account.  
- Enumerate users, groups, service principals; flags are hidden in **Group.Description**, **App/ServicePrincipal Notes**, and **Purview Audit** search.  
- **Final flag**: the “? answer” was to **send an email** to the **odd address revealed in a group description** (the *naddy* address). An auto‑reply yielded the last flag which **ends with `?`**.

---

## Artifact
- `scribbles.dat` — opaque data block dropped with the challenge.
- Hint text: `42 6c 6f 77 66 69 73 68` and the story about *Entra* + *CyberChef*.

---

## 1) Crack the “scribbles”: Blowfish → reversed Base64
The hex decodes to ASCII “Blowfish”—that’s both the **cipher family** and the **keying clue**.

```bash
# sanity
echo "426c6f7766697368" | xxd -r -p
# -> Blowfish

# Try using that material as KEY (and IV if mode requires it).
# In CyberChef, recipe example:
#   - From Hex ("42 6c ... 68") → "Blowfish"
#   - Decrypt → Blowfish (try ECB/CBC; if CBC, use same bytes for IV)
#   - If your output still looks structured but unreadable:
#       * Reverse (the text)
#       * From Base64
#       * (Try Gzip/Zlib if magic bytes like 1F 8B / 78 9C appear)
```

**Why “UTF‑16LE” sometimes matters:** If the payload includes **PowerShell/Windows**-style text, treat it as UTF‑16LE when decoding later stages. (In my run here, the core was standard ASCII after reversing Base64.)

**Outcome:** We get plaintext with **tenant context** and a nudge to Entra/Azure CLI.

---

## 2) Entra entry (device code, no subscription)
Use Azure CLI device login. The challenge creds looked like `phisher@<tenant>.onmicrosoft.com` with a known password.

```bash
az login --allow-no-subscriptions
# → open https://microsoft.com/devicelogin, paste the code shown
# Select the tenant if prompted
```

If MFA blocks the default user, try any **secondary admin** mentioned in the plaintext, or re-run when MFA is **not enforced** on that principal (the challenge momentarily allowed that).

---

## 3) Quick enumerations (users, groups, SPs)

### Users (to set the scene)
```bash
az ad user list -o table
```

### Groups (first bonus flag)
Group **Description** fields contained a flag:
```bash
az ad group list -o table
# Look at Description and DisplayName columns
# Example hit:
# Description: nattyp@51tjxh.onmicrosoft.com
# DisplayName: flag{mczxals2amxc}    # ends with 'c'
```

### Service Principals / Applications (two more flags)
The **Notes** field on some SPs/apps contained flags. Query everything and filter for `flag{`:

```bash
# Service Principals
az ad sp list --all --query "[?contains(to_string(notes),'flag{')].[displayName,notes,id]" -o tsv

# Applications (if needed)
az ad app list --all --query "[?contains(to_string(notes),'flag{')].[displayName,notes,id]" -o tsv
```
Expect two flags here (one **ends with `a`**, one **ends with `m`**).

---

## 4) Purview Audit (another bonus flag)
If the tenant exposes **Purview (Audit)**, search for **`flag`** in a time window (e.g., Sep → Today). Export the CSV results and scan:

```bash
# after export
grep -n 'flag{' *.csv
# Expect the flag that **ends with `d`**
```

If the portal is noisy, favor API/CLI where allowed, but the portal export worked fine for me.

---

## 5) The final “angler” hook — send the email
The wording “fisherman / fishing pole / Entra” + the first flag’s group **Description** exposed an **odd mailbox** (the “*naddy*” address). The intended solve: **email that address** with relevant keywords so an **auto-responder** returns the **final flag (ends with `?`)**.

What worked for me:
- **To:** the address from the group Description (e.g., `nattyp@51tjxh.onmicrosoft.com` in my run).  
- **Subject/Body:** include context keywords from the challenge (e.g., `flag phisher blowfish 42 6c 6f 77 66 69 73 68 426c6f7766697368`).  
- **Result:** a reply with the **final flag**, which **ends with `?`** as required by the prompt.

> If you prefer scripting, you can send via any SMTP/Graph method available to you. For the CTF, a normal email client was enough.

---

## Checklist of flags found
- Group Description → **flag that ends with `c`** ✅  
- Service Principal / App Notes → **flag that ends with `a`** ✅ and **flag that ends with `m`** ✅  
- Purview Audit CSV → **flag that ends with `d`** ✅  
- Email auto‑reply (“naddy” address) → **final flag that ends with `?`** ✅

---

## Commands cheat‑sheet

```bash
# Login (tenant-level)
az login --allow-no-subscriptions

# Users / Groups
az ad user list -o table
az ad group list -o table

# Hunt flags in Notes
az ad sp list --all --query "[?contains(to_string(notes),'flag{')].[displayName,notes]" -o tsv
az ad app list --all --query "[?contains(to_string(notes),'flag{')].[displayName,notes]" -o tsv

# Purview: use portal to export Audit CSV, then:
grep -n 'flag{' *.csv
```

---

## Takeaways
- The **hex → Blowfish** hint was literal; use the word as **key/IV seed** and keep an open mind on **mode** (ECB/CBC).  
- **CyberChef “Magic”** is great for spotting **reversed Base64** and suggesting follow‑up transforms.  
- Cloud side: flags hidden in **metadata** (Group.Description, SP/App.Notes, Audit logs) are easy to miss unless you **query broadly**.  
- The final **social/email step** matched the “angler” theme—don’t overthink it: **send the mail.**

**Final flag:** (returned via email auto‑reply) → _value ending with `?`_
