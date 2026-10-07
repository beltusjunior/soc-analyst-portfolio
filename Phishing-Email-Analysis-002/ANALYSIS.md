# Phishing Email Forensics — iCloud/Apple Impersonation

| Field | Value |
|-------|-------|
| **Case ID** | Phishing-Email-Analysis-002 |
| **Analyst** | Beltus Bejanga |
| **Source** | A real phishing email received in my own mailbox (Spam folder) |
| **Method** | Raw email-header analysis (SPF / DKIM / DMARC), sender & URL analysis |
| **Verdict** | Phishing — brand impersonation / credential harvesting. HIGH confidence |

> Real email analyzed from its **raw headers**. My personal address and the
> provider's internal routing/message IDs are redacted; only the attacker's
> indicators are kept. URLs are **defanged** (`hxxp`, `[.]`) so they can't be
> clicked by accident — standard analyst hygiene.

---

## The lure

A spam-foldered email titled *"iCloud storage is almost full"* with a friendly
sender name of **"iCloud Storage Notice,"** urgency ("upgrade now to avoid data
loss"), and a button leading to a link. Classic consumer phishing: impersonate a
trusted brand, create fear, drive a click to a credential/payment page.

---

## The standout lesson: **SPF passed — and it's STILL phishing** 🎯

```
Received-SPF: pass (domain of vipcampus.sbs designates 66.55.83.9 as permitted sender)
Authentication-Results: spf=pass smtp.mailfrom=vipcampus.sbs; dkim=unknown; dmarc=unknown
```

A junior reflex is "SPF pass = legitimate." **That's the trap.** SPF only proves
the mail came from a server the *sending domain* authorized. The attacker **owns
`vipcampus.sbs`**, so they authorized their own server — SPF passes every time.

**Email authentication validates the sending domain, not the impersonated brand.**
The word "iCloud" appears only in the **display name**, which no SPF/DKIM/DMARC
check ever inspects. So `spf=pass` here means *"this really came from
vipcampus.sbs"* — not *"this is really Apple."* (`dkim` and `dmarc` are both
`unknown` — not signed or validated.) Reading authentication results correctly,
instead of trusting a green "pass," is the core skill this case demonstrates.

---

## Header analysis (`01-header-analysis.png`)

| Header | Value | What it tells me |
|--------|-------|------------------|
| `From` | iCloud Storage Notice `<…@vipcampus.sbs>` | **Display-name spoofing** — brand in the name, throwaway domain in the address |
| `Return-Path` | `<return.…@vipcampus.sbs>` | Bounce path = same disposable domain, not Apple |
| `Received` (EHLO) | `66.55.83.9` / `fxu.netexcom.click` | Sending host is a **second** disposable domain (`.click`) |
| `Message-ID` | `…@atbwc.netexcom.click` | A **third** disposable domain |
| `Received-SPF` | `pass` | Passes — because the attacker owns the domain (see above) |
| `Authentication-Results` | `spf=pass; dkim=unknown; dmarc=unknown` | Only envelope domain validated; brand not verified |

**Throwaway TLDs** throughout — `.sbs`, `.click`, `.store` — cheap, abused,
disposable infrastructure.

### The payload
- **Link:** `hxxps://tinyurl[.]com/yc4enenr?…&uid=2&…&cid=7414` — a **URL
  shortener** hides the true destination, and the `uid`/`cid`/`pid` parameters are
  **per-victim tracking IDs**, a hallmark of a phishing kit.
- **Tracking pixel:** `hxxp://timestart[.]store/?…` loaded as a **1×1 hidden
  image** — an **open-tracking beacon** that confirms the address is live the
  moment the email is viewed (over plain HTTP).
- **Image-map body:** the message is images (`zupimages.net`, `imgur`) wrapped in
  clickable `<map>`/`<area>` regions with almost no real text — deliberately
  **evading keyword-based spam filters**.

---

## Indicators of Compromise

| Type | Indicator |
|------|-----------|
| Sender | `…@vipcampus.sbs` (display name "iCloud Storage Notice") |
| Sending IP | `66.55.83.9` |
| Infra domains | `vipcampus.sbs`, `netexcom.click`, `timestart.store` |
| Phishing URL | `hxxps://tinyurl[.]com/yc4enenr` |
| Tracking pixel | `hxxp://timestart[.]store/` |

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Phishing: Spearphishing Link | T1566.002 |
| Phishing for Information | T1598 |
| Masquerading (display-name spoof) | T1036 |

---

## Response

**As a user:** don't click, don't reply. It's already in Spam — report as
phishing and delete. Never log into Apple from an email link; go to `icloud.com`
directly.

**As a SOC analyst:**
1. Block the sender domain (`vipcampus.sbs`) and the infra domains at the mail/web gateway.
2. Detonate the TinyURL + final destination in a sandbox / URL intel (don't visit directly).
3. Search mail logs for other recipients; if it hit multiple users, alert them and blocklist the IOCs.
4. If anyone clicked and entered credentials, treat as account compromise — force reset + review.

---

## Note on scope — phishing vs. BEC
This is **consumer credential phishing** (brand impersonation), not Business Email
Compromise. BEC specifically targets organizations for money (fake invoices,
wire-transfer and vendor-change requests, executive impersonation). The **analysis
skills are identical** — sender/header analysis, SPF/DKIM/DMARC interpretation,
display-name spoofing, lookalike domains, URL and infrastructure analysis — which
is exactly the foundation BEC investigation builds on.

---

## Skills Demonstrated
- Reading and interpreting **raw email headers**
- **SPF / DKIM / DMARC** interpretation — and why "SPF pass" ≠ legitimate
- Detecting **display-name spoofing** and disposable attacker infrastructure
- Recognizing **URL-shortener obfuscation**, per-victim tracking, and **open-tracking pixels**
- IOC extraction and **defanging**; mapping to MITRE ATT&CK
- Responsible handling — redacting personal routing before publishing
