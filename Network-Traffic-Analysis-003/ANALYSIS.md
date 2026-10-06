# Network Traffic Analysis — DNS Queries

| Field | Value |
|-------|-------|
| **Case ID** | Network-Traffic-Analysis-003 |
| **Analyst** | Beltus Bejanga |
| **Tool** | Wireshark (live Wi-Fi capture) |
| **Traffic** | Real traffic from my own machine (authorised) |
| **Display filter** | `udp` (DNS is UDP/53) |
| **Verdict** | Benign — normal DNS resolution for common services |

> **Real capture** of my own machine's DNS traffic. MAC addresses are redacted; the
> link-local (`fe80::`) addresses are non-routable and the queried domains are
> ordinary public services, so they're kept — they are the analysis.

---

## Why DNS is the most important protocol a SOC watches

Before a device connects to *anything*, it asks DNS "what's the IP for this name?"
That makes DNS the **phone book of the network** — and the single richest hunting
ground in a SOC:

- Even when traffic is encrypted (TLS 1.3, and increasingly Encrypted Client Hello
  that hides the SNI from case 002), the device **still had to resolve the domain
  first** — so DNS often reveals *where* a host is talking.
- Malware uses DNS for **C2 resolution**, **domain generation algorithms (DGA)**,
  and **DNS tunnelling / exfiltration**.

So reading normal DNS well is what lets you spot abnormal DNS fast.

---

## Walkthrough (`01-wireshark-dns.png`)

### 1. These are DNS queries and responses over UDP/53

The detail pane confirms the structure: `User Datagram Protocol, Src Port: 53`,
carrying a `Domain Name System (response)`. Each line in the list is a **Standard
query** or **query response** with a transaction ID (e.g. `0xe7bb`).

### 2. What my machine was resolving

| Domain queried | What it is |
|----------------|-----------|
| `teams.live.com`, `go.trouter.teams.microsoft.com` | Microsoft Teams |
| `go.trouter.skype.com` | Skype / Teams signalling |
| `mobile.events.data.microsoft.com` | **Windows telemetry** endpoint |
| `copilot.cloud.microsoft` | Microsoft Copilot |
| `www.bing.com` | Bing |
| `www.google.com` | Google |
| `claude.ai` | Claude |

All ordinary, reputable services — consistent with a normal Windows desktop in use.
Recognising `mobile.events.data.microsoft.com` as **telemetry** (not something I
opened) is the kind of context that stops an analyst from chasing a false lead.

### 3. Reading A vs AAAA, and the CNAME chains

- **A** records return IPv4 (e.g. `www.google.com A 142.251.155.119`).
- **AAAA** records return IPv6 (e.g. `… AAAA 2001:4860:4802:…`).
- Big services answer with a **CNAME chain** into their CDN. For example:
  `teams.live.com → teamsforlife.afdcafe.tm.svc.cloud.microsoft → … → s-msedge.net`,
  and Bing resolves through `…trafficmanager.net → …edgekey.net → …akamaiedge.net`.
  Seeing `trafficmanager.net` (Azure) and `akamaiedge.net` (Akamai) tells me the
  traffic is being steered through normal cloud/CDN infrastructure — expected, not
  suspicious.

---

## How I'd spot *malicious* DNS (the hunt)

This capture is clean, but here is what I would pivot on if it weren't:

| Red flag | Why it matters | How to detect |
|----------|----------------|---------------|
| High-entropy / random-looking domains | DGA malware (`kq3v9z7x.info`) | Entropy scoring on the query name |
| Many unique subdomains of one domain | **DNS tunnelling / exfil** | Count distinct labels per parent domain |
| Large `TXT` responses, odd record types | Data smuggled in DNS | Alert on unusual record types/sizes |
| Fixed-interval queries to one domain | **C2 beaconing** | Time-delta analysis per destination |
| Newly-registered / low-reputation domains | Fresh attacker infra | Threat-intel + domain-age lookup |

---

## MITRE ATT&CK

| Technique | ID |
|-----------|-----|
| Application Layer Protocol: DNS | T1071.004 |
| Dynamic Resolution: Domain Generation Algorithms | T1568.002 |
| Exfiltration Over Alternative Protocol (DNS) | T1048 |

---

## Companion case

Read alongside [`../Network-Traffic-Analysis-002`](../Network-Traffic-Analysis-002/ANALYSIS.md)
(TLS 1.3): **DNS** shows the name resolution, **SNI** shows the connection that
follows. Together they give a SOC destination visibility even without decrypting
payloads.

---

## Skills Demonstrated

- Filtering and reading DNS traffic in Wireshark (`udp` / port 53)
- Distinguishing **A / AAAA / CNAME** records and following CDN resolution chains
- Recognising telemetry vs. user-initiated traffic
- Knowing DNS-based attacker techniques (DGA, tunnelling, C2, exfil) and how to hunt them
- Responsible handling of capture data (MAC redaction)
