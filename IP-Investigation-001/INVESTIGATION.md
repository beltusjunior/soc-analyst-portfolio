# IP Investigation Report — 157.66.224.37

| Field | Value |
|-------|-------|
| **Case ID** | IP-Investigation-001 |
| **Investigation date** | September 19–20, 2026 |
| **Time spent** | 45 minutes |
| **Analyst** | Beltus Bejanga |
| **Verdict** | Malicious: active scanning and brute-force source |
| **Severity** | High (Critical if this IP shows a *successful* login in your environment) |
| **Recommended action** | Block at the perimeter, then hunt for any successful authentication from this IP |

---

## Executive Summary

157.66.224.37 is a VPS address in Vietnam (AS150895, netname HOAVPS-VN). Eleven independent sources reported it to AbuseIPDB 12 times, with the most recent report five minutes before this review. The reports describe fast, automated scanning of **RDP (TCP/3389)** and **SSH**, plus brute-force attempts. Shodan shows no services on the IP, so it is used to **launch** attacks rather than to host anything. Only 1 of 89 VirusTotal vendors (CINS Army) flags it. That is common for short-lived scanning infrastructure, and it shows why one reputation source is not enough.

---

## Indicators of Compromise

| Type | Indicator | Context |
|------|-----------|---------|
| IPv4 | `157.66.224.37` | Scanning and brute-force source |
| CIDR | `157.66.224.0/23` | Allocation that contains the IP (HOAVPS-VN) |
| ASN | AS150895 — EZ Technology Company Limited | Hosting/VPS provider |
| Ports targeted | TCP/3389 (RDP), TCP/22 (SSH) | From the reporters' comments |

---

## Step 1 — AbuseIPDB (`01-abuseipdb-report.png`)

- **12 reports from 11 distinct sources.** First reported September 11, 2026; last reported 5 minutes before review.
- AbuseIPDB banner: *"potentially still actively engaged in abusive activities."*
- Categories: **Port Scan, Brute-Force, SSH, Hacking**.
- Reporter comments:
  - `noconex`: Wazuh alert, *Suricata: ET SCAN Behavioral Unusually fast Terminal Server Traffic*. This is an IDS signature for fast RDP connection attempts.
  - `OceanTreasure`: *tcp/3389; unsolicited SYN to a port that has never been offered on this address.* This is a honeypot-style detection.
  - `xmission.com`: *Blocked by UFW (TCP on 3389) … TTL 244.* A host firewall blocked the traffic.

**Analyst note:** most of the evidence points at **RDP (3389)**, not only SSH. A defender should check both Windows RDP logon events (4625/4624) and Linux `sshd` logs.

## Step 2 — VirusTotal (`02-virustotal-results.png`)

- **1/89 vendors** flag the IP as malicious (CINS Army). The rest return clean.
- Network: `157.66.224.0/23`, **AS150895 (EZ TECHNOLOGY COMPANY LIMITED)**, country VN.

**Analyst note:** a low VirusTotal score does not mean the IP is clean. CINS Army is built from sensor and honeypot data, and that matches the behavior AbuseIPDB reporters saw. The independent sources agree.

## Step 3 — Shodan (`03-shodan-services.png`)

- **No results.** Shodan's scanners found no exposed services on this IP.

**Analyst note:** an IP that reaches out to scan others but listens on nothing fits a disposable VPS used only as an attack source.

## Step 4 — WHOIS / RIR data (`04-whois-geolocation.png`, `05-whois-contacts.png`)

| Field | Value |
|-------|-------|
| inetnum | 157.66.224.0 – 157.66.225.255 |
| netname | HOAVPS-VN |
| descr | HOA FRUITS LLC, Quy Nhon City, Binh Dinh, Vietnam |
| Registry | APNIC (maintained by VNNIC, `MAINT-VN-VNNIC`) |
| Route | 157.66.224.0/23, AS150895 |
| Abuse contact | Listed in APNIC WHOIS (`IRT-VNNIC-AP` abuse mailbox, plus the network's own abuse address) |
| Allocation status | ALLOCATED PORTABLE; last modified 2024-05-06 |

**Analyst note:** "HOAVPS" is a small VPS reseller. Cheap VPS ranges are often used for scanning because the IPs are easy to replace. Geolocation tells you where the *server* is, not where the *operator* is, so it is not attribution.

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|----------|
| Active Scanning: Scanning IP Blocks | T1595.001 | Unsolicited SYNs to 3389 across many reporters |
| Brute Force: Password Guessing | T1110.001 | "Brute-Force" and "SSH" categories |
| Remote Services: RDP / SSH (targeted) | T1021.001 / T1021.004 | The services under attack |

---

## Detection & Hunting

The detection searches for this case are in [`../Detections`](../Detections):

- `Detections/splunk/brute_force_auth.spl`: brute force followed by a success from the same source (SSH and Windows RDP).
- `Detections/splunk/ioc_sweep.spl`: sweeps firewall, proxy and authentication logs for every IOC in this portfolio.
- `Detections/sigma/ssh_bruteforce_then_success.yml`
- `Network-Traffic-Analysis-001` shows what this attack pattern looks like on the wire, in a packet capture recorded in a lab.

---

## Response Actions

1. **Contain.** Block `157.66.224.37` (or the whole `/23` if your organization has no business with this provider) at the firewall or edge.
2. **Hunt.** Search the last 30 days of authentication logs for this IP:
   - Linux: `Failed password` / `Accepted password` from this source.
   - Windows: Event ID **4625** (failed) and **4624 logon type 10** (RDP success).
   - Any success → **escalate to Critical**: treat the account as compromised, reset its credentials, review what the session did.
3. **Harden.** Do not expose RDP or SSH to the internet. Put them behind a VPN, require MFA, use key-only SSH, and add account lockout or fail2ban.
4. **Report.** Send evidence (timestamps, ports, log excerpts) to the abuse contact in WHOIS, and report to AbuseIPDB.

---

## Lessons Learned

- Check several reputation sources. VirusTotal gave **1/89**, while AbuseIPDB showed **12 reports in 9 days**.
- Read the raw reporter comments. They showed the main target was **RDP**, which category tags alone did not make obvious.
- An IP with no open services that keeps generating outbound attack traffic is a typical sign of disposable attack infrastructure.
