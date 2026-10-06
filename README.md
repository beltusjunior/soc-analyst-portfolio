# SOC Analyst Portfolio — Real Threat Investigations

A hands-on portfolio demonstrating security operations center (SOC) skills:
threat intelligence investigation, malware triage, phishing analysis, SIEM
querying, network forensics, detection engineering, and incident response.

![Investigations](https://img.shields.io/badge/Investigations-6-2b6cb0)
![Detections](https://img.shields.io/badge/Detections-Splunk%20%2B%20Sigma-6b46c1)
![Framework](https://img.shields.io/badge/Mapped%20to-MITRE%20ATT%26CK-c53030)
![IR](https://img.shields.io/badge/Incident%20Response-SANS%20PICERL-2f855a)

## Portfolio Overview

| | |
|---|---|
| **Investigations** | 8 — IP, phishing, malware, SIEM, network forensics (×3), network discovery |
| **Detection content** | 2 Splunk searches + 3 Sigma rules + consolidated IOC list |
| **Incident response** | 1 full IR report (SANS PICERL lifecycle) |
| **Frameworks** | MITRE ATT&CK mapping on every case; CIS / NIST references |
| **Tools used** | AbuseIPDB, VirusTotal, Shodan, WHOIS, PhishTank, URLhaus, AlienVault OTX, Splunk, Wireshark/tshark, Advanced IP Scanner |
| **Analyst** | Beltus Bejanga — Thorold, Ontario, Canada |

### How to read this portfolio

Each investigation folder holds a markdown report + the screenshots behind it,
and follows the same flow: **Summary → IOCs → MITRE ATT&CK → Detection → Response**.
The [`Detections/`](Detections/README.md) folder turns the findings into reusable
Splunk and Sigma rules. Start with whichever case matches the skill you want to see:

| Skill | Best case to read |
|-------|-------------------|
| Threat intelligence | IP-Investigation-001 |
| Phishing analysis | Phishing-Email-Analysis-001 |
| Malware triage | Malware-Analysis-001 |
| **Incident response** | Malware-Analysis-001 → [INCIDENT-RESPONSE.md](Malware-Analysis-001/INCIDENT-RESPONSE.md) |
| SIEM / SPL | Splunk-SIEM-Analysis-001 |
| Network forensics | Network-Traffic-Analysis-001 |
| Asset discovery | Network-Discovery-001 |
| Detection engineering | Detections/ |

---

## Investigations

### 1. IP Investigation — `157.66.224.37`
Scanning / brute-force source (VPS in Vietnam, AS150895 / HOAVPS-VN). 12 AbuseIPDB
reports from 11 sources; reporters show the main target is **RDP (3389)** and SSH.
Shodan shows no services — disposable attack infrastructure.
**Verdict:** Malicious (High). → [`IP-Investigation-001/`](IP-Investigation-001/INVESTIGATION.md)

### 2. Phishing Analysis — `oluwaburnazip--renusharawat.replit.app`
Verified phishing (PhishTank #9528356, 100%) hosted on free Replit infrastructure,
**0/89 AV detections** — new and undetected, which makes it *more* dangerous.
**Verdict:** Verified active phishing (High, Critical in-context). → [`Phishing-Email-Analysis-001/`](Phishing-Email-Analysis-001/ANALYSIS.md)

### 3. Malware Analysis — `whack.sh`
Linux ELF dropper/stager, **28/64** VT detections. In-memory execution via
`memfd_create`→`fexecve`, XOR-decrypted payload (key `0x99`), C2 at `82.157.13.47`,
masquerades as `[kworker/0:2]`.
**Verdict:** Critical. → [`Malware-Analysis-001/`](Malware-Analysis-001/REPORT.md)
Includes a full **[incident-response report](Malware-Analysis-001/INCIDENT-RESPONSE.md)** (SANS PICERL lifecycle).

### 4. Splunk SIEM Analysis — Internal Audit Logs
9,427 audit events analysed with SPL and the `internal_audit_logs` data model;
action breakdown and interpretation. Skills demo on benign sample data.
→ [`Splunk-SIEM-Analysis-001/`](Splunk-SIEM-Analysis-001/ANALYSIS.md)

### 5. Network Traffic Analysis — SSH Brute Force → Compromise *(new)*
Packet forensics on a **synthetic, lab-generated** capture modelling the attacker
from case 1. tshark analysis finds **41 connection attempts, 40 resets, and 1
sustained 30-second session** — the single successful login hiding in the burst.
→ [`Network-Traffic-Analysis-001/`](Network-Traffic-Analysis-001/ANALYSIS.md)

---

### 6. Network Traffic Analysis — Live TLS 1.3 Capture *(real data)*
Real Wireshark capture of my own machine: a TCP handshake + **TLS 1.3** session to
`ecs.office.com`. Key takeaway — the encrypted session still leaks the **SNI**
(destination domain) in cleartext, which is how a SOC detects bad traffic without
breaking TLS. Own IP/MACs redacted.
→ [`Network-Traffic-Analysis-002/`](Network-Traffic-Analysis-002/ANALYSIS.md)

### 7. Network Traffic Analysis — DNS Queries *(real data)*
Real Wireshark capture of my own DNS traffic: A/AAAA/CNAME records resolving Teams,
Bing, Copilot, Google, and Windows telemetry through Azure/Akamai CDNs. Explains why
DNS is a SOC's richest hunting ground (DGA, tunnelling, C2) and how to spot each.
→ [`Network-Traffic-Analysis-003/`](Network-Traffic-Analysis-003/ANALYSIS.md)

### 8. Network Discovery on a Shared Network *(real data)*
Passive host discovery on the **shared, landlord-provided** network my devices connect
to (22 live hosts). The real finding: my PC and phone sit on a flat network with ~20
devices I don't control — so I treat it as **untrusted** and harden my own devices,
rather than touching equipment that isn't mine. Demonstrates correctly scoping
authority and threat-modeling my own exposure. MACs/serials redacted.
→ [`Network-Discovery-001/`](Network-Discovery-001/ANALYSIS.md)

---

## Detections *(new)*

Each investigation is turned into reusable detection content in
[`Detections/`](Detections/README.md):

- **Splunk:** brute-force-to-success correlation (SSH + RDP); portfolio-wide IOC sweep.
- **Sigma:** SSH brute force, Linux kworker masquerade, phishing domain access.
- **IOCs:** consolidated machine-readable list — [`Detections/iocs.csv`](Detections/iocs.csv).

---

## Skills Demonstrated

**Threat Intelligence:** IP reputation & geolocation, phishing verification, malware
hash/behaviour triage, multi-source correlation, IOC extraction.
**SIEM & Detection Engineering:** SPL queries, data models, Sigma rule authoring,
alert threshold tuning, MITRE ATT&CK mapping.
**Network Forensics:** Wireshark/tshark, conversation & flag analysis, reading a
brute-force-to-compromise pattern on the wire.
**SOC Operations:** investigation workflow, severity assessment, containment &
response planning, honest reporting (no over-claimed attribution).

---

## Methodology

Each investigation follows: **Recon → Analysis (multiple tools) → Documentation
(screenshots + IOCs) → Verdict (severity) → Detection & Response.** All cases use
real, verifiable data except the network capture, which is clearly labelled as a
lab-generated synthetic file.

---

## Training

- **Course completed:** Splunk — *"What is Splunk?"* (free eLearning), March 5, 2023.
  Certificate: [`Splunk-SIEM-Analysis-001/Certificate_of_Splunk_Completion.pdf`](Splunk-SIEM-Analysis-001/Certificate_of_Splunk_Completion.pdf).
  *(This is an introductory course completion, not a professional Splunk certification.)*

---

## Next Steps

- Behavioural malware detonation in an isolated sandbox
- Zeek/Suricata analysis of live-style captures
- Incident response playbooks and alert tuning write-ups

---

**Last Updated:** October 6, 2026
**Portfolio Owner:** Beltus Bejanga — Thorold, Ontario, Canada

### Contact
- GitHub: [@beltusjunior](https://github.com/beltusjunior)
- LinkedIn: [Tchatchoua Beltus Bejanga](https://www.linkedin.com/in/tchatchoua-beltus-bejanga-88475b242/)
