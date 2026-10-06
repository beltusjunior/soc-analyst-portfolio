# IP Enrichment Tool

A small command-line tool that enriches an IP address with threat intelligence
from **AbuseIPDB**, **VirusTotal**, and **RDAP/WHOIS**, then correlates the
sources into a single verdict.

It automates the exact workflow from [`../../IP-Investigation-001`](../../IP-Investigation-001/INVESTIGATION.md):
instead of pasting an IP into three websites by hand, one command pulls all
three sources and weighs them together — because no single reputation score
decides the call, correlation does.

> Standard library only — no `pip install` needed. API keys are read from
> environment variables and are never printed or written to disk.

---

## What it reports

| Source | What it adds | Key needed |
|--------|--------------|------------|
| **AbuseIPDB** | Abuse confidence score, report count, distinct reporters, ISP, usage type | Yes (free) |
| **VirusTotal** | How many vendors flag it malicious/suspicious, ASN/owner, reputation | Yes (free) |
| **RDAP / WHOIS** | Network name, owning org, CIDR, country | No |

The **verdict** is conservative: any strong signal (AbuseIPDB confidence ≥ 50%,
or ≥ 1 VirusTotal malicious vendor) raises the severity. It never calls an IP
"safe" — only "no strong indicators," because absence of evidence isn't evidence
of absence.

---

## Setup (one time)

**1. Get free API keys**
- **AbuseIPDB:** create a free account at <https://www.abuseipdb.com>, then
  **Account → API → Create Key**.
- **VirusTotal:** create a free account at <https://www.virustotal.com>, then
  **profile → API Key**.

**2. Set them as environment variables**

macOS / Linux / Git Bash:
```bash
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export VT_API_KEY="your_virustotal_key"
```

Windows PowerShell:
```powershell
$env:ABUSEIPDB_API_KEY="your_abuseipdb_key"
$env:VT_API_KEY="your_virustotal_key"
```

> Keep keys out of the code and out of git — environment variables only.

---

## Usage

```bash
# Human-readable report
python3 ip_enrich.py 157.66.224.37

# Machine-readable JSON (for piping into other tools)
python3 ip_enrich.py 157.66.224.37 --json
```

### Example output
```
=== IP Enrichment Report — 157.66.224.37 ===

[AbuseIPDB]
    Confidence           100%
    Total reports        12
    Distinct reporters   11
    ISP                  HOA FRUITS LLC
    Usage type           Data Center/Web Hosting/Transit
    Country              VN

[VirusTotal]
    Malicious            1
    Harmless             0
    ASN / owner          AS150895 (EZ TECHNOLOGY COMPANY LIMITED)
    Country              VN

[RDAP / WHOIS]
    Network              HOAVPS-VN
    CIDR                 157.66.224.0/23
    Country              VN

[VERDICT]
    MALICIOUS
      - AbuseIPDB confidence 100% (high)
      - 12 AbuseIPDB reports
      - 1 VirusTotal vendor(s) flagged malicious
```
*(Values shown are illustrative; run it live with your keys for current data.)*

---

## Notes & limits

- **Free API tiers are rate-limited** (a few hundred lookups/day) — fine for
  analysis, not for bulk scanning.
- The tool **enriches** an IP; it never connects to, scans, or attacks the
  target. All data comes from third-party intel APIs.
- RDAP is queried through the public bootstrap at `rdap.org`.
