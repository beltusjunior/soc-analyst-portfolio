#!/usr/bin/env python3
"""
ip_enrich.py — enrich an IP address with threat intelligence from multiple
sources and print a single, correlated verdict.

Sources:
  - AbuseIPDB   (abuse reports / confidence score)   needs ABUSEIPDB_API_KEY
  - VirusTotal  (vendor detections)                  needs VT_API_KEY
  - RDAP        (WHOIS-style ownership / network)     no key required

The point of this tool is the SOC workflow it automates: a single IP goes in,
and the three enrichment sources are correlated into one verdict — instead of
pasting the IP into three websites by hand. No single source decides the call;
stacking them does.

Usage:
    export ABUSEIPDB_API_KEY="your_key"      # free at abuseipdb.com
    export VT_API_KEY="your_key"             # free at virustotal.com
    python3 ip_enrich.py 157.66.224.37
    python3 ip_enrich.py 157.66.224.37 --json      # machine-readable output

Only the Python standard library is used — no pip install required.
Keys are read from environment variables and are never written to disk or output.
"""

import argparse
import ipaddress
import json
import os
import sys
import urllib.request
import urllib.error

TIMEOUT = 20


def http_get_json(url, headers=None):
    """GET a URL and return parsed JSON, or ('error', message)."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code} {e.reason}"}
    except Exception as e:  # noqa: BLE001 — surface any failure to the caller
        return {"_error": str(e)}


def query_abuseipdb(ip, key):
    if not key:
        return {"_skipped": "ABUSEIPDB_API_KEY not set"}
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    data = http_get_json(url, {"Key": key, "Accept": "application/json"})
    if "_error" in data:
        return data
    d = data.get("data", {})
    return {
        "abuse_confidence": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "distinct_reporters": d.get("numDistinctUsers"),
        "last_reported": d.get("lastReportedAt"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "domain": d.get("domain"),
    }


def query_virustotal(ip, key):
    if not key:
        return {"_skipped": "VT_API_KEY not set"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    data = http_get_json(url, {"x-apikey": key})
    if "_error" in data:
        return data
    attr = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
        "as_owner": attr.get("as_owner"),
        "asn": attr.get("asn"),
        "country": attr.get("country"),
        "reputation": attr.get("reputation"),
    }


def query_rdap(ip):
    """RDAP is the modern, machine-readable WHOIS. No API key needed."""
    data = http_get_json(f"https://rdap.org/ip/{ip}", {"Accept": "application/json"})
    if "_error" in data:
        return data
    org = None
    for ent in data.get("entities", []) or []:
        for item in ent.get("vcardArray", [[], []])[1] or []:
            if item and item[0] == "fn":
                org = item[3]
                break
        if org:
            break
    return {
        "network_name": data.get("name"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "org": org,
        "cidr": ", ".join(
            f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
            for c in (data.get("cidr0_cidrs") or [])
        ) or None,
    }


def verdict(abuse, vt):
    """Correlate the sources into one call. Conservative: any strong signal wins."""
    reasons = []
    score = 0

    ac = abuse.get("abuse_confidence") if isinstance(abuse, dict) else None
    reports = abuse.get("total_reports") if isinstance(abuse, dict) else None
    if isinstance(ac, int):
        if ac >= 50:
            score += 2; reasons.append(f"AbuseIPDB confidence {ac}% (high)")
        elif ac >= 10:
            score += 1; reasons.append(f"AbuseIPDB confidence {ac}%")
    if isinstance(reports, int) and reports >= 5:
        score += 1; reasons.append(f"{reports} AbuseIPDB reports")

    mal = vt.get("malicious") if isinstance(vt, dict) else None
    sus = vt.get("suspicious") if isinstance(vt, dict) else None
    if isinstance(mal, int) and mal >= 1:
        score += 2; reasons.append(f"{mal} VirusTotal vendor(s) flagged malicious")
    if isinstance(sus, int) and sus >= 1:
        score += 1; reasons.append(f"{sus} VirusTotal vendor(s) flagged suspicious")

    if score >= 3:
        label = "MALICIOUS"
    elif score >= 1:
        label = "SUSPICIOUS — investigate"
    else:
        label = "No strong indicators (not proof of safe)"
    return label, reasons


def line(k, v):
    return f"    {k:<20} {v}" if v not in (None, "") else None


def render(ip, abuse, vt, rdap):
    out = [f"\n=== IP Enrichment Report — {ip} ===\n"]

    out.append("[AbuseIPDB]")
    if "_skipped" in abuse:
        out.append(f"    (skipped — {abuse['_skipped']})")
    elif "_error" in abuse:
        out.append(f"    (error — {abuse['_error']})")
    else:
        for k, v in [
            ("Confidence", f"{abuse.get('abuse_confidence')}%"),
            ("Total reports", abuse.get("total_reports")),
            ("Distinct reporters", abuse.get("distinct_reporters")),
            ("Last reported", abuse.get("last_reported")),
            ("ISP", abuse.get("isp")),
            ("Usage type", abuse.get("usage_type")),
            ("Country", abuse.get("country")),
        ]:
            ln = line(k, v)
            if ln:
                out.append(ln)

    out.append("\n[VirusTotal]")
    if "_skipped" in vt:
        out.append(f"    (skipped — {vt['_skipped']})")
    elif "_error" in vt:
        out.append(f"    (error — {vt['_error']})")
    else:
        for k, v in [
            ("Malicious", vt.get("malicious")),
            ("Suspicious", vt.get("suspicious")),
            ("Harmless", vt.get("harmless")),
            ("Undetected", vt.get("undetected")),
            ("ASN / owner", f"AS{vt.get('asn')} ({vt.get('as_owner')})"),
            ("Country", vt.get("country")),
            ("Reputation", vt.get("reputation")),
        ]:
            ln = line(k, v)
            if ln:
                out.append(ln)

    out.append("\n[RDAP / WHOIS]")
    if "_error" in rdap:
        out.append(f"    (error — {rdap['_error']})")
    else:
        for k, v in [
            ("Network", rdap.get("network_name")),
            ("Org", rdap.get("org")),
            ("CIDR", rdap.get("cidr")),
            ("Country", rdap.get("country")),
        ]:
            ln = line(k, v)
            if ln:
                out.append(ln)

    label, reasons = verdict(abuse, vt)
    out.append("\n[VERDICT]")
    out.append(f"    {label}")
    for r in reasons:
        out.append(f"      - {r}")
    out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Enrich an IP with threat intelligence.")
    ap.add_argument("ip", help="IPv4 or IPv6 address to enrich")
    ap.add_argument("--json", action="store_true", help="output machine-readable JSON")
    args = ap.parse_args()

    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        sys.exit(f"error: '{args.ip}' is not a valid IP address")

    abuse = query_abuseipdb(args.ip, os.environ.get("ABUSEIPDB_API_KEY"))
    vt = query_virustotal(args.ip, os.environ.get("VT_API_KEY"))
    rdap = query_rdap(args.ip)
    label, reasons = verdict(abuse, vt)

    if args.json:
        print(json.dumps({
            "ip": args.ip, "abuseipdb": abuse, "virustotal": vt,
            "rdap": rdap, "verdict": label, "reasons": reasons,
        }, indent=2))
    else:
        print(render(args.ip, abuse, vt, rdap))


if __name__ == "__main__":
    main()
