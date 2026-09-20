# IP Investigation Report

## Target IP: 157.66.224.37

**Investigation Date:** September 19, 2026  
**Time Spent:** 45 minutes  
**Status:** Complete  

---

## Step 1: AbuseIPDB Analysis

**Findings from AbuseIPDB:**
- Total reports: 12 from 11 distinct sources
- Confidence score: High (multiple recent reports)
- Most common abuse type: Brute Force, Port Scanning, SSH Attacks
- Last reported: 5 minutes ago (actively attacking RIGHT NOW)
- First reported: September 11, 2026

**Warning:** Orange alert showing "Potentially still actively engaged in abusive activities"

**My observations:**
- This IP is ACTIVELY attacking systems RIGHT NOW
- Multiple different sources reporting the same IP
- The attacker is continuously trying brute force attacks
- Very recent activity shows ongoing threat

---

## Step 2: VirusTotal Detection

**Findings from VirusTotal:**
- Security vendor detections: 1/89 flagged as malicious
- CINS Army verdict: MALICIOUS (detected)
- Other vendors: Mostly clean (but CINS Army is a known threat intel source)
- ASN: AS150895 (EZ Technology Company Limited)
- Region: VN (Vietnam)
- Last analysis: 8 days ago

**My observations:**
- 1 out of 89 security vendors flagged this as malicious
- CINS Army is a trusted threat intelligence provider
- This confirms the malicious activity reported on AbuseIPDB
- Vietnam location matches WHOIS data

---

## Step 3: Shodan Service Enumeration

**Findings from Shodan:**
- Search result: No results found
- Meaning: No publicly exposed services detected on this IP

**My observations:**
- The attacker is NOT running exposed services on this IP
- This is typical for attackers - they hide their infrastructure
- The IP is likely used ONLY for attacking other systems
- This is a source of attacks, not a hosting server

---

## Step 4: Geolocation and Organization Data

**Findings from WHOIS:**
- IP Range: 157.66.224.0 - 157.66.225.255
- Country: VN (Vietnam)
- City: Quy Nhon City, Binh Dinh Province
- Organization: HOAVPS-VN / HOA FRUITS LLC
- Contact email: hoavps@hotmail.com
- Admin contact:
