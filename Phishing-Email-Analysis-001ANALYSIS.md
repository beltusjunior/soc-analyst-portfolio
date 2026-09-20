# Phishing Email Analysis Report

## Target URL: oluwaburnazip--renusharawat.replit.app

**Analysis Date:** September 19, 2026  
**Time Spent:** 30 minutes  
**Status:** Complete  
**Threat Level:** HIGH

---

## Step 1: PhishTank Verification

**Findings from PhishTank:**
- Submission ID: #9528356
- URL: https://oluwaburnazip--renusharawat.replit.app/
- Verification Status: Verified - Is a Phish (100%)
- Status: ONLINE (currently active)
- Submitted: September 20, 2026
- Verifiers: Dev darkmoon, Shazza, June

**My observations:**
- PhishTank has confirmed this is 100% phishing
- The site is currently ONLINE and actively deceiving users
- Multiple security experts verified the phishing
- Recent submission (September 2026) = newly deployed attack
- Still actively phishing users RIGHT NOW

---

## Step 2: VirusTotal Detection Analysis

**Findings from VirusTotal:**
- Detection Rate: 0/89 security vendors flagged
- Status: UNDETECTED by major antivirus engines
- Significance: This is a newly deployed phishing site

**My observations:**
- Zero detections from 89 security vendors
- This shows the phishing URL is BRAND NEW
- Attackers just deployed this, so antivirus databases haven't caught up
- Users are MORE likely to click it because it appears "safe"
- This makes it MORE dangerous, not less
- Traditional antivirus protection is INEFFECTIVE against this URL

---

## Step 3: URL Structure Analysis

**URL Breakdown:**
https://oluwaburnazip--renusharawat.replit.app/

**Suspicious Elements:**

1. **Subdomain: "oluwaburnazip--renusharawat"**
   - Very long and confusing
   - Random-looking characters
   - Double hyphen (--) is unusual
   - Designed to confuse users
   - Not a real company name

2. **Domain: replit.app**
   - Replit is a FREE coding platform
   - Attackers use free services to host phishing sites
   - Easy to deploy phishing pages
   - Can be created in minutes
   - Legitimate replit.app sites exist, making phishing more convincing

3. **HTTPS Encryption Present:**
   - URL uses HTTPS (has padlock)
   - But the content BEHIND it is phishing
   - HTTPS only encrypts the connection, not the legitimacy of the site
   - Users trust the padlock - this is deceptive

---

## Step 4: Phishing Indicators Identified

**Red Flags:**

1. ✓ Confusing subdomain - Designed to confuse users
2. ✓ Free hosting service - Replit is commonly abused for phishing
3. ✓ No legitimate branding - No company name, no logo reference
4. ✓ Generic URL path - Just "/" with no specific page
5. ✓ Recently deployed - Only days old, not yet detected
6. ✓ Currently active - PhishTank shows it's still online
7. ✓ Human verification - PhishTank experts confirmed it's phishing
8. ✓ Detection evasion - Zero antivirus detections shows new techniques

---

## FINAL ANALYSIS

### Is This a Phishing Site?

**VERDICT: ABSOLUTELY YES - ACTIVE PHISHING THREAT**

### Why?

**Critical Evidence:**
1. ✓ 100% verified by PhishTank (human experts confirmed)
2. ✓ Zero AV detections (newly deployed, currently evading detection)
3. ✓ Currently ONLINE (actively phishing users right now)
4. ✓ Free hosting service (typical attacker infrastructure)
5. ✓ Confusing URL (designed to trick users)
6. ✓ Uses HTTPS (fake security to gain trust)
7. ✓ Recently deployed (attack is fresh and active)

### Threat Level: CRITICAL

This phishing site is actively deceiving users and is undetected by traditional security tools.

---

## What Would I Do As SOC Analyst?

**Immediate Actions (Priority: CRITICAL):**

1. **BLOCK THE URL IMMEDIATELY**
   - Add to web filter/proxy blocklist
   - Block at firewall level
   - Set URL filter to prevent access

2. **ALERT USERS**
   - Send phishing alert email to all employees
   - Warn about this specific URL
   - Include indicators of phishing
   - Educate users NOT to click suspicious links

3. **CHECK EMAIL LOGS**
   - Search email system for this URL
   - Look for phishing emails containing this link
   - Identify which users received it
   - Check if anyone clicked it

4. **IDENTIFY AFFECTED USERS**
   - If users clicked the link, escalate to Incident Response
   - Assume accounts may be compromised
   - Force password reset if necessary
   - Monitor for suspicious activity

5. **REPORT TO THREAT INTEL**
   - Document the phishing attempt
   - Add to internal threat database
   - Share with security team
   - Monitor for similar attacks

6. **ESCALATE TO INCIDENT RESPONSE**
   - Report as active phishing campaign
   - Priority: HIGH/CRITICAL
   - Request immediate blocking action
   - Coordinate with email security team

---

## Skills I Demonstrated

✓ Phishing threat identification  
✓ Using PhishTank for verification  
✓ Using VirusTotal for threat detection  
✓ URL structure analysis  
✓ Security indicators recognition  
✓ Understanding detection evasion  
✓ Risk assessment and threat evaluation  
✓ Incident decision-making  
✓ Professional documentation and reporting  
✓ User awareness and education planning  

---

## Time Breakdown

- PhishTank research and analysis: 10 minutes
- VirusTotal URL analysis: 5 minutes
- URL structure analysis: 5 minutes
- Phishing indicators identification: 5 minutes
- Analysis and writing: 5 minutes
- Total: 30 minutes

---

## References & Tools

- PhishTank: https://www.phishtank.com
- VirusTotal: https://www.virustotal.com
- URLhaus: https://urlhaus.abuse.ch

---

## Key Learning: Detection Evasion

This investigation demonstrates an important SOC concept:

Zero antivirus detections does NOT mean safe

A phishing site with zero detections is MORE dangerous because:
- Users don't get antivirus warnings
- Traditional security tools can't detect it
- Attackers are using new evasion techniques
- Human verification (PhishTank) is critical
- SOC analysts must use MULTIPLE tools, not just AV

This is why SOC analysts are essential - we catch threats that automated tools miss.

---

## Conclusion

This phishing site should be:
1. Blocked immediately at the email and web gateway level
2. Users should be alerted about the threat
3. Any clicks should be investigated immediately
4. Affected accounts should be secured
5. The threat should be escalated to incident response

The combination of PhishTank verification plus zero AV detections equals an active, undetected threat that poses CRITICAL risk.
