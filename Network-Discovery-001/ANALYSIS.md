# Network Discovery & Asset Inventory

| Field | Value |
|-------|-------|
| **Case ID** | Network-Discovery-001 |
| **Analyst** | Beltus Bejanga |
| **Tool** | Advanced IP Scanner |
| **Scope** | My own home network (authorised — I own every device here) |
| **Networks scanned** | `172.20.10.0/24`, `172.20.16.0/24`, `192.168.0.0/24`, `192.168.56.0/24` |
| **Live hosts found** | 22 |
| **Objective** | Build an asset inventory and assess the network's security posture |

> **Scope & privacy note:** this is a discovery scan of **my own network**, which is authorised. MAC addresses and device serial numbers have been **redacted** in the screenshot and this report — publishing a full hardware inventory of a live network would itself be an information-disclosure risk. Only vendor (OUI) and device role are kept.

---

## Why this matters

*You cannot defend what you do not know you have.* Asset discovery is the first control in almost every framework (CIS Control 1, NIST ID.AM). Before hunting threats, a SOC needs an accurate inventory — so that an **unexpected** device or an **unpatched** one stands out immediately. This scan is that first step on a real network.

---

## Scan result (`01-advanced-ip-scanner.png`)

Advanced IP Scanner swept four ranges and resolved 22 live hosts by IP, hostname, and vendor (from the MAC OUI).

### Networks identified

| Network | What it is | Evidence |
|---------|-----------|----------|
| `192.168.0.0/24` | **Main home LAN** — most devices live here | Gateway `XBR-4400` at `.1` |
| `172.20.10.0/24` | **iPhone Personal Hotspot** | `172.20.10.x` is Apple's fixed hotspot range |
| `172.20.16.0/24` | **Hyper-V / WSL virtual switch** | host `*.mshome.net`, Microsoft OUI `00:15:5D` (Hyper-V) |
| `192.168.56.0/24` | **VirtualBox host-only adapter** | `192.168.56.1`, VirtualBox OUI `0A:00:27` |

Finding two virtualization adapters (Hyper-V and VirtualBox) tells me this host runs VMs — useful context, and a reminder that virtual interfaces belong in the inventory too.

### Device inventory (main LAN)

| IP | Role (from hostname / vendor) | Vendor (OUI) |
|----|-------------------------------|--------------|
| 192.168.0.1 | Gateway / router (`XBR-4400`) | — |
| 192.168.0.51 | **IP camera / NVR** | Hangzhou **Hikvision** |
| 192.168.0.72 | **Wi-Fi access point** (`ap-creekview-00`) | **Ubiquiti** (UniFi) |
| 192.168.0.81 | **Smart camera** | Wyze Labs |
| 192.168.0.94 | Smart-home device | Belkin (Wemo) |
| 192.168.0.136 | **Network printer** (`NPI019403`) | Hewlett Packard |
| 192.168.0.146 | Laptop (`LAPTOP-0QBOU3AQ`) | — |
| 192.168.0.180 / .181 | **Smart camera** (one device, two IPs) | Wyze Labs |
| 192.168.0.193 | Desktop (`DESKTOP-SFFKEAG`) | Tenda (Wi-Fi adapter) |
| 192.168.0.206 | Secondary router/AP (`RAX10`) | Netgear Nighthawk |
| 192.168.0.225 | Android phone | Shenzhen (ODM) |
| 192.168.0.226 | **PlayStation** | Sony Interactive |
| 192.168.0.232 | ASUS device | ASUSTek |
| 192.168.0.21, .150, .239 | Unidentified (two use randomized MACs) | — / locally-administered |

---

## Security Observations

### 1. Flat network — IoT shares the same subnet as computers 🔴
Cameras (Hikvision, two Wyze), a printer, and a smart plug sit on the **same `/24`** as the laptop, desktop, and phone. If any IoT device is compromised, the attacker is already on the same broadcast domain as the personal computers.
**Recommendation:** put IoT/cameras on a separate **VLAN or guest SSID** with no route to the trusted LAN. This is the single highest-value change here.

### 2. Hikvision camera — a high-value target 🔴
Hikvision cameras have a history of serious, actively-exploited vulnerabilities (e.g. **CVE-2021-36260**, an unauthenticated command-injection rated CVSS 9.8).
**Recommendation:** confirm the firmware is current, change any default credentials, and make absolutely sure the camera (and its ports) are **not reachable from the internet** — check the router for any port-forwarding to `.51`.

### 3. Cloud IoT cameras (Wyze) 🟠
Wyze cameras are cloud-dependent and have had past data-exposure incidents.
**Recommendation:** keep firmware updated, use a strong unique account password + MFA, and segment them with the other IoT devices.

### 4. Two routers / APs on one LAN 🟠
Both a Netgear `RAX10` and a Ubiquiti UniFi AP appear alongside the `XBR-4400` gateway. Multiple APs are fine, but each is an admin surface.
**Recommendation:** confirm every router/AP admin panel has a strong, non-default password and current firmware; disable WAN-side admin.

### 5. Network printer 🟠
HP printers expose a web admin panel and are a classic pivot/exfil point.
**Recommendation:** set an admin password, disable unused protocols (e.g. raw/9100 from untrusted segments), keep firmware updated.

### 6. Unidentified devices — a hunting item 🟠
`.21`, `.150`, and `.239` resolved no hostname/vendor; `.21` and `.239` use **randomized (locally-administered) MACs**. MAC randomization is normal for modern phones, but an unknown device on your LAN is exactly what asset inventory exists to surface.
**Recommendation:** identify each (match to a known phone/device); label known ones so the *next* scan makes a genuinely unknown device obvious.

---

## MITRE ATT&CK (defender's view)

This is the reconnaissance an attacker performs after gaining a foothold — doing it to **my own** network lets me see what they would see:

| Technique | ID |
|-----------|-----|
| Remote System Discovery | T1018 |
| Network Service Discovery | T1046 |
| System Network Configuration Discovery | T1016 |

---

## Response / Hardening Checklist

- [ ] Create an **IoT VLAN / guest network**; move cameras, plug, printer onto it.
- [ ] Verify **Hikvision** firmware + credentials; confirm no internet exposure / port-forwards.
- [ ] Update **Wyze** firmware; enable account MFA.
- [ ] Change default admin passwords on **all three** routers/APs; disable remote admin.
- [ ] Secure the **HP printer** admin panel.
- [ ] Identify and label the **unknown hosts**; keep this inventory as a baseline.
- [ ] Re-scan periodically and **diff against this baseline** — new device = investigate.

---

## Skills Demonstrated

- Network discovery and host enumeration
- Building an asset inventory from an unstructured scan
- Reading device identity from hostnames and MAC OUIs
- Recognising network segmentation gaps and IoT risk
- Tying a vendor (Hikvision) to a specific, known CVE
- **Handling data responsibly** — redacting MACs/serials before publishing
