# Network Discovery on a Shared Network — and Protecting My Own Devices

| Field | Value |
|-------|-------|
| **Case ID** | Network-Discovery-001 |
| **Analyst** | Beltus Bejanga |
| **Tool** | Advanced IP Scanner |
| **Scope** | The shared, landlord-provided residential network my own devices connect to |
| **Networks observed** | `192.168.0.0/24` (building LAN) plus my own local adapters (`172.20.10.x` iPhone hotspot, `172.20.16.x` Hyper-V, `192.168.56.x` VirtualBox) |
| **Live hosts found** | 22 |
| **Objective** | Understand what's on the network my devices sit on, and harden my own devices accordingly |

> **Scope, authorization & ethics note.** I rent in a building whose internet/Wi-Fi is **provided by the landlord**, so most of the hardware on `192.168.0.0/24` — the gateway, a Ubiquiti UniFi access point (`ap-creekview`), a Hikvision camera, and other tenants' devices — **is not mine.** I only ran **passive host discovery** on the network my own computer was already connected to; I did **not** log into, probe, access, or change any device I don't own, and I never attempted credentials on anything. Recognizing it as a network I don't administer, the correct response is **not** to "fix" other people's equipment — it's to treat the whole network as **untrusted** and harden *my own* devices. MAC addresses and device serials are **redacted** in the screenshot and this report.

---

## Why this matters

*You cannot defend what you do not know you have — or what you're sitting next to.* The first thing to understand on any network is what's on it. Running discovery here taught me something important about my own situation: **my personal computer and phone share a flat network with every other tenant and all the landlord's gear.** On a network you don't control, that realization is the finding — and it drives how you protect yourself.

---

## What the scan showed (`01-advanced-ip-scanner.png`)

Advanced IP Scanner resolved 22 live hosts by IP, hostname, and vendor (from the MAC OUI). My own adapters were easy to pick out: an iPhone personal hotspot (`172.20.10.x`), and two virtualization interfaces — Hyper-V/WSL (`172.20.16.x`, Microsoft OUI `00:15:5D`) and VirtualBox (`192.168.56.1`, OUI `0A:00:27`) — which tells me *my* host runs VMs.

Everything else lives on the building LAN (`192.168.0.0/24`):

| IP | Role (from hostname / vendor) | Vendor (OUI) | Whose? |
|----|-------------------------------|--------------|--------|
| 192.168.0.1 | Gateway / router (`XBR-4400`) | — | Building |
| 192.168.0.51 | IP camera | Hangzhou **Hikvision** | Building |
| 192.168.0.72 | Wi-Fi access point (`ap-creekview-00`) | **Ubiquiti** (UniFi) | Building |
| 192.168.0.81 | Smart camera | Wyze Labs | Other tenant |
| 192.168.0.136 | Network printer (`NPI019403`) | Hewlett Packard | Shared / other |
| 192.168.0.206 | Secondary router/AP (`RAX10`) | Netgear Nighthawk | Building / mine* |
| 192.168.0.180 / .181 | Smart camera (one device, two IPs) | Wyze Labs | Other tenant |
| 192.168.0.193 | Desktop (`DESKTOP-SFFKEAG`) | Tenda Wi-Fi adapter | **Mine** |
| 192.168.0.225 | Android phone | Shenzhen (ODM) | Other tenant |
| 192.168.0.226 | PlayStation | Sony Interactive | Other tenant |
| 192.168.0.232 | ASUS device | ASUSTek | Other tenant |
| 192.168.0.21, .150, .239 | Unidentified (two use randomized MACs) | — | Unknown |

\* Whether the Netgear `RAX10` is building equipment or my own is exactly the kind of thing to confirm — if it's mine, it's my route to isolation (below).

---

## The real analysis: I'm on an untrusted shared network

On a network I don't administer, I can't remediate other people's devices and it isn't my place to. What I **can** do is reason about my exposure and reduce it.

### Risk — a flat shared network 🔴
My desktop and phone share one broadcast domain with ~20 devices I don't control, including cameras and a printer. If **any** of them is compromised (IoT cameras are among the most-hijacked devices; the Hikvision model line, for example, has had critical unauthenticated-RCE issues such as **CVE-2021-36260**), the attacker is already on the same segment as my computer. I can't patch that camera — so I assume the network is hostile and protect myself.

### My response — harden my own devices
- **Treat the connection as "Public."** On Windows, set the network profile to **Public**, which disables file/printer sharing and network discovery so other tenants can't see into my PC. Confirm Windows Firewall is on.
- **Get behind my own router if allowed.** Putting my devices behind my *own* router (NAT) creates a private network that the building LAN can't reach into — the single best isolation step. (This is where confirming the `RAX10` matters.)
- **Strong, unique passwords + MFA**, and keep Windows / phone / browser fully updated — doubly important on a shared network.
- **A VPN** for privacy from others on the LAN (optional).
- **Don't touch what isn't mine**, and if something looks genuinely misconfigured (e.g., a camera exposed to the internet), the right move is to **report it to the building/landlord**, not to access it.

### What I did *not* do
I did not log into the gateway, the camera, the access point, or any other device; I did not attempt passwords; I did not change any setting on hardware I don't own. Discovery was limited to the network my own machine was already on.

---

## MITRE ATT&CK (defender's view)

Host discovery is the reconnaissance an attacker runs after gaining a foothold — observing it on the network I'm connected to shows what an attacker on this shared LAN would already see:

| Technique | ID |
|-----------|-----|
| Remote System Discovery | T1018 |
| Network Service Discovery | T1046 |
| System Network Configuration Discovery | T1016 |

---

## My Hardening Checklist (own devices only)

- [ ] Set my Windows network profile to **Public**; confirm firewall is on.
- [ ] Confirm whether the `RAX10` is mine; if so, put my devices behind it (NAT isolation).
- [ ] Strong, unique passwords + MFA on my accounts; full updates on my devices.
- [ ] Optional VPN for privacy on the shared LAN.
- [ ] Report any genuinely dangerous misconfig (e.g., an internet-exposed camera) to the landlord — do not touch it myself.
- [ ] Re-check my own exposure periodically.

---

## Skills Demonstrated

- Network discovery and host enumeration; reading device identity from hostnames and MAC OUIs
- **Correctly scoping authority** — recognizing a shared/landlord network, and limiting myself to passive discovery of my own connection rather than touching equipment I don't own
- Threat modeling my own exposure on an **untrusted network** and hardening accordingly
- Tying a vendor (Hikvision) to a known CVE as risk context — without acting on a device that isn't mine
- **Handling data and ethics responsibly** — redacting MACs/serials, and knowing the difference between *noticing* a risk and *authorized* remediation
