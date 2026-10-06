# Network Traffic Analysis — Live HTTPS / TLS 1.3 Capture

| Field | Value |
|-------|-------|
| **Case ID** | Network-Traffic-Analysis-002 |
| **Analyst** | Beltus Bejanga |
| **Tool** | Wireshark (live Wi-Fi capture) |
| **Traffic** | Real traffic from my own machine (authorised) |
| **Display filter** | `tcp` |
| **Verdict** | Benign — normal encrypted web/telemetry traffic |

> **Real capture.** Unlike `Network-Traffic-Analysis-001` (a synthetic lab file), this is **live traffic I captured on my own machine**. My own IPv6 address and MAC addresses are **redacted** in the screenshot — I kept the protocol detail, which is where the analysis lives.

---

## What I captured (`01-wireshark-tls.png`)

A short slice of normal outbound web activity over **IPv6**: my laptop opening TLS-encrypted connections to Microsoft and Google endpoints on port 443. Nothing malicious — the point of this case is to show I can **read a live capture, follow a TCP/TLS session, and reason about what is and isn't visible in encrypted traffic.**

---

## Walkthrough

### 1. The TCP 3-way handshake (packets 174–177)

```
174   50564 → 443   [SYN]        Seq=0  MSS=1380 WS=256 SACK_PERM
176   443 → 50566   [SYN, ACK]   Seq=0  Ack=1
177   50566 → 443   [ACK]        Seq=1  Ack=1
```

Classic **SYN → SYN,ACK → ACK**. The client proposes options (MSS 1380, window scaling, selective ACK); the server agrees. This is the TCP connection being established before any TLS happens. The detail pane confirms the first packet's `Flags: 0x002 (SYN)` and a 32-byte header with those options.

### 2. The TLS 1.3 handshake (packets 178–188)

```
178   TLSv1.3   Client Hello (SNI=ecs.office.com)
180   TLSv1.3   Server Hello, Change Cipher Spec
187   TLSv1.3   Change Cipher Spec, Application Data
```

The session is **TLS 1.3** — the current standard. `ecs.office.com` is a Microsoft Office / Microsoft 365 configuration-and-telemetry endpoint, so this is my Office client phoning home, which is expected.

### 3. The one thing an analyst must notice: **SNI is in cleartext** 🔎

Even though everything after the handshake is encrypted (`Application Data`), the **Server Name Indication (`SNI=ecs.office.com`) in the Client Hello is sent in the clear.**

This is the single most important lesson in this capture:
- I **cannot** see *what* was sent (the payload is encrypted).
- I **can** see *who* was contacted (`ecs.office.com`) — plus the IPs, ports, packet sizes, and timing.

For a SOC that matters a lot: **you don't need to break TLS to detect bad traffic.** The destination domain (SNI), the IP reputation, the beacon timing, and the data volume are often enough to spot C2 or exfiltration. (Note: TLS 1.3 *Encrypted Client Hello* (ECH) is starting to hide SNI too — a trend defenders are watching.)

### 4. A second connection (packets 197–201)

```
197   60234 → 443   [SYN]   MSS=1380 SACK_PERM WS=256
198   443 → 60234   [SYN, ACK]
201   60234 → 443   [ACK]   ... Len=1376
```

A fresh handshake to a different server (a Google `2607:f8b0::/32` address). Each destination gets its own TCP stream — Wireshark's **Stream index** field (visible in the detail pane) is how I'd isolate one conversation with `tcp.stream == N` or *Follow → TCP Stream*.

### 5. "TCP Out-Of-Order" / "Previous segment not captured" — not an incident

Packets 181–185 show `[TCP Previous segment not captured]` and `[TCP Out-Of-Order]`. On a **live Wi-Fi capture** this is normal: the sniffer occasionally misses a frame, or packets arrive reordered. It's a capture artefact, **not** evidence of an attack — an analyst needs to know the difference so they don't cry wolf.

---

## What this traffic is — and how I verified it's benign

| Observation | Reading |
|-------------|---------|
| TLS 1.3, port 443, to `ecs.office.com` | Microsoft 365 config/telemetry — expected |
| Second stream to a Google IPv6 range | Normal web/service traffic |
| Standard handshakes, no odd ports, no plaintext | Consistent with ordinary browsing/OS traffic |
| No beaconing pattern, no unknown-reputation IPs | No C2 indicators |

If I *wanted* to be suspicious, the hunt would be: unknown SNI/domain, rare destination IP (check reputation), fixed-interval beaconing, or large sustained uploads (exfil). None are present here.

---

## MITRE ATT&CK (what I'd look for in *malicious* TLS)

| Technique | ID |
|-----------|-----|
| Encrypted Channel: Asymmetric Cryptography | T1573.002 |
| Application Layer Protocol: Web Protocols | T1071.001 |
| Exfiltration Over C2 Channel | T1041 |

---

## Skills Demonstrated

- Capturing and filtering live traffic in Wireshark (`tcp` display filter)
- Reading a TCP 3-way handshake and TCP options from the packet detail
- Following a TLS 1.3 handshake (Client Hello → Server Hello → Application Data)
- Understanding **what encryption does and doesn't hide** (SNI, metadata)
- Distinguishing capture artefacts (out-of-order) from real anomalies
- IPv6 awareness
- Handling capture data responsibly (redacting own IP/MACs before publishing)
