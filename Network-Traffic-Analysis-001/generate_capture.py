#!/usr/bin/env python3
"""
generate_capture.py — build a synthetic pcap for the SSH brute-force case study.

This does NOT touch the network. It fabricates packet *metadata* (IPs, ports,
TCP flags, timestamps) and writes them to a .pcap file so the capture can be
analysed with tshark/Wireshark exactly like a real one. It lets this portfolio
demonstrate network-forensics skills in a sandbox with no live target and no
credential guessing.

Scenario modelled (from IP-Investigation-001):
    attacker 157.66.224.37  ->  victim 10.10.10.5  on tcp/22 (SSH)
    - a burst of short, failed login sessions (connect, a little data, reset)
    - then ONE longer session that keeps going (the "successful" login)

Run:  python3 generate_capture.py
Out:  ssh-bruteforce.pcap
"""

from scapy.all import IP, TCP, Raw, wrpcap
import random

ATTACKER = "157.66.224.37"
VICTIM = "10.10.10.5"
DPORT = 22
SEED = 1337

random.seed(SEED)
packets = []
t = 1_726_800_000.0  # base epoch (fixed, for reproducibility)


def session(sport, t0, data_bytes, success=False):
    """Append one TCP session's packets. Returns the next free timestamp."""
    pkts = []
    ts = t0
    base = IP(src=ATTACKER, dst=VICTIM)
    rbase = IP(src=VICTIM, dst=ATTACKER)

    # TCP 3-way handshake
    pkts.append((ts, base / TCP(sport=sport, dport=DPORT, flags="S", seq=1000)))
    ts += 0.04
    pkts.append((ts, rbase / TCP(sport=DPORT, dport=sport, flags="SA", seq=5000, ack=1001)))
    ts += 0.001
    pkts.append((ts, base / TCP(sport=sport, dport=DPORT, flags="A", seq=1001, ack=5001)))
    ts += 0.02

    # SSH banners (so the service is identifiable in Wireshark)
    pkts.append((ts, rbase / TCP(sport=DPORT, dport=sport, flags="PA", seq=5001, ack=1001)
                 / Raw(load=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")))
    ts += 0.03
    pkts.append((ts, base / TCP(sport=sport, dport=DPORT, flags="PA", seq=1001, ack=5042)
                 / Raw(load=b"SSH-2.0-OpenSSH_for_Windows_8.1\r\n")))
    ts += 0.05

    # encrypted key exchange + auth attempt (opaque payload stand-ins)
    seq_a, seq_v = 1034, 5042
    for _ in range(max(1, data_bytes // 48)):
        chunk = bytes(random.getrandbits(8) for _ in range(48))
        pkts.append((ts, base / TCP(sport=sport, dport=DPORT, flags="PA", seq=seq_a, ack=seq_v) / Raw(load=chunk)))
        seq_a += 48
        ts += 0.02
        chunk = bytes(random.getrandbits(8) for _ in range(48))
        pkts.append((ts, rbase / TCP(sport=DPORT, dport=sport, flags="PA", seq=seq_v, ack=seq_a) / Raw(load=chunk)))
        seq_v += 48
        ts += 0.02

    if success:
        # a successful login keeps the channel open: an interactive session
        # with many small back-and-forth packets over a longer time
        for _ in range(60):
            chunk = bytes(random.getrandbits(8) for _ in range(random.randint(16, 64)))
            who = base if random.random() < 0.5 else rbase
            sp, dp = (sport, DPORT) if who is base else (DPORT, sport)
            pkts.append((ts, who / TCP(sport=sp, dport=dp, flags="PA", seq=seq_a, ack=seq_v) / Raw(load=chunk)))
            ts += random.uniform(0.1, 0.9)
        # graceful close
        pkts.append((ts, base / TCP(sport=sport, dport=DPORT, flags="FA", seq=seq_a, ack=seq_v)))
        ts += 0.04
        pkts.append((ts, rbase / TCP(sport=DPORT, dport=sport, flags="FA", seq=seq_v, ack=seq_a + 1)))
    else:
        # a failed auth: server tears the connection down quickly with RST
        pkts.append((ts, rbase / TCP(sport=DPORT, dport=sport, flags="RA", seq=seq_v, ack=seq_a)))

    out = []
    for ts_i, p in pkts:
        p.time = ts_i
        out.append(p)
    return out, ts


# 1) ~40 rapid failed attempts from sequential ephemeral ports
sport = 40000
for i in range(40):
    pk, t = session(sport, t, data_bytes=96, success=False)
    packets += pk
    sport += 1
    t += random.uniform(0.2, 0.6)  # attacker hammers quickly

# 2) the one that "works": attempt #41 succeeds and stays connected
pk, t = session(sport, t, data_bytes=96, success=True)
packets += pk

packets.sort(key=lambda p: p.time)
wrpcap("ssh-bruteforce.pcap", packets)
print(f"wrote ssh-bruteforce.pcap with {len(packets)} packets")
