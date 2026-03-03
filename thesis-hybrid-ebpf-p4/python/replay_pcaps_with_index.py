#!/usr/bin/env python3
import argparse
import struct
import time
import socket
from scapy.all import rdpcap, sendp, Ether, IP, TCP, UDP

# ----- CRC16 (CRC-16/ARC) with reflection (matches your Tofino CRC16 style) -----
def reflect_bits(val: int, width: int) -> int:
    res = 0
    for _ in range(width):
        res = (res << 1) | (val & 1)
        val >>= 1
    return res

def crc16_tofino(data: bytes) -> int:
    POLY = 0x8005
    crc = 0x0000
    for b in data:
        b = reflect_bits(b, 8)
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ POLY) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return reflect_bits(crc, 16)

def ip_to_bytes(ip: str) -> bytes:
    # safer than split(".")
    return socket.inet_aton(ip)

def compute_flow_index_single_hash(src_ip: str, dst_ip: str, sport: int, dport: int, proto: int) -> int:
    """
    MATCHES YOUR NEW P4:
      idx = crc16({ srcIP, dstIP, sport, dport, proto })
    """
    blob = b"".join([
        ip_to_bytes(src_ip),
        ip_to_bytes(dst_ip),
        struct.pack("!H", sport),
        struct.pack("!H", dport),
        struct.pack("!B", proto),
    ])
    return crc16_tofino(blob)

def extract_5tuple(pkt):
    """Return (src_ip, dst_ip, sport, dport, proto) for IPv4 TCP/UDP, else None."""
    if IP not in pkt:
        return None
    ip = pkt[IP]

    if TCP in pkt:
        t = pkt[TCP]
        return (ip.src, ip.dst, int(t.sport), int(t.dport), 6)

    if UDP in pkt:
        u = pkt[UDP]
        return (ip.src, ip.dst, int(u.sport), int(u.dport), 17)

    return None

def ensure_ether(pkt):
    """If pcap packet doesn't have Ether header, wrap it."""
    if Ether in pkt:
        return pkt
    return Ether() / pkt

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="Path to .pcap/.pcapng")
    ap.add_argument("--iface", default="veth0")
    ap.add_argument("--limit", type=int, default=0, help="0 = all packets, else replay first N")
    ap.add_argument("--interval", type=float, default=0.0, help="seconds between packets")
    ap.add_argument("--index-file", default="indexes.txt", help="file to save per-packet indexes")
    ap.add_argument("--unique-only", action="store_true", help="save only unique indexes (order preserved)")
    args = ap.parse_args()

    pkts = rdpcap(args.pcap)
    total = len(pkts)
    n = total if args.limit == 0 else min(args.limit, total)

    print(f"Loaded {total} packets from {args.pcap}")
    print(f"Replaying {n} packets on {args.iface}\n")

    seen = set()
    indexes_out = []

    for i in range(n):
        pkt = ensure_ether(pkts[i])
        tup = extract_5tuple(pkt)

        # send the packet
        sendp(pkt, iface=args.iface, count=1, verbose=False)

        if tup is None:
            print(f"[{i+1}/{n}] Non IPv4 TCP/UDP -> sent (no index)")
            if not args.unique_only:
                indexes_out.append("NA")
            continue

        src, dst, sport, dport, proto = tup
        idx = compute_flow_index_single_hash(src, dst, sport, dport, proto)

        print(f"[{i+1}/{n}] {src}:{sport}->{dst}:{dport} proto={proto}  idx={idx}")

        if args.unique_only:
            if idx not in seen:
                seen.add(idx)
                indexes_out.append(str(idx))
        else:
            indexes_out.append(str(idx))

        if args.interval > 0:
            time.sleep(args.interval)

    with open(args.index_file, "w") as f:
        for x in indexes_out:
            f.write(f"{x}\n")

    if args.unique_only:
        print(f"\nDone. Saved {len(indexes_out)} unique indexes to {args.index_file}")
    else:
        print(f"\nDone. Saved {len(indexes_out)} per-packet indexes to {args.index_file}")

if __name__ == "__main__":
    main()

# sudo python3 replay_pcaps_with_index.py \
#   --pcap /home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/pcaps/test.pcap \
#   --iface veth0 --limit 150 \
#   --unique-only \
#   --index-file /home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/indexes_unique.txt