#!/usr/bin/env python3
import argparse
import struct
import time
import socket
import ipaddress
from scapy.all import rdpcap, sendp, Ether, IP, TCP, UDP


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


def ip_to_u32(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def u32_to_bytes(x: int) -> bytes:
    return struct.pack("!I", x & 0xFFFFFFFF)


def u16_to_bytes(x: int) -> bytes:
    return struct.pack("!H", x & 0xFFFF)


def compute_flow_index_symmetric(src_ip: str, dst_ip: str, sport: int, dport: int, proto: int) -> int:
    sip = ip_to_u32(src_ip)
    dip = ip_to_u32(dst_ip)

    ip_x = (sip ^ dip) & 0xFFFFFFFF
    ip_s = (sip + dip) & 0xFFFFFFFF

    sp = sport & 0xFFFF
    dp = dport & 0xFFFF
    p_x = (sp ^ dp) & 0xFFFF
    p_s = (sp + dp) & 0xFFFF

    blob = b"".join([
        u32_to_bytes(ip_x),
        u32_to_bytes(ip_s),
        u16_to_bytes(p_x),
        u16_to_bytes(p_s),
        struct.pack("!B", proto & 0xFF),
    ])
    return crc16_tofino(blob)


def extract_5tuple(pkt):
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
    return pkt if Ether in pkt else (Ether() / pkt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--int-iface", default="veth1")
    ap.add_argument("--ext-iface", default="veth3")
    ap.add_argument("--internal-cidr", default="172.16.11.0/24")
    ap.add_argument("--limit", type=int, default=0, help="0=all, else first N packets")
    ap.add_argument("--interval", type=float, default=0.0)
    ap.add_argument("--index-file", default="indexes_unique.txt")
    ap.add_argument("--unique-only", action="store_true")
    args = ap.parse_args()

    internal_net = ipaddress.ip_network(args.internal_cidr, strict=False)

    pkts = rdpcap(args.pcap)
    total = len(pkts)
    n = total if args.limit == 0 else min(args.limit, total)

    print(f"\nLoaded {total} packets from {args.pcap}")
    print(f"Replaying {n} packets with split injection:")
    print(f"  internal src in {internal_net} -> {args.int_iface}")
    print(f"  external src               -> {args.ext_iface}\n")

    seen = set()
    indexes_out = []

    for i in range(n):
        pkt = ensure_ether(pkts[i])
        tup = extract_5tuple(pkt)

        if tup is None:
            sendp(pkt, iface=args.int_iface, count=1, verbose=False)
            if not args.unique_only:
                indexes_out.append("NA")
            if args.interval > 0:
                time.sleep(args.interval)
            continue

        src, dst, sport, dport, proto = tup
        idx = compute_flow_index_symmetric(src, dst, sport, dport, proto)

        try:
            src_ip = ipaddress.ip_address(src)
            iface = args.int_iface if (src_ip in internal_net) else args.ext_iface
        except Exception:
            iface = args.int_iface

        sendp(pkt, iface=iface, count=1, verbose=False)
        print(f"[{i+1}/{n}] via {iface:11s} {src}:{sport}->{dst}:{dport} proto={proto} idx={idx}")

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

    print(f"\nDone. Saved {len(indexes_out)} {'unique ' if args.unique_only else ''}indexes to {args.index_file}")


if __name__ == "__main__":
    main()

# sudo python3 replay_pcaps_with_index.py \
#   --pcap /home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/pcaps/test.pcap \
#   --internal-cidr 172.16.11.0/24 \
#   --int-iface veth0 \
#   --ext-iface veth2 \
#   --limit 150 --unique-only \
#   --index-file /home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/indexes_unique.txt