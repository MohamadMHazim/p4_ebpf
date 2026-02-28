#!/usr/bin/env python3
import argparse
import struct
import time
import subprocess
from scapy.all import rdpcap, sendp, Ether, IP, TCP, UDP

# ----- If you want "ground truth" from the switch (recommended) -----
BFSHELL = "/home/ubuntu/open-p4studio/install/bin/bfshell"

def read_switch_dbg_idx() -> int:
    cmd = """
bfrt.basic.pipe.Ingress.reg_dbg_idx.get(0, from_hw=True)
quit
"""
    p = subprocess.run([BFSHELL, "-b"],
                       input=cmd.encode(),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    out = p.stdout.decode(errors="ignore")
    for line in out.splitlines():
        if "Ingress.reg_dbg_idx.f1" in line and "[" in line:
            arr = line.split("[", 1)[1].split("]", 1)[0]
            return int(arr.split(",")[0].strip())
    raise RuntimeError("Could not parse reg_dbg_idx output.\n" + out)


# ----- Your CRC16 (CRC-16/ARC) -----
def reflect_bits(val: int, width: int) -> int:
    result = 0
    for _ in range(width):
        result = (result << 1) | (val & 1)
        val >>= 1
    return result

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
    crc = reflect_bits(crc, 16)
    return crc

def ip_to_bytes(ip: str) -> bytes:
    return bytes(map(int, ip.split(".")))

def compute_flow_index(src_ip: str, dst_ip: str, sport: int, dport: int, proto: int) -> int:
    blob = b"".join([
        ip_to_bytes(src_ip),
        ip_to_bytes(dst_ip),
        struct.pack("!H", sport),
        struct.pack("!H", dport),
        struct.pack("!B", proto),
    ])
    return crc16_tofino(blob)


def extract_5tuple(pkt):
    """
    Return (src_ip, dst_ip, sport, dport, proto) for IPv4 TCP/UDP, else None.
    """
    if IP not in pkt:
        return None
    ip = pkt[IP]
    if TCP in pkt:
        tcp = pkt[TCP]
        return (ip.src, ip.dst, int(tcp.sport), int(tcp.dport), 6)
    if UDP in pkt:
        udp = pkt[UDP]
        return (ip.src, ip.dst, int(udp.sport), int(udp.dport), 17)
    return None


def ensure_ether(pkt):
    # If pcap packet doesn't have Ether header, wrap it.
    if Ether in pkt:
        return pkt
    return Ether() / pkt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="Path to .pcap/.pcapng")
    ap.add_argument("--iface", default="veth0")
    ap.add_argument("--limit", type=int, default=0, help="0 = all packets, else replay first N")
    ap.add_argument("--interval", type=float, default=0.0, help="seconds between packets")
    ap.add_argument("--show-switch", action="store_true", help="also read reg_dbg_idx after each send")
    ap.add_argument("--index-file", default="indexes.txt", help="file to save predicted flow indexes")
    args = ap.parse_args()

    pkts = rdpcap(args.pcap)
    total = len(pkts)
    n = total if args.limit == 0 else min(args.limit, total)

    print(f"Loaded {total} packets from {args.pcap}")
    print(f"Replaying {n} packets on {args.iface}\n")

    # Track unique predicted indexes (insertion-ordered, deduped)
    seen_indexes = set()
    all_indexes = []

    for i in range(n):
        pkt = ensure_ether(pkts[i])
        tup = extract_5tuple(pkt)

        # send 1 packet
        sendp(pkt, iface=args.iface, count=1, verbose=False)

        if tup is None:
            print(f"[{i+1}/{n}] Non IPv4 TCP/UDP -> sent (no index)")
        else:
            src, dst, sport, dport, proto = tup
            pred_idx = compute_flow_index(src, dst, sport, dport, proto)
            if pred_idx not in seen_indexes:
                seen_indexes.add(pred_idx)
                all_indexes.append(pred_idx)

            if args.show_switch:
                time.sleep(0.01)
                sw_idx = read_switch_dbg_idx()
                print(f"[{i+1}/{n}] {src}:{sport}->{dst}:{dport} proto={proto}  pred={pred_idx}  switch={sw_idx}")
            else:
                print(f"[{i+1}/{n}] {src}:{sport}->{dst}:{dport} proto={proto}  pred={pred_idx}")

        if args.interval > 0:
            time.sleep(args.interval)

    # Save indexes to file — one per line, "None" for non-IP/TCP/UDP packets
    with open(args.index_file, "w") as f:
        for idx in all_indexes:
            f.write(f"{idx}\n")

    print(f"\nDone. Saved {len(all_indexes)} unique indexes to {args.index_file}")


if __name__ == "__main__":
    main()


#sudo python3 replay_pcaps_with_index.py --pcap /home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/pcaps/test.pcap --iface veth0 --limit 50