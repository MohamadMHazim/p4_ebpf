#!/usr/bin/env python3
"""
send_packets.py — Send packets and predict flow_index from CRC16 hash.
Usage:
  sudo python3 send_packets.py --iface veth0 --mode udp --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --sport 5555 --dport 9999
  sudo python3 send_packets.py --iface veth0 --mode tcp --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --sport 12345 --dport 443 --flags S --count 5
"""
import argparse
import struct
from scapy.all import Ether, IP, TCP, UDP, sendp


# ── CRC-16/ARC: poly=0x8005, init=0x0000, refin=True, refout=True, xorout=0x0000
# This matches Tofino's HashAlgorithm_t.CRC16 / CRC_16.
def reflect_bits(val: int, width: int) -> int:
    result = 0
    for _ in range(width):
        result = (result << 1) | (val & 1)
        val >>= 1
    return result


def crc16_tofino(data: bytes) -> int:
    POLY = 0x8005
    crc = 0x0000          # init
    for b in data:
        b = reflect_bits(b, 8)          # refin
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ POLY) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    crc = reflect_bits(crc, 16)         # refout
    return crc ^ 0x0000                 # xorout


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface",     default="veth0")
    ap.add_argument("--mode",      choices=["udp", "tcp"], required=True)
    ap.add_argument("--src-ip",    default="10.0.0.1")
    ap.add_argument("--dst-ip",    default="10.0.0.2")
    ap.add_argument("--sport",     type=int, default=12345)
    ap.add_argument("--dport",     type=int, default=443)
    ap.add_argument("--count",     type=int, default=1)
    ap.add_argument("--interval",  type=float, default=0.0)
    ap.add_argument("--flags",     default="S", help="TCP flags (e.g. S, A, FA, R)")
    args = ap.parse_args()

    proto = 17 if args.mode == "udp" else 6
    idx   = compute_flow_index(args.src_ip, args.dst_ip, args.sport, args.dport, proto)

    print("=== Flow index prediction ===")
    print(f"  iface      : {args.iface}")
    print(f"  5-tuple    : {args.src_ip}:{args.sport} → {args.dst_ip}:{args.dport}  proto={proto}")
    print(f"  flow_index : {idx}  (0x{idx:04X})")
    print("=============================")

    if args.mode == "udp":
        pkt = Ether() / IP(src=args.src_ip, dst=args.dst_ip) / UDP(sport=args.sport, dport=args.dport)
    else:
        pkt = Ether() / IP(src=args.src_ip, dst=args.dst_ip) / TCP(sport=args.sport, dport=args.dport, flags=args.flags)

    sendp(pkt, iface=args.iface, count=args.count, inter=args.interval, verbose=False)
    print(f"Sent {args.count} packet(s).")


if __name__ == "__main__":
    main()

#sudo python3 send.py --iface veth0 --mode udp --sport 5555 --dport 9999 --count 1
#sudo python3 .py --mode tcp --sport 12346 --dport 443