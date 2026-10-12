#!/usr/bin/env python3
import argparse
import socket
import struct
from scapy.all import sniff

MAGIC = 0xBEEF


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
    p_x  = (sport ^ dport) & 0xFFFF
    p_s  = (sport + dport) & 0xFFFF

    blob = b"".join([
        u32_to_bytes(ip_x),
        u32_to_bytes(ip_s),
        u16_to_bytes(p_x),
        u16_to_bytes(p_s),
        struct.pack("!B", proto & 0xFF),
    ])
    return crc16_tofino(blob)


def parse_cpu_report(raw: bytes):
    if len(raw) < 16:
        return None

    magic, src_ip_raw, dst_ip_raw, sport, dport, proto, reason = struct.unpack("!HIIHHBB", raw[:16])
    if magic != MAGIC:
        return None

    src_ip = socket.inet_ntoa(struct.pack("!I", src_ip_raw))
    dst_ip = socket.inet_ntoa(struct.pack("!I", dst_ip_raw))
    idx = compute_flow_index_symmetric(src_ip, dst_ip, sport, dport, proto)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "sport": sport,
        "dport": dport,
        "proto": proto,
        "reason": reason,
        "idx": idx,
    }


def collect_indexes_on_iface(iface: str, timeout: float) -> list[int]:
    seen = []

    def handle(pkt):
        parsed = parse_cpu_report(bytes(pkt))
        if not parsed:
            return
        idx = parsed["idx"]
        if idx not in seen:
            seen.append(idx)
            print(
                f"[CPU-REPORT] {parsed['src_ip']}:{parsed['sport']} -> "
                f"{parsed['dst_ip']}:{parsed['dport']} proto={parsed['proto']} "
                f"reason={parsed['reason']} idx={idx}",
                flush=True,
            )

    sniff(iface=iface, prn=handle, store=False, timeout=timeout)
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="veth5")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    print(f"[INFO] Listening on {args.iface} for mirrored CPU reports...", flush=True)
    collect_indexes_on_iface(args.iface, args.timeout)


if __name__ == "__main__":
    main()