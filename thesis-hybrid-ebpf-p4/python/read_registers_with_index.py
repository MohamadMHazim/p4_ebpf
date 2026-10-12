#!/usr/bin/env python3
import os
import re
import sys
import json
import socket
import tempfile
import subprocess
import argparse
from pathlib import Path

BFSHELL = "/home/ubuntu/open-p4studio/install/bin/bfshell"
BF_PORT = 9999
INDEX_FILE = "/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/indexes_unique.txt"
FLOW_BUCKETS = 65536


def port_open(host: str, port: int, timeout=1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--indexes", default="", help="comma-separated indexes, e.g. 1,2,3")
    ap.add_argument("--index-file", default=INDEX_FILE)
    ap.add_argument("--index-mode", choices=["cli", "file"], default="cli")
    ap.add_argument("--flow-buckets", type=int, default=FLOW_BUCKETS)
    ap.add_argument("--format", choices=["summary", "json"], default="summary")
    args = ap.parse_args()

    if not Path(BFSHELL).exists():
        print(f"[ERROR] bfshell not found at: {BFSHELL}", file=sys.stderr)
        sys.exit(1)

    if not port_open("127.0.0.1", BF_PORT):
        print(f"[ERROR] Connection refused on 127.0.0.1:{BF_PORT}", file=sys.stderr)
        print("Start bf_switchd first, then re-run.", file=sys.stderr)
        print(f"Check: sudo ss -lntp | grep :{BF_PORT}", file=sys.stderr)
        sys.exit(1)

    cli_indexes = []
    if args.indexes.strip():
        for x in args.indexes.split(","):
            x = x.strip()
            if x:
                cli_indexes.append(int(x))

    inner_template = r'''
import re
import json

INDEX_FILE = r"__INDEX_FILE__"
INDEX_MODE = r"__INDEX_MODE__"
FLOW_BUCKETS = __FLOW_BUCKETS__
CLI_INDEXES = [__CLI_INDEXES__]
OUT_FORMAT = r"__OUT_FORMAT__"

ING = bfrt.basic.pipe.Ingress


def dedup_keep_order(vals):
    out, seen = [], set()
    for x in vals:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


def load_indices_from_file(path):
    idxs = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"[,\s]+", line)
            for p in parts:
                if p:
                    idxs.append(int(p))
    return dedup_keep_order(idxs)


def get_f1(reg, idx):
    e = reg.get(idx, from_hw=True)
    s = str(e)

    m = re.search(r"\.f1\s*:\s*\[(\d+),", s)
    if m:
        return int(m.group(1))

    m = re.search(r":\s*0x([0-9a-fA-F]+)", s)
    if m:
        return int(m.group(1), 16)

    m = re.search(r":\s*(\d+)", s)
    if m:
        return int(m.group(1))

    raise RuntimeError("Couldn't parse value from entry:\n" + s)


def get_reg(name):
    try:
        return getattr(ING, name)
    except AttributeError:
        return None


REG_NAMES = [
    "reg_pkts", "reg_bytes",
    "reg_pkts_ab", "reg_pkts_ba", "reg_bytes_ab", "reg_bytes_ba",
    "reg_ref_src_port", "reg_ref_dst_port", "reg_dir_valid",
    "reg_min_len", "reg_max_len",
    "reg_first_ts", "reg_last_ts",
    "reg_iat_sum", "reg_iat_cnt", "reg_iat_min", "reg_iat_max", "reg_iat_last",
    "reg_syn", "reg_ack", "reg_fin", "reg_rst",
]

REGS = {}
for n in REG_NAMES:
    REGS[n] = get_reg(n)


def read_reg(name, idx, default=0):
    r = REGS.get(name)
    if r is None:
        return default
    try:
        return get_f1(r, idx)
    except Exception:
        return default


def print_table(rows, cols, title=None):
    data = []
    for r in rows:
        data.append([fmt(r.get(key)) for header, key, fmt, align in cols])

    headers = [h for h, _, _, _ in cols]
    widths = [len(h) for h in headers]
    for row in data:
        for j, cell in enumerate(row):
            widths[j] = max(widths[j], len(cell))

    def line(ch="-"):
        return "+" + "+".join(ch * (w + 2) for w in widths) + "+"

    def fmt_cell(text, w, align):
        return text.rjust(w) if align == "r" else text.ljust(w)

    if title:
        print("\\n" + title)

    print(line("-"))
    print("| " + " | ".join(headers[j].ljust(widths[j]) for j in range(len(headers))) + " |")
    print(line("="))

    for row in data:
        out = []
        for j, cell in enumerate(row):
            out.append(fmt_cell(cell, widths[j], cols[j][3]))
        print("| " + " | ".join(out) + " |")

    print(line("-"))


if INDEX_MODE == "cli":
    idxs = dedup_keep_order(CLI_INDEXES)
    source_title = "indices from CLI"
else:
    idxs = load_indices_from_file(INDEX_FILE)
    source_title = "indices from file"


rows = []
for i in idxs:
    pkts  = read_reg("reg_pkts", i, 0)
    byt   = read_reg("reg_bytes", i, 0)
    bpp   = (byt / pkts) if pkts else 0.0

    pkts_ab  = read_reg("reg_pkts_ab",  i, 0)
    pkts_ba  = read_reg("reg_pkts_ba",  i, 0)
    bytes_ab = read_reg("reg_bytes_ab", i, 0)
    bytes_ba = read_reg("reg_bytes_ba", i, 0)

    ref_src_port = read_reg("reg_ref_src_port", i, 0)
    ref_dst_port = read_reg("reg_ref_dst_port", i, 0)
    dir_valid    = read_reg("reg_dir_valid", i, 0)

    min_len = read_reg("reg_min_len", i, 0)
    max_len = read_reg("reg_max_len", i, 0)

    first_ts = read_reg("reg_first_ts", i, 0)
    last_ts  = read_reg("reg_last_ts",  i, 0)

    iat_sum  = read_reg("reg_iat_sum",  i, 0)
    iat_cnt  = read_reg("reg_iat_cnt",  i, 0)
    iat_min  = read_reg("reg_iat_min",  i, 0)
    iat_max  = read_reg("reg_iat_max",  i, 0)
    iat_last = read_reg("reg_iat_last", i, 0)
    iat_avg = (iat_sum / iat_cnt) if iat_cnt else 0.0

    syn = read_reg("reg_syn", i, 0)
    ack = read_reg("reg_ack", i, 0)
    fin = read_reg("reg_fin", i, 0)
    rst = read_reg("reg_rst", i, 0)

    rows.append({
        "idx": i,
        "pkts": pkts,
        "bytes": byt,
        "bpp": bpp,
        "pkts_ab": pkts_ab,
        "pkts_ba": pkts_ba,
        "bytes_ab": bytes_ab,
        "bytes_ba": bytes_ba,
        "ref_src_port": ref_src_port,
        "ref_dst_port": ref_dst_port,
        "dir_valid": dir_valid,
        "min_len": min_len,
        "max_len": max_len,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "iat_cnt": iat_cnt,
        "iat_sum": iat_sum,
        "iat_avg": iat_avg,
        "iat_min": iat_min,
        "iat_max": iat_max,
        "iat_last": iat_last,
        "syn": syn,
        "ack": ack,
        "fin": fin,
        "rst": rst,
    })

if OUT_FORMAT == "json":
    payload = {
        "source": source_title,
        "flow_count": len(rows),
        "rows": rows,
    }
    print(json.dumps(payload))
else:
    tot_pkts  = sum(r["pkts"] for r in rows)
    tot_bytes = sum(r["bytes"] for r in rows)
    avg_bpp   = (tot_bytes / tot_pkts) if tot_pkts else 0.0

    nonzero_ab = sum(1 for r in rows if r["pkts_ab"] > 0 or r["bytes_ab"] > 0)
    nonzero_ba = sum(1 for r in rows if r["pkts_ba"] > 0 or r["bytes_ba"] > 0)
    dir_valid_cnt = sum(1 for r in rows if r["dir_valid"] != 0)

    print(f"\\n=== OVERALL ({source_title}) ===")
    print(f"Flows: {len(rows)}")
    print(f"Total pkts: {tot_pkts}")
    print(f"Total bytes: {tot_bytes}")
    print(f"Avg B/packet: {avg_bpp:.2f}")
    print(f"Flows with any AB traffic: {nonzero_ab} / {len(rows)}")
    print(f"Flows with any BA traffic: {nonzero_ba} / {len(rows)}")
    print(f"Flows with direction reference initialized: {dir_valid_cnt} / {len(rows)}")

    tot_syn = sum(r["syn"] for r in rows)
    tot_ack = sum(r["ack"] for r in rows)
    tot_fin = sum(r["fin"] for r in rows)
    tot_rst = sum(r["rst"] for r in rows)

    tot_iat_cnt = sum(r["iat_cnt"] for r in rows)
    tot_iat_sum = sum(r["iat_sum"] for r in rows)
    overall_iat_avg = (tot_iat_sum / tot_iat_cnt) if tot_iat_cnt else 0.0

    print("\\n=== TCP flags totals ===")
    print(f"SYN: {tot_syn}")
    print(f"ACK: {tot_ack}")
    print(f"FIN: {tot_fin}")
    print(f"RST: {tot_rst}")

    print("\\n=== IAT totals ===")
    print(f"IAT cnt: {tot_iat_cnt}")
    print(f"IAT sum: {tot_iat_sum}")
    print(f"Overall IAT avg: {overall_iat_avg:.2f}")
'''

    cli_indexes_str = ",".join(str(x) for x in cli_indexes)

    inner_py = (
        inner_template
        .replace("__INDEX_FILE__", args.index_file)
        .replace("__INDEX_MODE__", args.index_mode)
        .replace("__FLOW_BUCKETS__", str(args.flow_buckets))
        .replace("__CLI_INDEXES__", cli_indexes_str)
        .replace("__OUT_FORMAT__", args.format)
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as f:
        f.write(inner_py)
        inner_path = f.name

    try:
        cmd = [BFSHELL, "-p", str(BF_PORT), "-b", inner_path]
        subprocess.run(cmd, check=True)
    finally:
        try:
            os.unlink(inner_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()