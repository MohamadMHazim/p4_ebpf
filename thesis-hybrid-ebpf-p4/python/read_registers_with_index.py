import re

INDEX_FILE = "/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/indexes_unique.txt"

def load_indices(path):
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
    # unique, keep order
    seen = set()
    out = []
    for x in idxs:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

idxs = load_indices(INDEX_FILE)

def get_f1(reg, idx):
    e = reg.get(idx, from_hw=True)
    s = str(e)

    # common format: ".f1 : [123, 0, 0, 0]"
    m = re.search(r"\.f1\s*: \[(\d+),", s)
    if m:
        return int(m.group(1))

    # fallback hex: ": 0x0000000a"
    m = re.search(r":\s*0x([0-9a-fA-F]+)", s)
    if m:
        return int(m.group(1), 16)

    raise RuntimeError("Couldn't parse value from entry:\n" + s)

def print_table(rows, cols, title=None):
    data = []
    for r in rows:
        data.append([fmt(r[key]) for header, key, fmt, align in cols])

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
        print("\n" + title)

    print(line("-"))
    print("| " + " | ".join(headers[j].ljust(widths[j]) for j in range(len(headers))) + " |")
    print(line("="))

    for row in data:
        out = []
        for j, cell in enumerate(row):
            out.append(fmt_cell(cell, widths[j], cols[j][3]))
        print("| " + " | ".join(out) + " |")

    print(line("-"))

# ---------------------------
# NEW: read added features from registers
# ---------------------------
rows = []
for i in idxs:
    pkts  = get_f1(bfrt.basic.pipe.Ingress.reg_pkts,  i)
    byt   = get_f1(bfrt.basic.pipe.Ingress.reg_bytes, i)

    # NEW added: packet length stats
    min_len = get_f1(bfrt.basic.pipe.Ingress.reg_min_len, i)
    max_len = get_f1(bfrt.basic.pipe.Ingress.reg_max_len, i)

    # NEW added: IAT stats (from your ingress)
    last_ts = get_f1(bfrt.basic.pipe.Ingress.reg_last_ts, i)
    iat_sum = get_f1(bfrt.basic.pipe.Ingress.reg_iat_sum, i)
    iat_cnt = get_f1(bfrt.basic.pipe.Ingress.reg_iat_cnt, i)
    iat_min = get_f1(bfrt.basic.pipe.Ingress.reg_iat_min, i)
    iat_max = get_f1(bfrt.basic.pipe.Ingress.reg_iat_max, i)

    # Existing TCP flags
    syn   = get_f1(bfrt.basic.pipe.Ingress.reg_syn,   i)
    ack   = get_f1(bfrt.basic.pipe.Ingress.reg_ack,   i)
    fin   = get_f1(bfrt.basic.pipe.Ingress.reg_fin,   i)
    rst   = get_f1(bfrt.basic.pipe.Ingress.reg_rst,   i)

    bpp = (byt / pkts) if pkts else 0.0

    len_range = (max_len - min_len) if (min_len != 0 and max_len >= min_len) else 0

    # IAT derived
    iat_avg = (iat_sum / iat_cnt) if iat_cnt else 0.0
    iat_rng = (iat_max - iat_min) if (iat_cnt and iat_max >= iat_min) else 0

    rows.append({
        "idx": i,
        "pkts": pkts,
        "bytes": byt,
        "bpp": bpp,

        "min_len": min_len,
        "max_len": max_len,
        "len_range": len_range,

        "iat_cnt": iat_cnt,
        "iat_sum": iat_sum,
        "iat_avg": iat_avg,
        "iat_min": iat_min,
        "iat_max": iat_max,
        "iat_rng": iat_rng,

        "last_ts": last_ts,

        "syn": syn, "ack": ack, "fin": fin, "rst": rst,
    })

# ---------------------------
# OVERALL
# ---------------------------
tot_pkts  = sum(r["pkts"] for r in rows)
tot_bytes = sum(r["bytes"] for r in rows)
avg_bpp   = (tot_bytes / tot_pkts) if tot_pkts else 0.0

tot_syn = sum(r["syn"] for r in rows)
tot_ack = sum(r["ack"] for r in rows)
tot_fin = sum(r["fin"] for r in rows)
tot_rst = sum(r["rst"] for r in rows)

tot_iat_cnt = sum(r["iat_cnt"] for r in rows)
tot_iat_sum = sum(r["iat_sum"] for r in rows)
overall_iat_avg = (tot_iat_sum / tot_iat_cnt) if tot_iat_cnt else 0.0

print("\n=== OVERALL ===")
print(f"Flows: {len(rows)}")
print(f"Total pkts: {tot_pkts}")
print(f"Total bytes: {tot_bytes}")
print(f"Avg B/packet: {avg_bpp:.2f}")

print("\n=== TCP flags totals ===")
print(f"SYN: {tot_syn}")
print(f"ACK: {tot_ack}")
print(f"FIN: {tot_fin}")
print(f"RST: {tot_rst}")

print("\n=== IAT totals ===")
print(f"IAT cnt: {tot_iat_cnt}")
print(f"IAT sum: {tot_iat_sum}")
print(f"Overall IAT avg: {overall_iat_avg:.2f}")

# ---------------------------
# Tables
# ---------------------------
cols_all = [
    ("idx",   "idx",   lambda v: str(v),       "r"),
    ("pkts",  "pkts",  lambda v: str(v),       "r"),
    ("bytes", "bytes", lambda v: str(v),       "r"),
    ("bpp",   "bpp",   lambda v: f"{v:.2f}",   "r"),

    ("minL",  "min_len",   lambda v: str(v),   "r"),
    ("maxL",  "max_len",   lambda v: str(v),   "r"),
    ("rngL",  "len_range", lambda v: str(v),   "r"),

    ("iatN",  "iat_cnt", lambda v: str(v),     "r"),
    ("iatAvg","iat_avg", lambda v: f"{v:.2f}", "r"),
    ("iatMin","iat_min", lambda v: str(v),     "r"),
    ("iatMax","iat_max", lambda v: str(v),     "r"),
    ("iatR",  "iat_rng", lambda v: str(v),     "r"),

    ("syn",   "syn",   lambda v: str(v),       "r"),
    ("ack",   "ack",   lambda v: str(v),       "r"),
    ("fin",   "fin",   lambda v: str(v),       "r"),
    ("rst",   "rst",   lambda v: str(v),       "r"),
]

print_table(rows[:20], cols_all, title="=== PER-INDEX (first 20) ===")

# --- OLD TOP 5s (kept) ---
top_pkts  = sorted(rows, key=lambda r: r["pkts"],  reverse=True)[:5]
top_bytes = sorted(rows, key=lambda r: r["bytes"], reverse=True)[:5]
top_rst   = sorted(rows, key=lambda r: r["rst"],   reverse=True)[:5]

print_table(top_pkts,  cols_all, title="=== TOP 5 by pkts ===")
print_table(top_bytes, cols_all, title="=== TOP 5 by bytes ===")
print_table(top_rst,   cols_all, title="=== TOP 5 by RST ===")

# --- NEW TOP 5s for added features ---
top_len_rng = sorted(rows, key=lambda r: r["len_range"], reverse=True)[:5]
top_iat_avg = sorted(rows, key=lambda r: r["iat_avg"], reverse=True)[:5]
top_iat_rng = sorted(rows, key=lambda r: r["iat_rng"], reverse=True)[:5]

print_table(top_len_rng, cols_all, title="=== TOP 5 by Length range ===")
print_table(top_iat_avg, cols_all, title="=== TOP 5 by IAT avg ===")
print_table(top_iat_rng, cols_all, title="=== TOP 5 by IAT range ===")