import re

# ---------------------------
# Read indices from a text file
# ---------------------------
INDEX_FILE = "/home/ubuntu/Desktop/p4_ebpf/thesis-hybrid-ebpf-p4/python/indexes.txt"

def load_indices(path):
    idxs = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # allow: "123", "123,456", "123 456", "123, 456 789"
            parts = re.split(r"[,\s]+", line)
            for p in parts:
                if p:
                    idxs.append(int(p))
    # remove duplicates but keep order
    seen = set()
    out = []
    for x in idxs:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

idxs = load_indices(INDEX_FILE)

# ---------------------------
# Robust register read (TableEntry has no to_dict in your BFRT)
# ---------------------------
def get_f1(reg, idx):
    e = reg.get(idx, from_hw=True)
    s = str(e)  # parse printable TableEntry
    m = re.search(r"\.f1\s*: \[(\d+),", s)
    if not m:
        raise RuntimeError("Couldn't parse value from entry:\n" + s)
    return int(m.group(1))

# ---------------------------
# Build per-index rows
# ---------------------------
rows = []
for i in idxs:
    pkts  = get_f1(bfrt.basic.pipe.Ingress.reg_pkts,  i)
    byt   = get_f1(bfrt.basic.pipe.Ingress.reg_bytes, i)
    syn   = get_f1(bfrt.basic.pipe.Ingress.reg_syn,   i)
    ack   = get_f1(bfrt.basic.pipe.Ingress.reg_ack,   i)
    fin   = get_f1(bfrt.basic.pipe.Ingress.reg_fin,   i)
    rst   = get_f1(bfrt.basic.pipe.Ingress.reg_rst,   i)

    bpp = (byt / pkts) if pkts else 0.0
    rows.append({
        "idx": i, "pkts": pkts, "bytes": byt,
        "syn": syn, "ack": ack, "fin": fin, "rst": rst,
        "bpp": bpp
    })

# ---------------------------
# OVERALL STATS
# ---------------------------
tot_pkts  = sum(r["pkts"] for r in rows)
tot_bytes = sum(r["bytes"] for r in rows)
avg_bpp   = (tot_bytes / tot_pkts) if tot_pkts else 0.0

tot_syn = sum(r["syn"] for r in rows)
tot_ack = sum(r["ack"] for r in rows)
tot_fin = sum(r["fin"] for r in rows)
tot_rst = sum(r["rst"] for r in rows)

def rate(x):
    return (x / tot_pkts) if tot_pkts else 0.0

print("\n=== OVERALL STATS (selected indices) ===")
print(f"Flows:        {len(rows)}")
print(f"Total pkts:   {tot_pkts}")
print(f"Total bytes:  {tot_bytes}")
print(f"Avg B/packet: {avg_bpp:.2f}")

print("\n--- TCP Flag rates (counts / total_pkts) ---")
print(f"SYN: {tot_syn}  rate={rate(tot_syn):.4f}")
print(f"ACK: {tot_ack}  rate={rate(tot_ack):.4f}")
print(f"FIN: {tot_fin}  rate={rate(tot_fin):.4f}")
print(f"RST: {tot_rst}  rate={rate(tot_rst):.4f}")

# ---------------------------
# Pretty ASCII table for TOP 5
# ---------------------------
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
            align = cols[j][3]
            out.append(fmt_cell(cell, widths[j], align))
        print("| " + " | ".join(out) + " |")

    print(line("-"))

cols = [
    ("idx",   "idx",   lambda v: str(v),     "r"),
    ("pkts",  "pkts",  lambda v: str(v),     "r"),
    ("bytes", "bytes", lambda v: str(v),     "r"),
    ("B/pp",  "bpp",   lambda v: f"{v:.2f}", "r"),
    ("syn",   "syn",   lambda v: str(v),     "r"),
    ("ack",   "ack",   lambda v: str(v),     "r"),
    ("fin",   "fin",   lambda v: str(v),     "r"),
    ("rst",   "rst",   lambda v: str(v),     "r"),
]

top_pkts  = sorted(rows, key=lambda r: r["pkts"],  reverse=True)[:5]
top_bytes = sorted(rows, key=lambda r: r["bytes"], reverse=True)[:5]
top_rst   = sorted(rows, key=lambda r: r["rst"],   reverse=True)[:5]

print_table(top_pkts,  cols, title="=== TOP 5 by packets (table) ===")
print_table(top_bytes, cols, title="=== TOP 5 by bytes (table) ===")
print_table(top_rst,   cols, title="=== TOP 5 by RST (table) ===")