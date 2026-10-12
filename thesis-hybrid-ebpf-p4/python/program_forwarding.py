#!/usr/bin/env python3
import argparse
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_BFSHELL = "/home/ubuntu/open-p4studio/install/bin/bfshell"
DEFAULT_BF_PORT = 9999

DEFAULT_INT_PORT = 0
DEFAULT_EXT_PORT = 1
DEFAULT_REPORT_PORT = 2
DEFAULT_MIRROR_SID = 1
DEFAULT_MIRROR_MAX_LEN = 64


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def build_bfrt_script(
    int_port: int,
    ext_port: int,
    report_port: int,
    mirror_sid: int,
    mirror_max_len: int,
) -> str:
    return f"""\
p4 = bfrt.basic.pipe.Ingress.forwarding
mirror_cfg = bfrt.mirror.cfg

# ---------------------------
# Forwarding
# ---------------------------
try:
    p4.clear()
    print("[INFO] Cleared forwarding table")
except Exception as e:
    print(f"[WARN] Could not clear forwarding table: {{e}}")

p4.add_with_send_using_port({int_port}, port={ext_port})
print("[INFO] Added forwarding entry: {int_port} -> {ext_port}")

p4.add_with_send_using_port({ext_port}, port={int_port})
print("[INFO] Added forwarding entry: {ext_port} -> {int_port}")

# ---------------------------
# Mirror session
# ---------------------------
try:
    mirror_cfg.delete(sid={mirror_sid})
    print("[INFO] Deleted existing mirror session sid={mirror_sid}")
except Exception:
    pass

mirror_cfg.add_with_normal(
    sid={mirror_sid},
    session_enable=True,
    direction="INGRESS",
    ucast_egress_port={report_port},
    ucast_egress_port_valid=True,
    max_pkt_len={mirror_max_len}
)
print("[INFO] Added mirror session sid={mirror_sid} -> port {report_port}")

try:
    bfrt.complete_operations()
except Exception:
    pass

print("[OK] Forwarding + mirroring programming finished")
"""
    # If your SDE rejects the keyword form above for mirror_cfg,
    # use the alternative "$field" version shown below instead:
    #
    # mirror_cfg.add_with_normal(**{{
    #     "$sid": {mirror_sid},
    #     "$session_enable": True,
    #     "$direction": "INGRESS",
    #     "$ucast_egress_port": {report_port},
    #     "$ucast_egress_port_valid": True,
    #     "$max_pkt_len": {mirror_max_len}
    # }})


def main() -> None:
    ap = argparse.ArgumentParser(description="Program BFRT forwarding table and mirror session")
    ap.add_argument("--bfshell", default=DEFAULT_BFSHELL)
    ap.add_argument("--bf-port", type=int, default=DEFAULT_BF_PORT)

    ap.add_argument("--int-port", type=int, default=DEFAULT_INT_PORT)
    ap.add_argument("--ext-port", type=int, default=DEFAULT_EXT_PORT)

    ap.add_argument("--report-port", type=int, default=DEFAULT_REPORT_PORT)
    ap.add_argument("--mirror-sid", type=int, default=DEFAULT_MIRROR_SID)
    ap.add_argument("--mirror-max-len", type=int, default=DEFAULT_MIRROR_MAX_LEN)

    args = ap.parse_args()

    if not Path(args.bfshell).exists():
        print(f"[ERROR] bfshell not found at: {args.bfshell}")
        sys.exit(1)

    if not port_open("127.0.0.1", args.bf_port):
        print(f"[ERROR] Connection refused on 127.0.0.1:{args.bf_port}")
        sys.exit(1)

    script = build_bfrt_script(
        int_port=args.int_port,
        ext_port=args.ext_port,
        report_port=args.report_port,
        mirror_sid=args.mirror_sid,
        mirror_max_len=args.mirror_max_len,
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as f:
        f.write(script)
        temp_script = f.name

    try:
        cmd = [args.bfshell, "-p", str(args.bf_port), "-b", temp_script]
        print("[INFO] Running:", " ".join(cmd))
        subprocess.run(cmd, check=True)
    finally:
        try:
            os.unlink(temp_script)
        except OSError:
            pass


if __name__ == "__main__":
    main()