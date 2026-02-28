import struct

# CRC16-CCITT (poly 0x1021, init 0xFFFF, no reflection)
def crc16_tofino(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def ip_to_bytes(ip: str) -> bytes:
    return bytes(map(int, ip.split(".")))


def compute_flow_index(src_ip, dst_ip, src_port, dst_port, proto):
    data = b"".join([
        ip_to_bytes(src_ip),          # 4 bytes
        ip_to_bytes(dst_ip),          # 4 bytes
        struct.pack("!H", src_port),  # 2 bytes big endian
        struct.pack("!H", dst_port),  # 2 bytes big endian
        struct.pack("!B", proto),     # 1 byte
    ])

    return crc16_tofino(data)


# ===== Example =====
src_ip  = "10.0.0.1"
dst_ip  = "10.0.0.2"
src_port = 5555
dst_port = 9999
proto    = 17  # UDP

idx = compute_flow_index(src_ip, dst_ip, src_port, dst_port, proto)

print("Computed flow_index:", idx)
