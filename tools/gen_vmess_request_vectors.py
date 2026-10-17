"""独立计算 VMess PortThenAddress 请求明文字节；仅测试假参数。"""
import json
import struct


def vector(port, kind, address):
    body = bytes([1]) + bytes([0x22]) * 16 + bytes([0x11]) * 16
    body += bytes([0x33, 5, 1, 0, 1])
    body += struct.pack(">HB", port, kind) + address
    checksum = 0x811c9dc5
    for byte in body:
        checksum = ((checksum ^ byte) * 0x01000193) & 0xffffffff
    return (body + struct.pack(">I", checksum)).hex()


if __name__ == "__main__":
    print(json.dumps({
        "ipv4": vector(443, 1, bytes([192, 0, 2, 1])),
        "ipv6": vector(8080, 3, bytes([0x20]) * 16),
        "domain": vector(8443, 2, bytes([15]) + b"example.invalid"),
    }, indent=2))
