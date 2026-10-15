#!/usr/bin/env python3
"""独立生成测试假凭据的传统 SS UDP 向量；不是产品加密实现或参考互通证据。
需要测试环境安装 cryptography。HChaCha 自检来源为 IETF XChaCha-03 §2.2.1。
"""
import hashlib
import hmac
import json
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def rotate(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & 0xffffffff


def hchacha(key, nonce):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce))

    def quarter(a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] = rotate(state[d] ^ state[a], 16)
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] = rotate(state[b] ^ state[c], 12)
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] = rotate(state[d] ^ state[a], 8)
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] = rotate(state[b] ^ state[c], 7)

    for _ in range(10):
        for indices in [(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]:
            quarter(*indices)
    return struct.pack("<8I", *(state[:4] + state[12:]))


def master_key(size):
    output, previous = b"", b""
    while len(output) < size:
        previous = hashlib.md5(previous + b"passw0rd").digest()
        output += previous
    return output[:size]


def subkey(size, salt):
    prk = hmac.digest(salt, master_key(size), "sha1")
    output, previous, counter = b"", b"", 1
    while len(output) < size:
        previous = hmac.digest(prk, previous + b"ss-subkey" + bytes([counter]), "sha1")
        output += previous
        counter += 1
    return output[:size]


def vectors():
    assert hchacha(bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927")).hex() == (
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    targets = {
        "v4": bytes.fromhex("01c000020101bb"),
        "domain": b"\x03\x0fexample.invalid\x00\x35",
        "v6": b"\x04" + bytes.fromhex("20010db8000000000000000000000100") + bytes.fromhex("1f90"),
    }
    result = []
    for name in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"]:
        size = 16 if name == "aes-128-gcm" else 32
        salt = bytes(range(size))
        key = subkey(size, salt)
        for label, address in targets.items():
            plain = address + b"udp-payload-0123456789"
            if name.startswith("aes"):
                ciphertext = AESGCM(key).encrypt(bytes(12), plain, None)
            else:
                effective = hchacha(key, bytes(16)) if name.startswith("xchacha") else key
                ciphertext = ChaCha20Poly1305(effective).encrypt(bytes(12), plain, None)
            packet = salt + ciphertext
            result.append({"suite": name, "target": label, "length": len(packet), "hex": packet.hex()})
    return result


if __name__ == "__main__":
    print(json.dumps(vectors(), indent=2))
