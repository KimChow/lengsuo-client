#!/usr/bin/env python3
"""生成 Salamander 混淆的确定性参考向量。

per-network 语义（对照 Go 参考）：
  - 盐由 crypto/rand（Go 侧）或 os.urandom（本脚本）抽取；
  - 密钥 = BLAKE2b-256(PSK || salt)，取 32 字节；
  - 密文 = 明文 XOR key[i % 32]，整体包为 salt || ciphertext。

本脚本产出的行可直接喂给
`crates/lengsuo-hysteria/tests/xray_hysteria_obfs.rs::obfs_reference_vector_bytes`。
不写入任何口令明文，只写测试用假口令。
"""
import hashlib
import json
import os
import sys

# 测试用假口令（与参考实现无关，仅用于对照）
PSK = b"lengsuo-obfs-psk"


def blake2b_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def obfuscate(salt: bytes, plain: bytes, psk: bytes = PSK) -> bytes:
    key = blake2b_256(psk + salt)
    body = bytes(c ^ key[i % len(key)] for i, c in enumerate(plain))
    return salt + body


def main(argv):
    out_path = argv[1] if len(argv) > 1 else "salamander_vectors.txt"
    lines = [
        "# psk=<hex> salt=<hex> plain=<hex> cipher=<hex>",
        "# 由 tools/reference/gen_salamander_vector.py 生成；"
        "口令为测试假口令。",
    ]
    sizes = [1, 8, 31, 32, 33, 1200, 1500]
    for n in sizes:
        salt = bytes((i * 7) % 251 for i in range(8))
        plain = bytes((i * 31 + 7) % 251 for i in range(n))
        cipher = obfuscate(salt, plain)
        lines.append(
            "psk=%s salt=%s plain=%s cipher=%s"
            % (PSK.hex(), salt.hex(), plain.hex(), cipher.hex())
        )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(sizes)} vectors to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
