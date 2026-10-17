# 生成 SS 协议黄金测试向量（与 Xray v26.3.27 行为对齐）
# 输出: crates/ss-core/tests/fixtures/vectors.json
import hashlib, hmac, json, zlib, os, sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

def evp_bytes_to_key(password: bytes, key_len: int) -> bytes:
    d, prev = b"", b""
    while len(d) < key_len:
        prev = hashlib.md5(prev + password).digest()
        d += prev
    return d[:key_len]

def hkdf_sha1(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, secret, hashlib.sha1).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha1).digest()
        okm += t
        i += 1
    return okm[:length]

def inc_nonce(nonce: bytes) -> bytes:
    # Xray GenerateIncreasingNonce: 从字节 0 开始递增，进位向高位，先加后用
    c = bytearray(nonce)
    for i in range(len(c)):
        c[i] = (c[i] + 1) & 0xFF
        if c[i] != 0:
            break
    return bytes(c)

def nonce_gen(nonce_size: int):
    # Xray GenerateAEADNonceWithSize: 全 FF 起始，首次调用返回全 0
    n = b"\xff" * nonce_size
    while True:
        n = inc_nonce(n)
        yield n

def seal(key: bytes, nonce: bytes, pt: bytes, algo: str) -> bytes:
    if algo.startswith("aes"):
        return AESGCM(key).encrypt(nonce, pt, None)
    if algo == "chacha20-ietf-poly1305":
        return ChaCha20Poly1305(key).encrypt(nonce, pt, None)
    raise ValueError(algo)

def open_(key: bytes, nonce: bytes, ct: bytes, algo: str) -> bytes:
    if algo.startswith("aes"):
        return AESGCM(key).decrypt(nonce, ct, None)
    if algo == "chacha20-ietf-poly1305":
        return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    raise ValueError(algo)

TAG = 16

def build_tcp_stream(algo: str, password: str, iv: bytes, chunks: list, first_payload: bytes) -> dict:
    """模拟 Xray 客户端 WriteTCPRequest + AuthenticationWriter：
    线格式 chunk = [AEAD(BE16(payload_len)) 2+16B][AEAD(payload) payload+16B]
    nonce 序列: 全FF起始 LE 递增，size 与 payload 共用同一序列
    """
    key = evp_bytes_to_key(password.encode(), 16 if algo == "aes-128-gcm" else 32)
    subkey = hkdf_sha1(key, iv, b"ss-subkey", len(key))
    nonce_size = 12 if algo != "xchacha20-ietf-poly1305" else 24
    gen = nonce_gen(nonce_size)
    wire = iv
    first = True
    for pt in chunks:
        size_wire = seal(subkey, next(gen), (len(pt)).to_bytes(2, "big"), algo)
        payload_wire = seal(subkey, next(gen), pt, algo)
        wire += size_wire + payload_wire
        _ = first_payload if first else None
        first = False
    return {
        "algo": algo, "password": password,
        "key": key.hex(), "iv": iv.hex(), "subkey": subkey.hex(),
        "chunks_plain": [c.hex() for c in chunks],
        "wire_hex": wire.hex(),
    }

def build_udp_packet(algo: str, password: str, iv: bytes, addr_bytes: bytes, payload: bytes) -> dict:
    """Xray EncodeUDPPacket: packet = [iv][AEAD(addr+payload)]
    密钥同 TCP：createAuthenticator(key, iv) → HKDF subkey；nonce 首值 = 全 0（GenerateAEADNonceWithSize 先增后返回）"""
    key = evp_bytes_to_key(password.encode(), 16 if algo == "aes-128-gcm" else 32)
    subkey = hkdf_sha1(key, iv, b"ss-subkey", len(key))
    pt = addr_bytes + payload
    nonce = bytes(24 if algo == "xchacha20-ietf-poly1305" else 12)
    if algo.startswith("aes"):
        ct = AESGCM(subkey).encrypt(nonce, pt, None)
    elif algo == "chacha20-ietf-poly1305":
        ct = ChaCha20Poly1305(subkey).encrypt(nonce, pt, None)
    else:
        raise ValueError(algo)
    return {"algo": algo, "password": password, "iv": iv.hex(), "subkey": subkey.hex(),
            "addr": addr_bytes.hex(), "payload": payload.hex(),
            "packet_hex": (iv + ct).hex()}

v = {"evp": [], "subkey": [], "tcp": [], "udp": [], "behavior": []}

for pw in ["test", "secret-password-2026"]:
    for klen in [16, 32]:
        v["evp"].append({"password": pw, "key_len": klen,
                         "key": evp_bytes_to_key(pw.encode(), klen).hex()})

mk = evp_bytes_to_key(b"test", 16)
salt = bytes.fromhex("00112233445566778899aabbccddeeff")
v["subkey"].append({"master_key": mk.hex(), "salt": salt.hex(),
                    "subkey": hkdf_sha1(mk, salt, b"ss-subkey", 16).hex()})

# TCP: aes-128-gcm 两个 chunk（首个含 addr: 0x01 + 8.8.8.8 + port 443）
addr_v4 = bytes([0x01, 8, 8, 8, 8]) + (443).to_bytes(2, "big")
iv16 = bytes(range(16))
v["tcp"].append(build_tcp_stream("aes-128-gcm", "test", iv16,
                                 [addr_v4 + b"hello", b"world" * 20], addr_v4))
# TCP: aes-256-gcm（iv 32B）
addr_dom = bytes([0x03, 11]) + b"example.com" + (8080).to_bytes(2, "big")
iv32 = bytes((i * 7 + 3) & 0xFF for i in range(32))
v["tcp"].append(build_tcp_stream("aes-256-gcm", "secret-password-2026", iv32,
                                 [addr_dom, b"x" * 300], addr_dom))
# TCP: chacha20-ietf-poly1305
v["tcp"].append(build_tcp_stream("chacha20-ietf-poly1305", "test", iv32,
                                 [addr_v4 + b"A" * 100], addr_v4))

# UDP
v["udp"].append(build_udp_packet("aes-128-gcm", "test", iv16, addr_v4, b"udp-payload"))
v["udp"].append(build_udp_packet("aes-256-gcm", "secret-password-2026", iv32, addr_dom, b"Z" * 64))

# behavior seed: 服务端 crc64-ECMA（Go hash/crc64，反射 poly 0xC96C5795D7870F42）；客户端 crc32-IEEE
_CRC64_POLY = 0xC96C5795D7870F42
_tbl = []
for i in range(256):
    c = i
    for _ in range(8):
        c = (c >> 1) ^ (_CRC64_POLY if c & 1 else 0)
    _tbl.append(c)
def crc64_ecma(data: bytes) -> int:
    crc = 0xFFFFFFFFFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _tbl[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFFFFFFFFFF

for pwd in ["test", "pass2"]:
    for klen in [16, 32]:
        k = evp_bytes_to_key(pwd.encode(), klen)
        h = hmac.new(b"SSBSKDF", k, hashlib.sha256).digest()
        v["behavior"].append({"password": pwd, "key_len": klen,
                              "hmac_hex": h.hex(), "crc32": hex(zlib.crc32(h)),
                              "crc64_ecma": hex(crc64_ecma(h))})

out = os.path.join(os.path.dirname(__file__), "..", "crates", "ss-core", "tests", "fixtures")
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "vectors.json"), "w") as f:
    json.dump(v, f, indent=1)
print("vectors written:", {k: len(val) for k, val in v.items()})
