//! 黄金向量逐字节断言（AGENTS §4：固定分块 + 固定 salt 后逐字节核对）。
//!
//! 权威边界（不得高估，lib.rs 同样已声明）：
//! - `evp` / `subkey` / `behavior` 三组锚定**公开规范**（OpenSSL EVP_BytesToKey MD5、
//!   RFC 5869 HKDF-SHA1、HMAC-SHA256 + 标准 CRC 反射语义），跨实现必然一致，可作正确性证据。
//! - `tcp.wire_hex` 由 tools/gen_vectors.py 依同一规范**独立复算**，用于锁定我方实现的
//!   分块顺序与 nonce 纪律；它不是 Xray 实跑抓包，**不能**证明互通。
//!   Rust↔Xray 双向验收仍须在构建机单独执行（AGENTS §4）。

use serde::Deserialize;

// 夹具兼容助手：金标 JSON 中部分整数为 "0x.." 十六进制字符串，数值/字符串两兼容。
mod hexnum {
    use serde::{Deserialize, Deserializer};
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V {
        S(String),
        U32(u32),
        U64(u64),
    }
    fn parse(s: &str) -> u64 {
        let t = s.trim();
        u64::from_str_radix(t.trim_start_matches("0x"), 16)
            .unwrap_or_else(|_| t.parse().expect("金标数值必须是十进制或 0x 十六进制"))
    }
    pub fn u32_hex<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
        match V::deserialize(d)? {
            V::U32(n) => Ok(n),
            V::U64(n) => u32::try_from(n).map_err(serde::de::Error::custom),
            V::S(s) => u32::try_from(parse(&s)).map_err(serde::de::Error::custom),
        }
    }
    pub fn u64_hex<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        match V::deserialize(d)? {
            V::U32(n) => Ok(n as u64),
            V::U64(n) => Ok(n),
            V::S(s) => Ok(parse(&s)),
        }
    }
}

use ss_core::chunk::{read_chunk, write_chunk, write_eof, MAX_CHUNK_PAYLOAD, SIZE_WIRE_LEN};
use ss_core::crypto::{CipherSuite, NonceCounter, SessionAead};
use ss_core::kdf::{behavior_seed_hmac, evp_bytes_to_key, hkdf_sha1_subkey};

const FIXTURE: &str = include_str!("fixtures/vectors.json");
const TAG: usize = 16;

#[derive(Deserialize)]
struct Vectors {
    evp: Vec<EvpCase>,
    subkey: Vec<SubkeyCase>,
    tcp: Vec<TcpCase>,
    udp: Vec<UdpCase>,
    behavior: Vec<BehaviorCase>,
}

#[derive(Deserialize)]
struct EvpCase {
    password: String,
    key_len: usize,
    key: String,
}

#[derive(Deserialize)]
struct SubkeyCase {
    master_key: String,
    salt: String,
    subkey: String,
}

#[derive(Deserialize)]
struct TcpCase {
    algo: String,
    password: String,
    key: String,
    iv: String,
    subkey: String,
    chunks_plain: Vec<String>,
    wire_hex: String,
}

#[derive(Deserialize)]
struct UdpCase {
    algo: String,
    password: String,
    iv: String,
    subkey: String,
    addr: String,
    payload: String,
}

#[derive(Deserialize)]
struct BehaviorCase {
    password: String,
    key_len: usize,
    hmac_hex: String,
    #[serde(deserialize_with = "hexnum::u32_hex")]
    crc32: u32,
    #[serde(deserialize_with = "hexnum::u64_hex")]
    crc64_ecma: u64,
}

fn vectors() -> Vectors {
    serde_json::from_str(FIXTURE).expect("vectors.json must parse")
}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("fixture hex broken: {e}"))
}

// ============ 规范锚定：跨实现必然一致 ============

/// 独立复现 Xray `GenerateIncreasingNonce` 作为 nonce 预言机。
/// 必要性：若只让被测代码自比，方向写反（BE vs LE）测不出来，
/// 而 nonce 方向是本协议最高危单点——错了会静默产生对端解不出的流。
fn oracle_nonce(len: usize, bumps: u64) -> Vec<u8> {
    let mut c = vec![0xFFu8; len];
    for _ in 0..bumps {
        for b in c.iter_mut() {
            let (v, ov) = b.overflowing_add(1);
            *b = v;
            if !ov {
                break;
            }
        }
    }
    c
}

#[test]
fn nonce_counter_matches_independent_oracle() {
    for len in [12usize, 24] {
        let mut n = NonceCounter::new(len);
        assert_eq!(
            n.next().expect("nonce"),
            vec![0u8; len],
            "FF 起始 + 先增后用 → 首值全 0"
        );
        for k in 1..=300u64 {
            assert_eq!(
                n.next().expect("nonce"),
                oracle_nonce(len, k),
                "nonce #{k} len={len}"
            );
        }
    }
    // 跨字节进位边界（byte0 走满一轮 → byte1 进位）
    let mut m = NonceCounter::new(12);
    for _ in 0..256 {
        let _ = m.next();
    }
    assert_eq!(&m.next().expect("nonce")[0..2], &[0u8, 1u8]);
}

#[test]
fn suite_names_and_lengths_match_xray_table() {
    let cases = [
        ("aes-128-gcm", 16, 16, 12usize),
        ("aes-256-gcm", 32, 32, 12),
        ("chacha20-ietf-poly1305", 32, 32, 12),
        ("xchacha20-ietf-poly1305", 32, 32, 24),
    ];
    for (name, key, salt, nonce) in cases {
        let s = CipherSuite::from_name(name).unwrap();
        assert_eq!(
            (s.key_len(), s.salt_len(), s.nonce_len()),
            (key, salt, nonce)
        );
    }
    assert!(
        CipherSuite::from_name("aes-128-ctr").is_none(),
        "非 AEAD 必须拒绝"
    );
    assert!(
        CipherSuite::from_name("none").is_none(),
        "NONE 不支持多用户，不接入"
    );
}

#[test]
fn evp_bytes_to_key_matches_spec_vectors() {
    for c in vectors().evp {
        let got = evp_bytes_to_key(c.password.as_bytes(), c.key_len);
        assert_eq!(got.len(), c.key_len);
        assert_eq!(hex::encode(&got), c.key, "evp pwd={}", c.password);
    }
}

#[test]
fn hkdf_sha1_subkey_matches_spec_vector() {
    for c in vectors().subkey {
        let got = hkdf_sha1_subkey(&hx(&c.master_key), &hx(&c.salt), c.subkey.len() / 2);
        assert_eq!(hex::encode(got), c.subkey);
    }
}

#[test]
fn behavior_hmac_and_crc_semantics_match_vectors() {
    for c in vectors().behavior {
        let master = evp_bytes_to_key(c.password.as_bytes(), c.key_len);
        let seed_in = behavior_seed_hmac(&master);
        assert_eq!(hex::encode(seed_in), c.hmac_hex, "pwd={}", c.password);
        // 交叉验证 CRC 参数（反射/init/xorout）——将来写 validator 时最易写错处。
        assert_eq!(
            crc32fast::hash(&seed_in),
            c.crc32,
            "crc32-IEEE pwd={}",
            c.password
        );
<<<<<<< HEAD
        // CRC-64/XZ（即 ECMA-182 反射形态）由 crate 内置参数承载，与手搓 Spec 完全一致
        // （poly 0x42F0_E1BA_E9ED_C6B9 / init&xorout 全 F / 反射 / check 0x62EC_59E3_A116_F9FA）。
        static ECMA: crc::Crc<u64> = crc::Crc::<u64>::new(&crc::CRC_64_XZ);
        assert_eq!(ECMA.checksum(&seed_in), c.crc64_ecma);
=======
        type Crc64Ecma = crc::Crc<u64, crc::TableSize<256>>;
        const ECMA: crc::SixtyFour = crc::Spec {
            poly: 0x42F0_E1BA_E9ED_C6B9,
            init: 0xFFFF_FFFF_FFFF_FFFF,
            refin: true,
            refout: true,
            xorout: 0xFFFF_FFFF_FFFF_FFFF,
            check: 0x62_EC_59E3_A116_F9FA,
            residue: 0x0000_0000_0000_0000,
        };
        assert_eq!(Crc64Ecma::new(&ECMA).checksum(&seed_in), c.crc64_ecma);
>>>>>>> agent/m-memory
    }
}

// ============ 内部一致性：锁定分块与 nonce 纪律，≠ Xray 互通 ============

#[tokio::test]
async fn tcp_wire_matches_fixture_byte_for_byte() {
    for c in vectors().tcp {
        let suite = CipherSuite::from_name(&c.algo).unwrap();
        let iv = hx(&c.iv);
        let subkey = hx(&c.subkey);
        let plains: Vec<Vec<u8>> = c.chunks_plain.iter().map(|h| hx(h)).collect();
        let wire = hx(&c.wire_hex);

        // ① 派生链逐字节复现：password →(EVP)→ key →(HKDF, salt=iv)→ subkey
        assert_eq!(iv.len(), suite.salt_len());
        let master = evp_bytes_to_key(c.password.as_bytes(), suite.key_len());
        assert_eq!(master, hx(&c.key), "master key for {}", c.algo);
        assert_eq!(
            hkdf_sha1_subkey(&master, &iv, suite.key_len()),
            subkey,
            "subkey derivation for {}",
            c.algo
        );

        // ② 客户端写侧：[iv][size_ct|payload_ct]… 必须与 fixture 完全一致
        let mut enc = SessionAead::new(suite, subkey.clone());
        let mut got: Vec<u8> = iv.clone();
        for p in &plains {
            assert!(p.len() <= MAX_CHUNK_PAYLOAD);
            let head = write_head(&mut enc, p.len() as u16);
            got.extend(head);
            got.extend(enc.seal(p).unwrap());
        }
        assert_eq!(got.len(), wire.len(), "wire length for {}", c.algo);
        assert_eq!(hex::encode(&got), c.wire_hex, "wire bytes for {}", c.algo);

        // ③ 服务端读侧：只喂 iv 之后的帧，逐 chunk 还原明文
        let mut dec = SessionAead::new(suite, subkey);
        let mut frames = &wire[iv.len()..];
        let mut back = Vec::new();
        while let Some(chunk) = read_chunk(&mut frames, &mut dec).await.unwrap() {
            assert!(!chunk.is_empty(), "零长 chunk 应判 EOF 而非 Some");
            back.push(chunk);
        }
        assert_eq!(back, plains, "decoded chunks for {}", c.algo);
        assert!(frames.is_empty(), "读完必须精确消费全部帧字节");
    }
}

fn write_head(enc: &mut SessionAead, plain_len: u16) -> Vec<u8> {
    let ct = enc.seal(&plain_len.to_be_bytes()).unwrap();
    assert_eq!(ct.len(), SIZE_WIRE_LEN);
    ct
}

#[tokio::test]
async fn tcp_io_traits_roundtrip_with_eof() {
    // 走真实 AsyncWrite/AsyncRead 路径（Vec<u8> 与 &[u8]），含 EOF 判据。
    for c in vectors().tcp {
        let suite = CipherSuite::from_name(&c.algo).unwrap();
        let subkey = hx(&c.subkey);
        let plains: Vec<Vec<u8>> = c.chunks_plain.iter().map(|h| hx(h)).collect();

        let mut enc = SessionAead::new(suite, subkey.clone());
        let mut buf: Vec<u8> = Vec::new();
        for p in &plains {
            write_chunk(&mut buf, &mut enc, p).await.unwrap();
        }
        let before_eof = buf.len();
        write_eof(&mut buf, &mut enc).await.unwrap();
        assert_eq!(buf.len(), before_eof + SIZE_WIRE_LEN, "EOF 段只含 size 块");

        let mut dec = SessionAead::new(suite, subkey);
        let mut r = &buf[..];
        let mut back = Vec::new();
        while let Some(chunk) = read_chunk(&mut r, &mut dec).await.unwrap() {
            back.push(chunk);
        }
        assert_eq!(back, plains);
    }
}

#[test]
fn fixture_wire_length_math_is_self_consistent() {
    // 帧长公式：Σ(18 + plain_len + 16) + iv_len == wire_len。
    // 独立于实现重算一遍，防止 fixture 自身生成时长度/分块错位。
    for c in vectors().tcp {
        let iv = c.iv.len() / 2;
        let sum: usize = c
            .chunks_plain
            .iter()
            .map(|h| SIZE_WIRE_LEN + h.len() / 2 + TAG)
            .sum();
        assert_eq!(c.wire_hex.len() / 2, iv + sum, "length math for {}", c.algo);
    }
}

#[test]
fn udp_fixture_derivation_chain_matches() {
    // UDP codec 尚未实现（lib.rs 已声明未完成），此处只锁派生链与包长语义：
    // [iv][addr][payload] 整包一次 AEAD → 密文长 = iv + addr + payload + 16。
    for u in vectors().udp {
        let suite = CipherSuite::from_name(&u.algo).unwrap();
        let iv = hx(&u.iv);
        assert_eq!(iv.len(), suite.salt_len());
        let master = evp_bytes_to_key(u.password.as_bytes(), suite.key_len());
        assert_eq!(
            hkdf_sha1_subkey(&master, &iv, suite.key_len()),
            hx(&u.subkey),
            "udp subkey for {}",
            u.algo
        );
        // addr 首字节是 ATYP，服务端解包后需 addr[0] &= 0x0F（掩码变体）
        let addr = hx(&u.addr);
        assert!(matches!(addr[0] & 0x0F, 0x01 | 0x03 | 0x04));
        let _ = hx(&u.payload);
    }
}

#[test]
fn tampered_stream_fails_closed_at_first_byte() {
    // 篡改任一帧字节都必须 AuthFailed，不得明文回退（AGENTS §3 fail-closed）。
    let c = &vectors().tcp[0];
    let suite = CipherSuite::from_name(&c.algo).unwrap();
    let wire = hx(&c.wire_hex);
    let iv_len = c.iv.len() / 2;
    for idx in [iv_len, iv_len + 1, iv_len + SIZE_WIRE_LEN, wire.len() - 1] {
        let mut broken = wire.clone();
        broken[idx] ^= 0x01;
        let mut dec = SessionAead::new(suite, hx(&c.subkey));
        let mut r = &broken[iv_len..];
        let res = tokio_test_block_on(read_chunk(&mut r, &mut dec));
        assert!(
            matches!(res, Err(ss_core::Error::AuthFailed)),
            "byte {idx} tamper must fail closed, got {res:?}"
        );
    }
}

/// 单线程 executor 包装，供非异步测试内调用 async 读函数。
fn tokio_test_block_on<F: std::future::Future<Output = R>, R>(fut: F) -> R {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}
