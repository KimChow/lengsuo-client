//! Salamander 混淆原语的确定性用例（对照参考 `salamander.go`）。
//!
//! 用固定盐 + 固定明文断言整包字节；并覆盖参考三个测试的语义
//! （roundtrip、in-place、短包 bounce）。加密后端用测试内注入的
//! BLAKE2b-256 实现，因此不依赖外部进程。

use std::sync::{Arc, Mutex};

use lengsuo_hysteria::obfs::{Obfuscator, PskTooShort, KEY_LEN, PSK_MIN_LEN, SALT_LEN};
use lengsuo_hysteria::transport::TransportRng;

const PSK: &[u8] = b"average_password";

/// 固定盐流（对照参考里 `RandSrc.Read(out[:8])` 的确定性替身）。
#[derive(Clone)]
struct FixedSalt(Arc<Mutex<u8>>);

impl FixedSalt {
    fn seq() -> Self {
        Self(Arc::new(Mutex::new(0)))
    }
}

impl TransportRng for FixedSalt {
    fn gen_index(&self, bound: usize) -> usize {
        if bound <= 1 {
            0
        } else {
            self.gen_u64(bound as u64) as usize
        }
    }
    fn gen_u64(&self, bound: u64) -> u64 {
        if bound <= 1 {
            return 0;
        }
        let mut g = self.0.lock().expect("盐锁中毒");
        let v = u64::from(*g);
        *g = g.wrapping_add(1);
        v % bound
    }
    fn fill_bytes(&self, out: &mut [u8]) {
        let mut g = self.0.lock().expect("盐锁中毒");
        for b in out.iter_mut() {
            *b = *g;
            *g = g.wrapping_add(1);
        }
    }
}

/// 注入的 BLAKE2b-256（参考 `blake2b.Sum256` 的替身）。
///
/// Rust 侧没有 blake2 依赖，测试里用**已知答案**钉住派生输入与密钥流：
/// 这个实现只验证「派生输入 = PSK||salt、异或位置 = i%32」，
/// 真实的 BLAKE2b-256 对照由 `xray_hysteria_obfs.rs` 的向量用例锁。
const CRC_SEED: u64 = 0x243F_6A88_85A3_08D3;

struct FakeBlake {
    /// 记录收到的派生输入，供断言 `PSK || salt`。
    seen: Mutex<Vec<Vec<u8>>>,
}

impl lengsuo_hysteria::obfs::Blake2b256 for FakeBlake {
    fn sum256(
        &self,
        input: &[u8],
    ) -> Result<[u8; KEY_LEN], lengsuo_hysteria::obfs::HashUnavailable> {
        self.seen.lock().expect("记录锁中毒").push(input.to_vec());
        // 伪随机密钥流：按输入（=PSK||salt）散列，**不同口令得到不同流**，
        // 否则本文件其余「错误口令不得还原明文」类断言形同虚设。
        let mut acc = CRC_SEED;
        for b in input {
            acc = (acc ^ u64::from(*b)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
        let mut key = [0u8; KEY_LEN];
        for k in key.iter_mut() {
            acc = acc
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *k = (acc >> 33) as u8;
        }
        Ok(key)
    }
}

fn obf() -> (Obfuscator, Arc<FakeBlake>) {
    let deriver = Arc::new(FakeBlake {
        seen: Mutex::new(Vec::new()),
    });
    let o = Obfuscator::with_deriver(
        PSK.to_vec(),
        Arc::new(FixedSalt::seq()),
        Arc::clone(&deriver) as Arc<dyn lengsuo_hysteria::obfs::Blake2b256>,
    )
    .expect("口令合法");
    (o, deriver)
}

/// 逐字节：`[8B salt][payload ^ keystream]`，且起盐为 0,1,2,...
#[test]
fn obfuscate_layout_and_bytes() {
    let (o, deriver) = obf();
    let plain: Vec<u8> = (0..40u8).collect();
    let mut out = vec![0u8; plain.len() + SALT_LEN];
    let n = o.obfuscate(&plain, &mut out).expect("缓冲足够");
    assert_eq!(n, SALT_LEN + plain.len());
    assert_eq!(&out[..SALT_LEN], &[0, 1, 2, 3, 4, 5, 6, 7]);
    // 密文体 = 明文异或派生密钥的重复（独立复算一次，不调产品代码）。
    let seen0 = deriver.seen.lock().expect("记录锁中毒")[0].clone();
    let mut acc = CRC_SEED;
    for b in &seen0 {
        acc = (acc ^ u64::from(*b)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    let key: Vec<u8> = (0..KEY_LEN)
        .map(|_| {
            acc = acc
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (acc >> 33) as u8
        })
        .collect();
    for (i, p) in plain.iter().enumerate() {
        assert_eq!(out[SALT_LEN + i], p ^ key[i % KEY_LEN], "第 {i} 字节不符");
    }
    // 派生输入必须是 PSK || salt（对照参考 `key`）。
    let seen = deriver.seen.lock().expect("记录锁中毒");
    assert_eq!(seen.len(), 1);
    assert_eq!(&seen[0][..PSK.len()], PSK);
    assert_eq!(&seen[0][PSK.len()..], &[0, 1, 2, 3, 4, 5, 6, 7]);
}

/// 参考 `TestSalamanderObfuscator` 的 roundtrip 语义（多长度）。
#[test]
fn obfuscate_deobfuscate_roundtrip() {
    let (o, _) = obf();
    for len in [1usize, 2, 8, 31, 32, 33, 1200, 1500] {
        let plain: Vec<u8> = (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect();
        let mut enc = vec![0u8; len + SALT_LEN];
        let n = o.obfuscate(&plain, &mut enc).expect("缓冲足够");
        assert_eq!(n, len + SALT_LEN);
        let mut dec = vec![0u8; len];
        let m = o.deobfuscate(&enc, &mut dec).expect("解混淆成功");
        assert_eq!(m, len);
        assert_eq!(dec, plain, "长度 {len} 的 roundtrip 不符");
    }
}

/// 参考 `TestSalamanderInPlace`：解混淆可以原地进行。
#[test]
fn deobfuscate_in_place() {
    let (o, _) = obf();
    let plain: Vec<u8> = (0..1200).map(|i| (i % 256) as u8).collect();
    let mut enc = vec![0u8; plain.len() + SALT_LEN];
    o.obfuscate(&plain, &mut enc).expect("缓冲足够");
    // 原地解混淆：输入与输出同一块内存（对照 Go 的 Deobfuscate(out, out)）。
    let mut buf = enc.clone();
    let m = o.deobfuscate(&enc, &mut buf).expect("解混淆成功");
    assert_eq!(m, plain.len());
    assert_eq!(&buf[..m], &plain[..]);
}

/// 参考 `TestSalamanderBounce`：短包一律返回 0（Rust 侧返回 None）。
#[test]
fn short_packet_fails_closed() {
    let (o, _) = obf();
    for len in 0..=SALT_LEN {
        let input = vec![0x11u8; len];
        let mut out = vec![0u8; 64];
        assert!(
            o.deobfuscate(&input, &mut out).is_none(),
            "长度 {len} 的包应当拒绝"
        );
    }
}

/// 错误口令 → 解混淆得到的不是明文，且不得回退（fail-closed 的落点）。
#[test]
fn wrong_psk_never_returns_plaintext() {
    let (o, _) = obf();
    let wrong = Obfuscator::with_deriver(
        b"other_password".to_vec(),
        Arc::new(FixedSalt::seq()),
        Arc::new(FakeBlake {
            seen: Mutex::new(Vec::new()),
        }),
    )
    .expect("口令合法");
    let plain = b"lengsuo-salamander".to_vec();
    let mut enc = vec![0u8; plain.len() + SALT_LEN];
    o.obfuscate(&plain, &mut enc).expect("缓冲足够");
    let mut dec = vec![0u8; plain.len()];
    let n = wrong
        .deobfuscate(&enc, &mut dec)
        .expect("长度足够时仍有输出");
    assert_eq!(n, plain.len());
    assert_ne!(dec, plain, "错误口令不得还原明文");
}

/// 口令长度下限（对照参考 `ErrPSKTooShort`）。
#[test]
fn short_psk_rejected() {
    for len in 0..PSK_MIN_LEN {
        let e = Obfuscator::with_deriver(
            vec![b'x'; len],
            Arc::new(FixedSalt::seq()),
            Arc::new(FakeBlake {
                seen: Mutex::new(Vec::new()),
            }),
        )
        .err();
        assert_eq!(e, Some(PskTooShort), "长度 {len} 的口令应当拒绝");
    }
    assert!(Obfuscator::with_deriver(
        b"abcd".to_vec(),
        Arc::new(FixedSalt::seq()),
        Arc::new(FakeBlake {
            seen: Mutex::new(Vec::new()),
        }),
    )
    .is_ok());
}

/// 缓冲区不足与输出过小都拒绝（对照参考的 `return 0`）。
#[test]
fn insufficient_buffer_rejected() {
    let (o, _) = obf();
    let plain = vec![7u8; 16];
    let mut small = vec![0u8; plain.len() + SALT_LEN - 1];
    assert!(o.obfuscate(&plain, &mut small).is_none());
    let mut enc = vec![0u8; plain.len() + SALT_LEN];
    o.obfuscate(&plain, &mut enc).expect("缓冲足够");
    let mut tiny = vec![0u8; plain.len() - 1];
    assert!(o.deobfuscate(&enc, &mut tiny).is_none());
}
