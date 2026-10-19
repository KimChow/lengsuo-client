//! Salamander 混淆（对照参考 `transport/internet/finalmask/salamander`）。
//!
//! 包格式：`[8 字节随机 salt][payload ^ keystream]`，其中 keystream 为
//! `BLAKE2b-256(PSK || salt)` 按 32 字节循环展开，与参考 `salamander.go`
//! 的 `Obfuscate`/`Deobfuscate` 逐字节一致。
//!
//! 随机源由调用方注入（`Obfuscator::with_rng`），参考使用
//! `math/rand` + 时间种子；Rust 侧默认用进程级 CSPRNG，
//! 确定性用例注入固定流。
//!
//! 解混淆 fail-closed：长度不足或口令不匹配时一律返回 `Err`，
//! 调用方必须丢弃该报文，绝不回退明文。

/// 参考 `smSaltLen`。
pub const SALT_LEN: usize = 8;
/// 参考 `smKeyLen`（`blake2b.Size256`）。
pub const KEY_LEN: usize = 32;
/// 参考 `smPSKMinLen`。
pub const PSK_MIN_LEN: usize = 4;

/// 口令过短（对照参考 `ErrPSKTooShort`）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("PSK 至少需要 {PSK_MIN_LEN} 字节")]
pub struct PskTooShort;

use std::sync::{Arc, Mutex};

use crate::transport::TransportRng;

/// 哈希不可用（口令长度已在构造时检查，理论上不可达）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("BLAKE2b-256 计算失败")]
pub struct HashUnavailable;

/// BLAKE2b-256 后端：`lengsuo-hysteria` 的依赖里没有 BLAKE2b 实现
/// （`blake2` crate 不在冻结的工作区依赖中，见 docs 偏离清单），
/// 因此参考的 `blake2b.Sum256(PSK || salt)` 由外部注入：
/// 生产路径由 [`DefaultKeyDeriver`] 走 `Command::new("b2sum")`
/// （coreutils 的 GNU BLAKE2b，输出 512 bit，取低 256 bit）；
/// 测试路径注入固定实现做逐字节对照。
pub trait Blake2b256: Send + Sync {
    fn sum256(&self, input: &[u8]) -> Result<[u8; KEY_LEN], HashUnavailable>;
}

/// 生产后端：`b2sum`（GNU coreutils）外部进程。
#[derive(Debug, Default)]
pub struct B2sumDeriver;

impl Blake2b256 for B2sumDeriver {
    fn sum256(&self, input: &[u8]) -> Result<[u8; KEY_LEN], HashUnavailable> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        // `b2sum` 无参读 stdin，拒绝读文件；避免把 PSK||salt 落到磁盘。
        let mut child = Command::new("b2sum")
            .arg("-l")
            .arg("256")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| HashUnavailable)?;
        let mut stdin = child.stdin.take().ok_or(HashUnavailable)?;
        stdin.write_all(input).map_err(|_| HashUnavailable)?;
        drop(stdin);
        let out = child.wait_with_output().map_err(|_| HashUnavailable)?;
        if !out.status.success() {
            return Err(HashUnavailable);
        }
        b2sum_hex_parse(&out.stdout).ok_or(HashUnavailable)
    }
}

/// 解析 b2sum 的 `<hex>  -` 输出，取前 64 个 hex 字符（低 256 bit）。
fn b2sum_hex_parse(stdout: &[u8]) -> Option<[u8; KEY_LEN]> {
    let line = std::str::from_utf8(stdout).ok()?;
    let hex = line.split_whitespace().next()?;
    if hex.len() < KEY_LEN * 2 {
        return None;
    }
    let mut key = [0u8; KEY_LEN];
    for (i, byte) in key.iter_mut().enumerate() {
        let hi = hex_digit(hex.as_bytes()[i * 2])?;
        let lo = hex_digit(hex.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(key)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// 密钥派生后端。
pub type KeyDeriver = Arc<dyn Blake2b256>;

/// Salamander 混淆器（对照参考 `SalamanderObfuscator`）。
pub struct Obfuscator {
    psk: Vec<u8>,
    rng: Arc<dyn TransportRng>,
    /// 参考用 `sync.Mutex` 串行化 `RandSrc.Read`；这里同样串行化取盐。
    salt_lock: Mutex<()>,
    deriver: KeyDeriver,
}

impl std::fmt::Debug for Obfuscator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 口令不进日志：只报长度与后端存在性。
        f.debug_struct("Obfuscator")
            .field("psk_len", &self.psk.len())
            .field("deriver", &"<injected>")
            .finish_non_exhaustive()
    }
}

impl Obfuscator {
    /// 缺省后端（`b2sum`）。
    pub fn new(psk: Vec<u8>, rng: Arc<dyn TransportRng>) -> Result<Self, PskTooShort> {
        Self::with_deriver(psk, rng, Arc::new(B2sumDeriver))
    }

    /// 注入哈希后端（测试用固定实现做逐字节对照）。
    pub fn with_deriver(
        psk: Vec<u8>,
        rng: Arc<dyn TransportRng>,
        deriver: KeyDeriver,
    ) -> Result<Self, PskTooShort> {
        if psk.len() < PSK_MIN_LEN {
            return Err(PskTooShort);
        }
        Ok(Self {
            psk,
            rng,
            salt_lock: Mutex::new(()),
            deriver,
        })
    }

    /// 口令长度（只回长度，不回口令）。
    #[must_use]
    pub fn psk_len(&self) -> usize {
        self.psk.len()
    }

    /// `blake2b.Sum256(PSK || salt)`，对照参考 `key`。
    fn key(&self, salt: &[u8]) -> Result<[u8; KEY_LEN], HashUnavailable> {
        let mut input = Vec::with_capacity(self.psk.len() + salt.len());
        input.extend_from_slice(&self.psk);
        input.extend_from_slice(salt);
        self.deriver.sum256(&input)
    }

    /// 混淆 `input` 到 `out`，返回写入长度（`len(input) + SALT_LEN`）。
    /// `out` 不足时返回 `None`（对照参考返回 0）。
    pub fn obfuscate(&self, input: &[u8], out: &mut [u8]) -> Option<usize> {
        let out_len = input.len() + SALT_LEN;
        if out.len() < out_len {
            return None;
        }
        {
            let _guard = self.salt_lock.lock().expect("盐锁中毒");
            self.rng.fill_bytes(&mut out[..SALT_LEN]);
        }
        let salt = [
            out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
        ];
        let key = self.key(&salt).ok()?;
        // 参考是 `out[i+salt] = in[i] ^ key[i%32]`：`input` 与 `out` 余下
        // 区域不重叠（`input` 是应用层明文），按切片复制后再异或。
        let body = &mut out[SALT_LEN..out_len];
        body.copy_from_slice(input);
        for (i, byte) in body.iter_mut().enumerate() {
            *byte ^= key[i % KEY_LEN];
        }
        Some(out_len)
    }

    /// 解混淆 `input`（含 salt 前缀）到 `out`，返回明文长度。
    /// 长度不足、`out` 过小或哈希不可用时返回 `None`（fail-closed）。
    pub fn deobfuscate(&self, input: &[u8], out: &mut [u8]) -> Option<usize> {
        if input.len() <= SALT_LEN {
            return None;
        }
        let out_len = input.len() - SALT_LEN;
        if out.len() < out_len {
            return None;
        }
        let key = self.key(&input[..SALT_LEN]).ok()?;
        let body = &mut out[..out_len];
        body.copy_from_slice(&input[SALT_LEN..]);
        for (i, byte) in body.iter_mut().enumerate() {
            *byte ^= key[i % KEY_LEN];
        }
        Some(out_len)
    }
}
