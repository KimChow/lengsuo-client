//! REALITY 端到端测试的公共夹具（`tests/reality_e2e.rs` 专用）。
//!
//! 本模块提供三类东西：
//!
//! 1. **确定性随机源**——握手需要可复现的 X25519 临时密钥、随机数与服务端
//!    随机数。用固定种子（SHA-256 计数器模式）保证每次跑出来的字节完全
//!    一致，从而让「期望值」可以硬编码在测试里。
//! 2. **回环 TCP 夹具**——在本机 `127.0.0.1` 上起一个监听端口，客户端与
//!    服务端在同一条 TCP 连接上跑完整的 REALITY + TLS 1.3 握手。
//! 3. **hex 工具**——把字节数组与十六进制字符串互转，用于比对硬编码向量。
//!
//! **硬约束**：只用回环地址、临时端口、假凭据；日志不得输出密钥/明文/口令。
//! 本模块不打印任何密钥材料。

pub mod e2e;
pub mod vectors;

use std::time::Duration;

use aes_gcm::aead::rand_core::{CryptoRng, Error as RngError, RngCore};
use lengsuo_vless::reality::hash::sha::sha256;
use lengsuo_vless::reality::x25519::{x25519, x25519_base};

/// 握手截止时间（卡片硬约束：所有网络操作必须有界）。
pub const DEADLINE: Duration = Duration::from_secs(10);

/// 测试用的假 SNI（回环场景下只是个字符串，不做真实 DNS 解析）。
pub const SERVER_NAME: &str = "www.example.com";

/// 十六进制解码（忽略大小写；非法字符返回 `None`）。
#[allow(dead_code)]
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// 十六进制编码（小写）。
#[allow(dead_code)]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 固定字节的「确定性熵源」。
///
/// 实现 `RngCore` + `CryptoRng`：`fill_bytes` 用 SHA-256 计数器模式从
/// `seed` 展开出任意长度的字节流。因此同一个种子永远得到同一串字节，
/// 握手过程完全可复现。
#[derive(Clone)]
pub struct SeededRng {
    seed: [u8; 32],
    counter: u64,
    buffer: Vec<u8>,
}

impl SeededRng {
    /// 用一个种子新建熵源。
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: Vec::new(),
        }
    }

    /// 用一个可读的标签造种子（便于在测试里区分不同用途的随机流）。
    pub fn from_label(label: &str) -> Self {
        Self::new(sha256(label.as_bytes()))
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        while self.buffer.len() < dest.len() {
            let mut input = [0u8; 40];
            input[..32].copy_from_slice(&self.seed);
            input[32..].copy_from_slice(&self.counter.to_be_bytes());
            self.buffer.extend_from_slice(&sha256(&input));
            self.counter = self.counter.wrapping_add(1);
        }
        let take = dest.len();
        dest.copy_from_slice(&self.buffer[..take]);
        self.buffer.drain(..take);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeededRng {}

/// 一套 REALITY 服务端的固定身份材料（全部是**假**测试值）。
#[derive(Clone)]
pub struct ServerIdentity {
    /// 服务端 REALITY 私钥（32 字节）。
    pub private_key: [u8; 32],
    /// 服务端 REALITY 公钥（32 字节）——客户端用它算 ECDH。
    pub public_key: [u8; 32],
    /// 准入短 ID（8 字节）。
    pub short_id: [u8; 8],
    /// 准入 SNI。
    pub server_name: String,
}

impl ServerIdentity {
    /// 由种子造一套服务端身份。
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            private_key: seed,
            public_key: x25519_base(&seed),
            short_id: *b"12345678",
            server_name: SERVER_NAME.to_owned(),
        }
    }

    /// 由服务端私钥与对端公钥派生 REALITY `auth_key`。
    pub fn auth_key(&self, client_public: &[u8; 32], client_random: &[u8; 32]) -> Option<[u8; 32]> {
        let shared = x25519(&self.private_key, client_public).ok()?;
        lengsuo_vless::reality::auth::derive_auth_key(&shared, client_random).ok()
    }
}

/// 客户端用的固定身份材料。
#[derive(Clone)]
pub struct ClientIdentity {
    /// 客户端 X25519 临时私钥种子。
    pub seed: [u8; 32],
    /// 客户端临时公钥。
    #[allow(dead_code)]
    pub ephemeral_public: [u8; 32],
    /// 客户端 `client_random`。
    #[allow(dead_code)]
    pub random: [u8; 32],
}

impl ClientIdentity {
    /// 由种子造一套客户端身份。
    pub fn new(seed: [u8; 32]) -> Self {
        let mut rng = SeededRng::new(seed);
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        Self {
            seed,
            ephemeral_public: x25519_base(&seed),
            random,
        }
    }
}
