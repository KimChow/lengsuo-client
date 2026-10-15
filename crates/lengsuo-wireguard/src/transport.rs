//! WireGuard **运输数据消息**（类型 4）的封装与解封。
//!
//! 线上格式依据 WireGuard 官方公开协议说明自主实现（未读取、未复制 GPL 源码）：
//!
//! ```text
//! 0..4   类型字段 u32 little endian = 4
//! 4..8   接收者标识 u32 little endian
//! 8..16  报文计数器 u64 little endian
//! 16..   AEAD 密文正文 || 16 字节认证标签（无 additional data）
//! ```
//!
//! nonce 为 `4 字节零前缀 || 计数器 LE64`（共 12 字节），与参考实现的 transport
//! 数据消息一致。**没有复用 `ss_core::crypto::SessionAead`**：它的
//! `NonceCounter` 把递增的小端整数放在 nonce 的**低字节前端**（`[ctr…ctr, 0,0,0,0]`），
//! 且每次取用自增、按调用顺序消耗，与这里“nonce 高 8 字节携带显式计数器、
//! 允许按任意计数器解封”的语义不兼容。本模块只写一层薄适配，直接调用
//! `chacha20poly1305`，密钥长度与标签长度仍复用 `ss_core::crypto` 的元数据，
//! 不复制 AEAD 实现、也不复制重放窗口。
//!
//! 范围与前提：
//! - 会话密钥由调用方提供（`TransportKey` newtype 包装，`Debug` 只输出长度）。
//!   **Noise IK 握手与密钥协商仍未实现**，因此本模块不构成可用的 WireGuard 连接，
//!   也不与任何真实 WireGuard 对端做过互通验证；只保证与本仓 `wire::parse` 自洽。
//! - 单包上限 `MAX_PACKET_LEN = 1420` 字节（对齐参考端默认 MTU），在写入与
//!   消耗计数器**之前**拒绝，不产生半包。零长载荷合法（keepalive 语义）。
//! - fail-closed：AEAD 认证/封装失败后上下文**永久 poison**，不再输出任何明文，
//!   也不得回退明文；重放窗口拒绝只丢包、不改变窗口状态。

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ss_core::crypto::{CipherSuite, TAG_LEN};

use crate::replay::{Error as ReplayError, Window};
use crate::wire::{parse, Message};

/// 运输报文固定头部：类型(4) + 接收者(4) + 计数器(8)。
const HEADER_LEN: usize = 16;
/// nonce 总长（chacha20poly1305 固定 12 字节）。
const NONCE_LEN: usize = 12;
/// nonce 中零前缀长度；其余 8 字节携带 LE64 计数器。
const NONCE_PREFIX_LEN: usize = NONCE_LEN - 8;
/// 运输消息类型。
const MESSAGE_TYPE_TRANSPORT: u32 = 4;
/// chacha20poly1305 密钥长度，复用 ss-core 套件元数据（=32）。
pub fn key_len() -> usize {
    CipherSuite::ChaCha20IetfPoly1305.key_len()
}
/// 单包总长上限（头部 + 密文 + 标签），对齐参考端默认 MTU 1420 字节。
pub const MAX_PACKET_LEN: usize = 1420;
/// 单次封装允许的最大载荷长度：`MAX_PACKET_LEN` 减去头部与标签。
pub const MAX_PAYLOAD_LEN: usize = MAX_PACKET_LEN - HEADER_LEN - TAG_LEN;
/// 接收侧计数器上限的默认值：u64 全量程，实际由密钥生命周期策略收紧。
pub const DEFAULT_MAX_COUNTER: u64 = u64::MAX;

/// 失败原因。全部 fail-closed：任何分支都不会输出明文，也不会回退到未认证路径。
/// 错误文本只含长度与计数器，不含密钥或载荷字节。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 会话密钥长度不对。
    #[error("运输密钥长度 {actual} 字节，要求 {expected} 字节")]
    KeyLength { actual: usize, expected: usize },
    /// 整包长度超过 `MAX_PACKET_LEN`；封装侧在写入前拒绝，解封侧直接丢包。
    #[error("整包长度 {actual} 字节超过上限 {limit} 字节：写入前拒绝，未消耗计数器")]
    TooLong { actual: usize, limit: usize },
    /// 计数器已到 `u64::MAX`：本包之后无法再推进，永久 poison，绝不回绕复用 0。
    #[error("计数器 {counter} 已用尽：不回绕复用，上下文永久 poison")]
    CounterExhausted { counter: u64 },
    /// 上下文已因认证/封装失败永久 poison。
    #[error("上下文已永久 poison：拒绝继续封装或解封")]
    Poisoned,
    /// 报文类型不是 4。
    #[error("非运输报文：{0}")]
    NotTransport(&'static str),
    /// 接收者标识与本端不符：丢包，不视为本端密钥失同步。
    #[error("接收者标识不匹配：期望 {expected:#010x}，实际 {actual:#010x}")]
    ReceiverMismatch { expected: u32, actual: u32 },
    /// AEAD 认证解密失败：密钥或 nonce 失同步，永久 poison。
    #[error("AEAD 认证失败：永久 poison，不回退明文")]
    AuthFailed,
    /// AEAD 封装失败（理论不可达）：永久 poison。
    #[error("AEAD 封装失败：永久 poison")]
    SealFailed,
    /// 重放窗口拒绝（重复、过旧、或超过注入上限）。
    #[error("重放窗口拒绝：{0}")]
    Replay(#[from] ReplayError),
    /// 头部结构检查失败，直接沿用 `wire::Error` 的语义。
    #[error("报文头部非法：{0}")]
    Wire(#[from] crate::wire::Error),
}

/// chacha20poly1305 会话密钥的 newtype 包装。
///
/// 字节私有不公开、不可通过 `AsRef`/`Deref` 取出；`Debug` 只输出长度，
/// 绝不输出密钥字节，避免密钥材料进入日志或 panic 信息。
#[derive(Clone)]
pub struct TransportKey {
    bytes: Vec<u8>,
}

impl TransportKey {
    /// 由调用方（未来的握手层）提供的 32 字节会话密钥。
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        let expected = key_len();
        if bytes.len() != expected {
            return Err(Error::KeyLength {
                actual: bytes.len(),
                expected,
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    fn cipher(&self) -> Result<ChaCha20Poly1305, Error> {
        ChaCha20Poly1305::new_from_slice(&self.bytes).map_err(|_| Error::KeyLength {
            actual: self.bytes.len(),
            expected: key_len(),
        })
    }
}

impl core::fmt::Debug for TransportKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TransportKey")
            .field("len", &self.bytes.len())
            // 故意不输出 bytes：密钥材料不得进入日志。
            .finish_non_exhaustive()
    }
}

/// 按显式计数器构造 nonce：4 字节零前缀 + 计数器 little endian 8 字节。
fn nonce(counter: u64) -> Nonce {
    let mut bytes = [0u8; NONCE_LEN];
    bytes[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_le_bytes());
    // 长度固定 12 字节，与 chacha20poly1305 的 nonce 尺寸一致。
    Nonce::clone_from_slice(&bytes)
}

/// 发送侧的失败状态：一旦离开 `Active` 就永久保持（fail-closed），不退回可用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SenderState {
    /// 正常可用。
    Active,
    /// AEAD 封装失败。
    Failed,
    /// 计数器已到 `u64::MAX`，无法再推进；保留读数以便 fail-closed 报错。
    Exhausted { counter: u64 },
}

/// 发送侧封装上下文：持有会话密钥、目的接收者标识与下一个待用计数器。
///
/// 计数器只在封装成功后推进；失败路径既不消耗计数器，也不产出半包。
/// 一旦进入失败态（封装失败或计数器用尽）即永久拒绝。
#[derive(Clone)]
pub struct Sender {
    key: TransportKey,
    receiver: u32,
    counter: u64,
    state: SenderState,
}

impl Sender {
    /// `initial_counter` 是本 key epoch 的首个待用计数器（通常为 0）。
    #[must_use]
    pub fn new(key: TransportKey, receiver: u32, initial_counter: u64) -> Self {
        Sender {
            key,
            receiver,
            counter: initial_counter,
            state: SenderState::Active,
        }
    }

    /// 报文里写入的接收者标识。
    #[must_use]
    pub fn receiver(&self) -> u32 {
        self.receiver
    }

    /// 下一个将被写入报文的计数器读数。
    #[must_use]
    pub fn next_counter(&self) -> u64 {
        self.counter
    }

    /// 是否已进入不可恢复的失败态。
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.state != SenderState::Active
    }

    /// 封装一条运输报文；`payload` 为空切片时即 keepalive 语义（合法零长载荷）。
    ///
    /// 返回完整报文（含 16 字节头部），可直接交给本仓 `wire::parse`。
    /// 载荷长度超限、失败态、计数器用尽都在写入前返回错误。
    pub fn seal(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        match self.state {
            SenderState::Active => {}
            SenderState::Failed => return Err(Error::Poisoned),
            SenderState::Exhausted { counter } => return Err(Error::CounterExhausted { counter }),
        }
        let actual = HEADER_LEN + TAG_LEN + payload.len();
        if payload.len() > MAX_PAYLOAD_LEN {
            // 在分配/写入与计数器推进之前拒绝：不产生半包，不消耗计数器。
            return Err(Error::TooLong {
                actual,
                limit: MAX_PACKET_LEN,
            });
        }
        let counter = self.counter;
        let cipher = self.key.cipher()?;
        let encrypted = cipher.encrypt(&nonce(counter), payload).map_err(|_| {
            self.state = SenderState::Failed;
            Error::SealFailed
        })?;
        let mut packet = Vec::with_capacity(actual);
        packet.extend_from_slice(&MESSAGE_TYPE_TRANSPORT.to_le_bytes());
        packet.extend_from_slice(&self.receiver.to_le_bytes());
        packet.extend_from_slice(&counter.to_le_bytes());
        packet.extend_from_slice(&encrypted);
        // 到这里报文已完整成形，才推进计数器；无法推进（回绕）则进入失败态，
        // 绝不回绕复用计数器 0——本包仍是合法的最高计数器报文。
        match counter.checked_add(1) {
            Some(next) => self.counter = next,
            None => self.state = SenderState::Exhausted { counter },
        }
        Ok(packet)
    }

    /// 零长载荷封装：等价于 `seal(&[])`，用于 keepalive。
    pub fn keepalive(&mut self) -> Result<Vec<u8>, Error> {
        self.seal(&[])
    }

    /// 主动进入失败态（密钥轮换策略尚未实现，这里只提供显式的 fail-closed 入口）。
    pub fn poison(&mut self) {
        if self.state == SenderState::Active {
            self.state = SenderState::Failed;
        }
    }
}

impl core::fmt::Debug for Sender {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Sender")
            .field("receiver", &self.receiver)
            .field("counter", &self.counter)
            .field("poisoned", &self.is_poisoned())
            .field("key", &"[redacted]")
            // 故意不输出 key：密钥材料不得进入日志。
            .finish_non_exhaustive()
    }
}

/// 解封结果：明文载荷与对应的计数器。
///
/// `Debug` 不输出明文（内层 IP 报文内容），只输出长度与计数器。
#[derive(Clone, PartialEq, Eq)]
pub struct Decrypted {
    /// 报文头部的计数器（已通过重放窗口）。
    pub counter: u64,
    /// 报文头部的接收者标识。
    pub receiver: u32,
    /// 认证解密后的明文载荷；零长载荷表示对端 keepalive。
    pub plaintext: Vec<u8>,
}

impl core::fmt::Debug for Decrypted {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Decrypted")
            .field("counter", &self.counter)
            .field("receiver", &self.receiver)
            .field("plaintext_len", &self.plaintext.len())
            // 故意不输出 plaintext。
            .finish_non_exhaustive()
    }
}

/// 接收侧解封上下文：会话密钥 + 本端期望的接收者标识 + 共享重放窗口。
///
/// 每个 peer / key epoch 必须独占一个实例（内部 `Window` 由 `Window::new` 新建），
/// 禁止跨 epoch 复用。
#[derive(Clone)]
pub struct Receiver {
    key: TransportKey,
    expected_receiver: u32,
    window: Window,
    poisoned: bool,
}

impl Receiver {
    /// `max_counter` 是本 key epoch 允许的最大计数器（注入共享窗口）。
    #[must_use]
    pub fn new(key: TransportKey, expected_receiver: u32, max_counter: u64) -> Self {
        Receiver {
            key,
            expected_receiver,
            window: Window::new(max_counter),
            poisoned: false,
        }
    }

    /// 期望的接收者标识。
    #[must_use]
    pub fn expected_receiver(&self) -> u32 {
        self.expected_receiver
    }

    /// 当前最高已接受计数器；空窗口为 `None`。
    #[must_use]
    pub fn highest(&self) -> Option<u64> {
        self.window.highest()
    }

    /// 是否已永久 poison。
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// 重放窗口拒绝：丢包但不 poison（不是密钥失同步的信号）。
    /// AEAD 认证失败：永久 poison。任何错误都不返回明文。
    pub fn open(&mut self, packet: &[u8]) -> Result<Decrypted, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if packet.len() > MAX_PACKET_LEN {
            return Err(Error::TooLong {
                actual: packet.len(),
                limit: MAX_PACKET_LEN,
            });
        }
        let transport = match parse(packet)? {
            Message::Transport(transport) => transport,
            Message::Init(_) => return Err(Error::NotTransport("握手初始化")),
            Message::Response(_) => return Err(Error::NotTransport("握手响应")),
            Message::Cookie(_) => return Err(Error::NotTransport("COOKIE")),
        };
        if transport.receiver != self.expected_receiver {
            return Err(Error::ReceiverMismatch {
                expected: self.expected_receiver,
                actual: transport.receiver,
            });
        }
        let cipher = self.key.cipher()?;
        // 先做 AEAD 认证解密；只有认证成功后才允许触碰重放窗口。
        let plaintext = cipher
            .decrypt(&nonce(transport.counter), transport.encrypted)
            .map_err(|_| {
                self.poisoned = true;
                Error::AuthFailed
            })?;
        // 窗口拒绝不改窗口状态、也不 poison：重复/过旧/超上限都只是丢包。
        self.window.accept_authenticated(transport.counter)?;
        Ok(Decrypted {
            counter: transport.counter,
            receiver: transport.receiver,
            plaintext,
        })
    }
}

impl core::fmt::Debug for Receiver {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Receiver")
            .field("expected_receiver", &self.expected_receiver)
            .field("highest", &self.window.highest())
            .field("poisoned", &self.poisoned)
            .field("key", &"TransportKey([redacted])")
            // 故意不输出 key 与窗口位图。
            .finish_non_exhaustive()
    }
}
