//! 传统 Shadowsocks AEAD 的异步 TCP 字节 chunk 收发（**不是**完整代理会话）。
//!
//! 线上格式与参考基线一致（Xray v26.3.27 / 完整 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，`proxy/shadowsocks/protocol.go` 的
//! `WriteTCPRequest` / `ReadTCPSession` / `ReadTCPResponse` / `WriteTCPResponse`，
//! 帧与 nonce 语义见 `common/crypto/auth.go` 的 `AuthenticationReader/Writer` 与
//! `common/crypto/chunk.go` 的 `AEADChunkSizeParser`）：
//!
//! ```text
//! salt（套件 IV 长度：AES-128-GCM 16，其余 32）
//!   [ AEAD(BE16(载荷明文长)) 18B || AEAD(载荷) 载荷长+16B ] × N
//! ```
//!
//! - **每个方向独立**：一个方向一个新随机 salt（`getrandom`）与一条独立的 AEAD
//!   nonce 递增序列；客户端发出方向与服务端发出方向互不相关。密钥派生复用
//!   `crate::key`（内部只调 `ss_core::kdf`），chunk 帧与 AEAD 上下文复用
//!   `ss_core::chunk::{write_chunk, read_chunk}` 与 `ss_core::crypto::SessionAead`，
//!   本模块不复制任何派生、AEAD 或帧编解码实现。
//! - **不等待对端回复**：`Writer` 只做 `盐 → 分块 → flush`，从不读取；`send`
//!   一次把整段输入切成不超过 `MAX_SEGMENT_PAYLOAD` 的若干 chunk（与参考实现
//!   `writeStream` 的 `buf.Size - Overhead - sizeBytes` 分段一致）。
//! - **首段明文是上层写的目标地址**：本 API 是**字节 chunk 层**，不解析地址。
//!   上层用 `TargetAddr::encode_checked` 把地址编进首次 `send` 的载荷，地址字节
//!   跨 chunk 时由上层请求层在重组字节上续读，因此不把 codec 当完整代理。
//! - **收尾用底层写半关闭**（`Writer::shutdown` → `AsyncWrite::shutdown`，TCP 上
//!   是 `SHUT_WR`），**不伪造 EOF 空帧**；正常 `send` 永不发送 size 明文为 0 的帧。
//!   空载荷 `send` 只保证 salt 上线（首次），不发送任何 chunk 帧。
//!   对端若发来终止帧，读取侧按参考判据视为正常收尾（`read_chunk` 的 `None`）。
//! - **截断与边界**：底层正常 EOF 只允许出现在 chunk 边界；salt、size 段或载荷体
//!   读到一半遇到 EOF 一律 `Truncated` 报错，绝不当作正常结束。
//! - **有限总超时 + 永久 poison**：每次 `send` / `recv`（含首次的盐收发）用同一个
//!   正数截止时间覆盖整个操作；任何 I/O、认证、截断、长度非法或超时错误之后该
//!   方向永久 `Poisoned`，后续调用不碰流直接失败，调用方必须关闭连接，
//!   不得重试，也没有明文回退路径。
//!
//! 未实现（不构成互通证明）：参考实现的
//! `drain.BehaviorSeedLimitedDrainer`（行为探测缓解与慢读惩罚）、分块 padding、
//! UDP 中继、真实服务与跨平台互通验收。入站 salt 防重放已接入
//! [`Reader::recv_guarded`]（窗口见 `crate::replay`，密钥化状态持久化见
//! `crate::persist`；密钥轮换见 [`crate::ReplayFilter::load_with_keys`]）。
//! 状态见 `docs/shadowsocks-status.md`。

use std::time::Duration;

use ss_core::chunk::{read_chunk, write_chunk, MAX_CHUNK_PAYLOAD, SIZE_WIRE_LEN};
use ss_core::crypto::{CipherSuite, SessionAead, TAG_LEN};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::timeout;

use std::sync::{Arc, Mutex};

use crate::drain::{BehaviorSeedLimitedDrainer, BehaviorSeedSource, HandshakeError};
use crate::key::{KeyError, MasterKey};
use crate::replay::{Error as ReplayError, ReplayFilter};

/// 跨连接共享的重放过滤器句柄。用 `Arc<Mutex<..>>`（**Send + Sync**）：`record`
/// 是同步方法，锁只在这一次调用内持有，不跨 await。
pub type ReplayFilterShared = Arc<Mutex<ReplayFilter>>;

/// 构造一个共享句柄。
#[must_use]
pub fn shared_replay(filter: ReplayFilter) -> ReplayFilterShared {
    Arc::new(Mutex::new(filter))
}

/// 重放判定句柄：一次性可变借用或跨连接共享句柄二选一。
///
/// 用枚举而非 trait object，避免在热路径上引入动态分发；两种形态都只是借用，
/// 不改变 `Reader` 各 future 的 `Send`/`Sync` 性质（`&Arc<Mutex<..>>` 是 `Send`）。
pub enum FilterRef<'a> {
    /// 调用方持有唯一可变引用（单连接测试路径）。
    Unique(&'a mut ReplayFilter),
    /// 跨连接共享句柄（中继服务路径）。
    Shared(&'a ReplayFilterShared),
}

impl FilterRef<'_> {
    fn record(&mut self, salt: &[u8], now_millis: u64) -> std::result::Result<(), Error> {
        let outcome = match self {
            Self::Unique(filter) => filter.record(salt, now_millis),
            Self::Shared(shared) => shared
                .lock()
                .expect("重放窗口锁中毒")
                .record(salt, now_millis),
        };
        outcome.map_err(Error::Replay)
    }
}

/// 单个 chunk 载荷明文上限，与参考实现 `writeStream` 的分段大小一致：
/// `buf.Size(8192) - Overhead(16) - sizeBytes(18)` = 8158。
/// 更大的输入由 `send` 自动分成多个 chunk，不额外设总量上限。
pub const MAX_SEGMENT_PAYLOAD: usize = MAX_CHUNK_PAYLOAD - TAG_LEN - SIZE_WIRE_LEN;

/// TCP 流方向上的失败原因。Display 与 Debug 都不含口令、主密钥、salt 或 subkey。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("会话参数非法：{0}")]
    Key(#[from] KeyError),

    #[error("随机 salt 获取失败")]
    Entropy,

    #[error("截止时间必须大于零")]
    InvalidDeadline,

    #[error("AEAD 认证失败（错误口令、篡改或 nonce 失步）")]
    Authentication,

    #[error("chunk 长度字段非法：{0} 字节")]
    InvalidFrame(usize),

    #[error("流在{expect}处被截断（底层提前 EOF，不在 chunk 边界）")]
    Truncated { expect: &'static str },

    #[error("本方向已失效，永久拒绝继续（fail-closed）")]
    Poisoned,

    #[error("写端已半关闭，不得再发送")]
    Closed,

    #[error("单次操作超过截止时间")]
    Timeout,

    #[error("salt 重放拒绝：{0}")]
    Replay(#[from] ReplayError),

    #[error("共享协议原语拒绝：{0}")]
    Protocol(ss_core::Error),

    #[error("底层 I/O 失败：{0}")]
    Io(#[from] std::io::Error),

    #[error("握手失败触发行为探测缓解：{0}")]
    Drained(HandshakeError),
}

type Result<T> = std::result::Result<T, Error>;

/// 零时长会被 `tokio::time::timeout` 立刻判定过期，这里显式拒绝以便调用方区分。
fn check_timeout(wait: Duration) -> Result<()> {
    if wait.is_zero() {
        Err(Error::InvalidDeadline)
    } else {
        Ok(())
    }
}

/// 把 `ss_core` 帧/AEAD 错误映射为本模块语义：认证失败与长度非法分开报告，
/// 两者都要求调用方关闭连接。`ss_core::Error` 的消息只含长度/枚举名，不含密钥。
fn core_error(err: ss_core::Error) -> Error {
    match err {
        ss_core::Error::AuthFailed => Error::Authentication,
        ss_core::Error::InvalidLength(len) => Error::InvalidFrame(len),
        ss_core::Error::Io(io) => read_io(io, "chunk"),
        other => Error::Protocol(other),
    }
}

/// 读侧 I/O 错误：`UnexpectedEof` 意味着帧读到一半就结束了 ⇒ 截断，不是正常收尾。
fn read_io(err: std::io::Error, expect: &'static str) -> Error {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Truncated { expect }
    } else {
        Error::Io(err)
    }
}

/// 一个方向的发送端：写出随机 salt 与后续 AEAD chunk，不读取、不等对端回复。
///
/// 持有 salt 派生出的 subkey 与 nonce 序列，因此**故意不实现 `Debug`**，
/// 避免密钥材料进入日志或调试输出。
pub struct Writer<W> {
    inner: W,
    suite: CipherSuite,
    aead: SessionAead,
    salt: Vec<u8>,
    salt_sent: bool,
    closed: bool,
    poisoned: bool,
    wait: Duration,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    /// 检查参数、取新随机 salt 并派生本方向会话。空口令、套件参数不符、零截止
    /// 时间都在返回 `Err` 时失败，不写出任何字节，也不留半构造状态。
    /// salt 在此刻生成，但直到首次 `send` 才上线；`new` 本身不做 I/O。
    pub fn new(write: W, suite: CipherSuite, password: &[u8], wait: Duration) -> Result<Self> {
        check_timeout(wait)?;
        let key = MasterKey::new(suite, password)?;
        let salt = key.new_salt().map_err(|_| Error::Entropy)?;
        let aead = key.session(&salt)?;
        Ok(Self {
            inner: write,
            suite,
            aead,
            salt,
            salt_sent: false,
            closed: false,
            poisoned: false,
            wait,
        })
    }

    #[must_use]
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// 本套件 salt 长度。
    #[must_use]
    pub fn salt_len(&self) -> usize {
        self.suite.salt_len()
    }

    /// salt 是否已上线（首次成功的 `send` 之后为真）。
    #[must_use]
    pub fn salt_sent(&self) -> bool {
        self.salt_sent
    }

    /// 底层写端引用（例如查询 `TcpStream` 状态）。
    #[must_use]
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// 底层写端可变引用。绕过本类型直接写字节会破坏帧边界，仅供非协议用途
    /// （如查询能力、设置 socket 选项）。
    #[must_use]
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// 交出底层写端。若本方向已失效，流上字节位置不可恢复，调用方仍须关闭连接。
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// 把 `payload` 作为若干 chunk 写出：首次调用先把 salt 写出，随后按
    /// `MAX_SEGMENT_PAYLOAD` 分块，最后 flush。不等待也不读取对端任何字节。
    ///
    /// 空载荷不发送任何 chunk 帧（尤其不发送 size 明文为 0 的终止帧）；首次
    /// 空载荷仍会把 salt 上线，使该方向成为一个已建立、零 chunk 的空流。
    /// 一次调用是一个整体：单个 `wait` 覆盖 salt 与全部分块。
    /// 任何错误之后本方向永久失效，调用方必须关闭连接。
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        self.usable()?;
        let outcome = self.send_inner(payload).await;
        if outcome.is_err() {
            self.poisoned = true;
        }
        outcome
    }

    /// 正常收尾：flush 后对底层做写半关闭（TCP 上是 `SHUT_WR`），让对端恰好在
    /// chunk 边界看到 EOF。不发送终止帧，因此不消耗 nonce。可重复调用；
    /// 之后 `send` 报 `Closed`。超时或 I/O 失败同样永久失效本方向。
    pub async fn shutdown(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.closed {
            return Ok(());
        }
        let wait = self.wait;
        let inner = &mut self.inner;
        let outcome = timeout(wait, async move {
            inner.flush().await?;
            inner.shutdown().await
        })
        .await;
        match outcome {
            Ok(Ok(())) => {
                self.closed = true;
                Ok(())
            }
            Ok(Err(io)) => {
                self.poisoned = true;
                Err(Error::Io(io))
            }
            Err(_) => {
                self.poisoned = true;
                Err(Error::Timeout)
            }
        }
    }

    async fn send_inner(&mut self, payload: &[u8]) -> Result<()> {
        let wait = self.wait;
        let need_salt = !self.salt_sent;
        // 逐字段借用：salt 只读，inner/aead 可变，三者互不重叠。
        let salt = &self.salt;
        let inner = &mut self.inner;
        let aead = &mut self.aead;
        timeout(wait, async move {
            if need_salt {
                inner.write_all(salt).await.map_err(Error::Io)?;
            }
            for piece in payload.chunks(MAX_SEGMENT_PAYLOAD) {
                write_chunk(inner, aead, piece).await.map_err(core_error)?;
            }
            inner.flush().await.map_err(Error::Io)
        })
        .await
        .map_err(|_| Error::Timeout)??;
        self.salt_sent = true;
        Ok(())
    }

    fn usable(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.closed {
            return Err(Error::Closed);
        }
        Ok(())
    }
}

/// 一个方向的接收端：首次 `recv` 读取 salt 并派生会话，之后逐 chunk 取回明文字节。
///
/// 只完成本方向所需的最小读取，不写任何东西，因此调用方可以安全地半关闭自己
/// 的发送方向后继续读取（半关闭由底层流提供）。内部带一层 `BufReader`：用它
/// 判断“是否恰好停在 chunk 边界”，从而把正常 EOF 与帧内截断分开；缓冲的字节
/// 仍由后续 `recv` 取回，不会丢失或越过认证。正因为这个缓冲，本类型不提供
/// `into_inner`/`get_mut`（会丢掉已读入缓冲但未交付的字节）。
/// **故意不实现 `Debug`**（持有主密钥与 subkey）。
pub struct Reader<R> {
    pub(crate) buffered: BufReader<R>,
    key: MasterKey,
    aead: Option<SessionAead>,
    /// 本连接读到并列过会话的 salt；保留到首个 chunk 认证通过后交给重放窗口判定。
    salt: Option<Vec<u8>>,
    /// 本连接的重放判定是否已完成（无论是否启用 filter，只在首个认证 chunk 后置真）。
    replay_checked: bool,
    closed: bool,
    poisoned: bool,
    wait: Duration,
    /// 行为探测缓解（参考 `ReadTCPSession` 的 drainer 钩子）；细节见 `crate::tcp_drain`。
    pub(crate) drainer: Option<BehaviorSeedLimitedDrainer>,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    /// 检查参数并派生主密钥。salt 与 subkey 留到首次 `recv`（那时才可能读流）。
    /// 空口令、套件参数不符与零截止时间立即失败，不碰流。
    pub fn new(read: R, suite: CipherSuite, password: &[u8], wait: Duration) -> Result<Self> {
        check_timeout(wait)?;
        let key = MasterKey::new(suite, password)?;
        Ok(Self {
            buffered: BufReader::new(read),
            key,
            aead: None,
            salt: None,
            replay_checked: false,
            closed: false,
            poisoned: false,
            wait,
            drainer: None,
        })
    }

    /// 挂上行为探测缓解（参考 `ReadTCPSession` 的 drainer）；细节见 `crate::tcp_drain`。
    #[must_use]
    pub fn with_drainer(self, seed_source: Option<&mut BehaviorSeedSource>) -> Self {
        crate::tcp_drain::attach(self, seed_source)
    }

    /// 直接指定 seed（测试与可复现部署用）。
    #[must_use]
    pub fn with_drainer_seed(self, seed: i64) -> Self {
        crate::tcp_drain::attach_seed(self, seed)
    }

    /// 当前 drain 预算（未挂 drainer 时为 `None`）。仅供测试与诊断观察。
    #[must_use]
    pub fn drain_budget(&self) -> Option<i64> {
        crate::tcp_drain::budget(self)
    }

    #[must_use]
    pub fn suite(&self) -> CipherSuite {
        self.key.suite()
    }

    /// 本套件 salt 长度（预分配与截断判断可用）。
    #[must_use]
    pub fn salt_len(&self) -> usize {
        self.key.salt_len()
    }

    /// salt 是否已读到（会话是否已建立）。salt 未读满就 EOF 是截断错误，不是正常结束。
    #[must_use]
    pub fn session_started(&self) -> bool {
        self.aead.is_some()
    }

    /// 底层读端引用（例如查询 `TcpStream` 状态）。
    #[must_use]
    pub fn get_ref(&self) -> &R {
        self.buffered.get_ref()
    }

    /// 取回下一个 chunk 的明文字节；`Ok(None)` 表示该方向正常结束（chunk 边界上
    /// 的底层 EOF，或对端显式终止帧）。首次调用包含 salt 读取与派生，与后续读取
    /// 共用同一个 `wait`；任何错误之后本方向永久失效。
    ///
    /// 目标地址等跨 chunk 结构由上层在 `Ok(Some(..))` 交付的字节序列上续读重组；
    /// 本层只保证每个 chunk 的认证、顺序与长度边界。结束后的再次调用继续返回
    /// `Ok(None)`，不再碰流。
    ///
    /// 本入口不做 salt 唯一性检查（与 `UdpCodec::open` 的无状态语义一致）；需要
    /// 入站防重放的调用方用 [`Reader::recv_guarded`]。
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        self.drive(None).await
    }

    /// 与 [`Reader::recv`] 相同的读取语义，但会在**首个 chunk 认证通过后**把本连接
    /// 的 salt 交给 `filter` 做重放判定：`filter` 由调用方在连接之间共享，第二次
    /// 出现同 salt 时返回 [`Error::Replay`] 并永久 poison 本方向。
    ///
    /// 只读到 salt 就干净 EOF 的空流没有任何已认证的 chunk，不记录该 salt——这
    /// 既避免把「无法证明通过认证」的 salt 记入窗口，也让攻击者无法用随机垃圾
    /// salt 灌满窗口。
    pub async fn recv_guarded(&mut self, filter: &mut ReplayFilter) -> Result<Option<Vec<u8>>> {
        self.drive(Some(FilterRef::Unique(filter))).await
    }

    /// 与 [] 同语义，但接受**跨连接共享**的重放句柄
    /// （中继服务用：多条连接并发握手时不会争用同一个 ）。
    pub async fn recv_guarded_shared(
        &mut self,
        filter: &ReplayFilterShared,
    ) -> Result<Option<Vec<u8>>> {
        self.drive(Some(FilterRef::Shared(filter))).await
    }

    async fn drive(&mut self, filter: Option<FilterRef<'_>>) -> Result<Option<Vec<u8>>> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.closed {
            return Ok(None);
        }
        let wait = self.wait;
        let outcome = timeout(wait, self.read_next(filter))
            .await
            .map_err(|_| Error::Timeout);
        match outcome {
            Ok(Ok(chunk @ Some(_))) => Ok(chunk),
            Ok(Ok(None)) => {
                self.closed = true;
                Ok(None)
            }
            Ok(Err(err)) => {
                self.poisoned = true;
                Err(err)
            }
            Err(timeout_err) => {
                self.poisoned = true;
                Err(timeout_err)
            }
        }
    }

    /// 握手失败时的行为探测缓解钩子（参考 `drain.WithError` → `Drain`）。
    ///
    /// 未挂 drainer 时原样返回 `err`；挂上时按 seed 限量读出并丢弃对端字节，
    /// 详见 `crate::tcp_drain`。
    async fn drain_handshake(&mut self, handshake: HandshakeError, err: Error) -> Error {
        crate::tcp_drain::drain_handshake(self, handshake, err).await
    }

    async fn read_next(&mut self, filter: Option<FilterRef<'_>>) -> Result<Option<Vec<u8>>> {
        if self.aead.is_none() {
            // salt 读不满 ⇒ 截断（本层不认为“短 salt 后 EOF”是空流）。
            let mut salt = vec![0u8; self.key.salt_len()];
            if let Err(err) = self.buffered.read_exact(&mut salt).await {
                return Err(self
                    .drain_handshake(HandshakeError::ShortHeader, read_io(err, "salt"))
                    .await);
            }
            // salt 等价于参考读完 IV 后的 `AcknowledgeReceive(ivLen)`：
            // 已认证前缀从不变量里抵扣，正常客户端不必为缓解付代价。
            crate::tcp_drain::credit_salt(self);
            self.salt = Some(salt.clone());
            let aead = match self.key.session(&salt) {
                Ok(aead) => aead,
                // 派生失败等价于参考的 “failed to initialize decoding stream”。
                Err(err) => {
                    return Err(self
                        .drain_handshake(HandshakeError::DecodeInit, Error::Key(err))
                        .await)
                }
            };
            self.aead = Some(aead);
        }
        // 边界探测：等到至少一个字节或确认 EOF，才让 read_chunk 开始读帧。
        if self.buffered.fill_buf().await?.is_empty() {
            // 底层在 chunk 边界干净结束 ⇒ 正常收尾；此时没有任何已认证的 chunk。
            return Ok(None);
        }
        // 已可得的字节数用来区分“size 段读到一半结束”与“载荷段读到一半结束”。
        let available = self.buffered.buffer().len();
        let aead = self.aead.as_mut().expect("salt 之后会话必然已建立");
        let chunk = match read_chunk(&mut self.buffered, aead).await {
            Ok(chunk) => chunk,
            Err(err) => {
                let mapped = match core_error(err) {
                    // read_chunk 用 read_exact 取段，帧内 EOF ⇒ 截断；按已可得字节定位段。
                    Error::Truncated { .. } if available < SIZE_WIRE_LEN => {
                        Error::Truncated { expect: "size 段" }
                    }
                    Error::Truncated { .. } => Error::Truncated {
                        expect: "载荷段"
                    },
                    other => other,
                };
                // 首个 chunk 认证失败等价于参考的 “failed to match an user” /
                // “failed iv check”：探测者最可能命中这条路径，必须同样缓解。
                let handshake = match mapped {
                    Error::Authentication => Some(HandshakeError::NoUser),
                    Error::Truncated { .. } => Some(HandshakeError::ShortHeader),
                    _ => None,
                };
                return Err(match handshake {
                    Some(h) => self.drain_handshake(h, mapped).await,
                    None => mapped,
                });
            }
        };
        match chunk {
            Some(data) => {
                // 认证通过且确有一块明文交付，才把 salt 记入重放窗口（每连接只记一次）。
                if !self.replay_checked {
                    if let (Some(mut filter), Some(salt)) = (filter, self.salt.as_deref()) {
                        // record 是同步方法，锁/借用只覆盖这一次调用，绝不跨 await。
                        filter.record(salt, ReplayFilter::system_now_millis())?;
                    }
                    self.replay_checked = true;
                }
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }
}
