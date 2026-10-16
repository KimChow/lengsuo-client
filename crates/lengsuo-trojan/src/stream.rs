//! Trojan 异步握手、UDP 数据报帧与关闭收尾（原语，不是完整协议服务）。
//!
//! 线上格式与参考实现一致（Xray v26.3.27，完整 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，`proxy/trojan/protocol.go`）：
//!
//! ```text
//! 请求头：密码哈希(56) CRLF 命令(1) SOCKS 地址+端口 CRLF
//! UDP 帧：SOCKS 地址+端口 长度(2, 大端) CRLF 载荷
//! ```
//!
//! 头部编解码复用 `crate::codec`，地址复用 `ss_core::target::TargetAddr` 的
//! `encode_checked` / `decode`，本模块不复制任何编解码实现。
//!
//! 读取一律逐字节增量进行，因此解析完成后流上只剩应用载荷，头部之后的字节
//! 不会被吞掉。Trojan 没有成功响应头，
//! 故本模块不提供响应头函数；认证结果由调用方通过关闭连接表达。
//!
//! 每次调用使用**一个**正数截止时间覆盖整个操作（包括截断后的续读），零时长
//! 直接拒绝。任何失败都是 fail-closed：调用方必须关闭连接，不得重试或回退明文。
//! TLS 由上层（`lengsuo-tls`）负责，调用方必须先完成认证 TLS 再握手。
//!
//! 关闭收尾（对齐 `common/drain/drainer.go`）：`close_stream` 先在 `Drainer` 策略下
//! 丢弃读侧残留，再做写半关闭（flush + shutdown），**两个阶段共用同一个调用参数
//! `wait` 派生出的单一截止时间**——阶段各自拿到的剩余时间之和不超过 `wait`，
//! 剩余为 0 即记为超时，绝不无限等待。参考 trojan 本身不安装 drainer，所以
//! `Drainer::default()`（不丢弃）就是参考默认行为；丢弃长度、抵消与逐字节语义
//! 见 `crate::drain`，需要“先开门再转发”的调用方用 `crate::session`。

use std::time::Duration;

use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, Instant};

use crate::codec::{self, Command, Request};
use crate::credential::Credential;
use crate::drain::{DrainOutcome, Drainer};

/// 两处 CRLF 分隔符，与 `codec` 的线上格式相同。
const CRLF: [u8; 2] = *b"\r\n";

/// 请求头最大长度：哈希 56 + CRLF 2 + 命令 1 + 最长域名地址 259 + CRLF 2。
/// 用作续读上限，避免对异常长度前缀无界缓冲。
const MAX_HEADER_LEN: usize = 56 + 2 + 1 + (1 + 1 + 255 + 2) + 2;

/// SOCKS 地址最大长度：ATYP 1 + 域名长度 1 + 域名 255 + 端口 2。
const MAX_TARGET_LEN: usize = 1 + 1 + 255 + 2;

/// 参考 `proxy/trojan/protocol.go` 服务端 UDP 帧载荷上限 `maxLength = 8192`。
/// 线上长度字段本身可到 65535（`send_datagram` / `receive_datagram` 保持线上边界，
/// 不改既有行为）；需要参考默认策略的调用方用 `crate::session::Session`，
/// 它在转发数据报前按本常量拒绝。
pub const REFERENCE_MAX_DATAGRAM_PAYLOAD: usize = 8192;

/// 流操作错误。包装 codec、`ss_core`、drain 与 I/O 失败，并区分超时、非法截止时间、
/// 帧超长、坏 CRLF、会话 poison 与命令分支不匹配。
/// Display/Debug 不含密码或哈希；凭据仍受隐私策略约束。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("请求头处理失败：{0}")]
    Codec(#[from] codec::Error),

    #[error("目标地址非法：{0}")]
    Core(#[from] ss_core::Error),

    #[error("协议操作超时")]
    Timeout,

    #[error("截止时间必须大于零")]
    InvalidDeadline,

    #[error("数据帧长度超过限制")]
    FrameTooLarge,

    #[error("数据帧分隔符不是 CRLF")]
    InvalidCrlf,

    #[error("关闭前残留读取失败：{0}")]
    Drain(#[from] crate::drain::Error),

    #[error("会话已失败，永久拒绝后续操作：必须关闭连接")]
    Poisoned,

    #[error("命令分支不匹配：会话是 {0:?}，该操作属于另一分支")]
    CommandMismatch(Command),

    #[error("流操作失败：{0}")]
    Io(#[from] std::io::Error),
}

/// 零时长会被 `tokio::time::timeout` 立刻判定过期，这里显式拒绝以便调用方区分。
fn check_deadline(wait: Duration) -> Result<(), Error> {
    if wait.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    Ok(())
}

/// 写出请求头。头部之后的应用载荷由调用方继续写入同一 `stream`；
/// 需要“认证/写头成功前不得转发载荷”这一约束由类型表达的调用方，
/// 用 `crate::session::Session::handshake`（它只在头部完整写出后才交回会话）。
pub async fn send_request<W: AsyncWrite + Unpin>(
    stream: &mut W,
    request: &Request,
    credential: &Credential,
    wait: Duration,
) -> Result<(), Error> {
    check_deadline(wait)?;
    // 非法域名在编码阶段拒绝，不写出任何字节。
    let header = codec::encode(request, credential)?;
    timeout(wait, async {
        stream.write_all(&header).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(())
}

/// 读取并校验请求头，返回请求；头部之后的字节原样留在流上供应用读取。
///
/// 逐字节续读：`codec::decode` 报 `Truncated` 就再读一字节，报其他错误立即返回。
/// 因此错误密码在读满 56 字节哈希时即被拒绝，不等地址到达；认证通过后才会
/// 暴露命令与地址解析结果。
pub async fn receive_request<R: AsyncRead + Unpin>(
    stream: &mut R,
    credential: &Credential,
    wait: Duration,
) -> Result<Request, Error> {
    check_deadline(wait)?;
    timeout(wait, async {
        let mut header = Vec::with_capacity(MAX_HEADER_LEN);
        loop {
            match codec::decode(&header, credential) {
                Ok((request, used)) => {
                    // 逐字节读取保证 used 恰等于已读字节数，不会越过头部末尾。
                    debug_assert_eq!(used, header.len());
                    return Ok(request);
                }
                Err(codec::Error::Truncated { need, .. }) => {
                    // 防御性上限：长度前缀超出 Trojan 头部最大规模即拒绝。
                    if need > MAX_HEADER_LEN || header.len() >= MAX_HEADER_LEN {
                        return Err(Error::FrameTooLarge);
                    }
                    header.push(stream.read_u8().await?);
                }
                Err(other) => return Err(Error::Codec(other)),
            }
        }
    })
    .await
    .map_err(|_| Error::Timeout)?
}

/// 写出一个 UDP 数据报帧：目标地址 + 两字节大端长度 + CRLF + 载荷。
///
/// 载荷超过 2 字节可表示范围时在分配前拒绝；写入要么整帧完成，要么返回错误
/// 由调用方关闭连接。参考服务端的 `maxLength = 8192` 策略不在本函数强制，
/// 见 `REFERENCE_MAX_DATAGRAM_PAYLOAD`。
pub async fn send_datagram<W: AsyncWrite + Unpin>(
    stream: &mut W,
    target: &TargetAddr,
    packet: &[u8],
    wait: Duration,
) -> Result<(), Error> {
    check_deadline(wait)?;
    // 先验证容量再分配：长度必须由 2 字节大端无符号数表示（协议线上限制 65535）。
    let length = u16::try_from(packet.len()).map_err(|_| Error::FrameTooLarge)?;
    let frame_len = target
        .encoded_len()
        .checked_add(2 + 2 + packet.len())
        .ok_or(Error::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(frame_len);
    // encode_checked 在写入任何字节前拒绝空/超长/含 NUL 的域名。
    target.encode_checked(&mut frame)?;
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&CRLF);
    frame.extend_from_slice(packet);

    timeout(wait, async {
        stream.write_all(&frame).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(())
}

/// 读取一个 UDP 数据报帧，返回（目标地址，载荷）。
///
/// `limit` 是上层给的载荷容量上限，在分配载荷缓冲之前检查；超限立即拒绝，
/// 不读取载荷也不回退。CRLF 必须是 `\r\n` 两个字节，宽松分隔符不容忍。
/// 失败后流位置不可恢复，调用方必须关闭连接。
pub async fn receive_datagram<R: AsyncRead + Unpin>(
    stream: &mut R,
    limit: u16,
    wait: Duration,
) -> Result<(TargetAddr, Vec<u8>), Error> {
    check_deadline(wait)?;
    timeout(wait, async {
        let target = read_target(stream).await?;
        let length = stream.read_u16().await?;
        // 容量检查先于分配。
        if length > limit {
            return Err(Error::FrameTooLarge);
        }
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        if crlf != CRLF {
            return Err(Error::InvalidCrlf);
        }
        let mut packet = vec![0u8; usize::from(length)];
        stream.read_exact(&mut packet).await?;
        Ok((target, packet))
    })
    .await
    .map_err(|_| Error::Timeout)?
}

/// 逐字节增量解析 SOCKS 地址，读完地址即停手，长度字段仍留在流上。
async fn read_target<R: AsyncRead + Unpin>(stream: &mut R) -> Result<TargetAddr, Error> {
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_TARGET_LEN);
    loop {
        match TargetAddr::decode(&buf) {
            Ok((target, used)) => {
                debug_assert_eq!(used, buf.len());
                return Ok(target);
            }
            // 只有“字节还不够”才续读；非法 ATYP/域名等格式错误立即返回。
            Err(ss_core::Error::TooShort { .. }) => {
                if buf.len() >= MAX_TARGET_LEN {
                    return Err(Error::FrameTooLarge);
                }
                buf.push(stream.read_u8().await?);
            }
            Err(other) => return Err(Error::Core(other)),
        }
    }
}

/// 写出应用载荷并 flush（头部之后的字节流转发）。
///
/// 本函数只是 `send_request` 的写侧对偶，供 `Session` 与上层复用；
/// 它自身**不**代表任何“已认证”证明，fail-closed 顺序约束由 `crate::session` 表达。
pub async fn forward_payload<W: AsyncWrite + Unpin>(
    stream: &mut W,
    payload: &[u8],
    wait: Duration,
) -> Result<(), Error> {
    check_deadline(wait)?;
    timeout(wait, async {
        stream.write_all(payload).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(())
}

/// 读取应用载荷到 `buf`，返回读到的字节数；`Ok(0)` 表示对端正常 EOF（不视为失败）。
///
/// 与 `forward_payload` 成对，供 `crate::session` 与上层复用。空 `buf` 不触碰流，
/// 只在零 `wait` 时拒绝；EOF 之外的读错误由调用方关闭连接。
pub async fn receive_payload<R: AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut [u8],
    wait: Duration,
) -> Result<usize, Error> {
    check_deadline(wait)?;
    if buf.is_empty() {
        return Ok(0);
    }
    timeout(wait, stream.read(buf))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)
}

/// 写半关闭：flush 后 `AsyncWrite::shutdown`（TCP 上是 `SHUT_WR`），
/// 读侧仍可继续收对端数据。`drain` 阶段请在此之前用 `close_stream` 完成。
pub async fn shutdown_write<W: AsyncWrite + Unpin>(
    stream: &mut W,
    wait: Duration,
) -> Result<(), Error> {
    check_deadline(wait)?;
    timeout(wait, async {
        stream.flush().await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(())
}

/// 关闭收尾的结果。两步都尝试：drain 失败绝不阻止写半关闭（否则只会得到 RST），
/// 这与参考 `drain.WithError` 把 drain 结果叠加在原始错误上的做法一致。
///
/// 无论内容如何，调用方都必须随后关闭连接；本类型不派生 PartialEq（内含错误）。
#[derive(Debug)]
pub struct CloseReport {
    /// 读侧残留丢弃结果；`Err(Timeout)`/`Err(Drain(..))` 表示没能按策略丢完。
    pub drain: Result<DrainOutcome, Error>,
    /// 写半关闭结果。
    pub write_shutdown: Result<(), Error>,
}

impl CloseReport {
    /// 两步都成功（drain 结果允许是策略本身的任何成功分支）。
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.drain.is_ok() && self.write_shutdown.is_ok()
    }

    /// 实际丢弃的字节数；drain 失败时为 0（失败详情看 `drain`）。
    #[must_use]
    pub fn drained_bytes(&self) -> usize {
        self.drain.as_ref().map_or(0, DrainOutcome::bytes)
    }
}

/// 按 `drainer` 策略丢弃读侧残留，然后做写半关闭；两个阶段共用**同一个**
/// 由 `wait` 派生的截止时间，剩余时间耗尽即记为 `Error::Timeout`。
///
/// `Drainer::default()`（`Nop`）= 参考 trojan 的默认收尾：不读残留，只半关闭写侧。
/// 零 `wait` 拒绝（`Err(Timeout)` 之前的分支，见 `CloseReport::rejected`）。
/// 传入同一个流的两半（例如 `tokio::io::split` 的结果）或两个独立句柄。
pub async fn close_stream<R, W>(
    read: &mut R,
    write: &mut W,
    drainer: &mut Drainer,
    wait: Duration,
) -> CloseReport
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if wait.is_zero() {
        return CloseReport::rejected();
    }
    let deadline = Instant::now() + wait;
    // 阶段一：丢弃残留。参考的判据是 DrainSize <= 0 就不读，因此 Nop 策略下
    // 即便截止时间已经用光也无需报错。
    let drain = if drainer.remaining() == 0 {
        drainer.drain(read, wait).await.map_err(Error::Drain)
    } else {
        match remaining(deadline) {
            Some(left) => drainer.drain(read, left).await.map_err(Error::Drain),
            None => Err(Error::Timeout),
        }
    };
    // 阶段二：写半关闭，用剩下的时间；已经耗尽则只报超时，但仍**尝试**关闭。
    let write_shutdown = match remaining(deadline) {
        Some(left) => shutdown_write(write, left).await,
        None => Err(Error::Timeout),
    };
    CloseReport {
        drain,
        write_shutdown,
    }
}

impl CloseReport {
    /// 零时长调用的结果：两步都标为拒绝，调用方仍须关闭连接。
    fn rejected() -> Self {
        CloseReport {
            drain: Err(Error::InvalidDeadline),
            write_shutdown: Err(Error::InvalidDeadline),
        }
    }
}

/// 截止时间剩余时间；已过期返回 `None`（`saturating_duration_since` 给 0）。
fn remaining(deadline: Instant) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        None
    } else {
        Some(left)
    }
}
