//! UDP 关联中继：把流上的 Trojan UDP 报文转发到真实 UDP 套接字并回程。
//!
//! 语义基线：Xray v26.3.27，`proxy/trojan/server.go:247-320` 的 `handleUDPPayload`
//! + `protocol.go` 的 `PacketReader` / `PacketWriter`。
//!
//! 出站会话复用对齐 `transport/internet/udp/dispatcher.go`
//!（落地在 `crate::udp_pool`）。
//!

//! 与参考的逐条对应（差异见 `docs/trojan-status.md` 偏离清单）：
//! - 参考按目标分发到出站链路（`udpServer.Dispatch(currentPacketCtx, *dest, b)`）；
//!   本实现经 `crate::udp_pool` 按**目标地址**复用出站 socket。
//! - 参考的 cone 短路（`if !s.cone || dest == nil { dest = &destination }`）由池的
//!   `cone` 配置承载：cone 开启时首包目标固定到整个关联，**后续包自身的目标被忽略**
//!   （参考语义，不是 bug）。
//! - 参考的回程写回失败 ⇒ `cancel()` 整个会话（不是只关这一条）：本实现在回程写
//!   失败时结束整条关联。
//! - 参考的空闲计时 `signal.CancelAfterInactivity(..., ConnectionIdle)`：本实现对
//!   每次读操作套同一 `idle` 截止（逐操作等价，见文档偏离清单）。
//!
//! 回程是**异步**的：请求侧与回程侧并行，收到即写回（参考的
//! `udpServer` 回调也是异步写回），不再逐包串行等待。

use std::time::Duration;

use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::udp::{decode_packet, encode_packet, Error as FrameError};
use crate::udp_pool::{PoolConfig, UdpPool};

/// 上行读缓冲：容纳最长域名地址 + 2 字节长度 + CRLF + 最大载荷（65535）。
const READ_BUF: usize = 1 + 1 + 255 + 2 + 2 + 2 + crate::udp::MAX_PAYLOAD_LEN;

/// UDP 中继错误。帧格式错误、池错误、IO 与超时分区上报，一律 fail-closed。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("截止时间必须大于零")]
    InvalidDeadline,

    #[error("UDP 报文帧非法：{0}")]
    Frame(#[from] FrameError),

    #[error("UDP 会话池错误：{0}")]
    Pool(#[from] crate::udp_pool::Error),

    #[error("UDP 关联内协议操作超时")]
    Timeout,

    #[error("UDP 关联读侧结束：{0}")]
    Io(#[from] std::io::Error),
}

/// 上行帧读取器：把流上的字节流切成 Trojan UDP 报文。
struct FrameReader<R> {
    reader: R,
    buf: Vec<u8>,
    filled: usize,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buf: vec![0u8; READ_BUF],
            filled: 0,
        }
    }

    /// 读下一帧。`Ok(None)` 表示读侧在**帧边界**干净结束（半关闭）。
    ///
    /// 流上的一帧可能被 TCP/TLS 切成多块：只要声明长度还没读满，就继续读
    /// （对齐参考 `protocol.go` 的 `io.ReadFull`：短读不是错误）。只有读侧
    /// 结束（EOF）时字节仍不足才是协议错误（fail-closed）。
    async fn next_frame(
        &mut self,
        limit: usize,
        idle: Duration,
    ) -> Result<Option<(TargetAddr, Vec<u8>)>, Error> {
        loop {
            match decode_packet(&self.buf[..self.filled], limit) {
                Ok(((target, payload), used)) => {
                    // 载荷必须先复制：后续读会覆写同一缓冲。
                    let owned = payload.to_vec();
                    // 本帧之后的字节属于**后续帧**：保留，不丢。
                    self.buf.copy_within(used..self.filled, 0);
                    self.filled -= used;
                    return Ok(Some((target, owned)));
                }
                Err(FrameError::Truncated { need, .. }) => {
                    if need > READ_BUF {
                        return Err(Error::Frame(FrameError::Oversize(need)));
                    }
                    if !self.read_more(idle).await? {
                        // 读侧结束：缓冲为空 ⇒ 干净 EOF（半关闭），不是协议错误。
                        // 缓冲非空 ⇒ 残留半帧是协议错误（fail-closed）。
                        if self.filled == 0 {
                            return Ok(None);
                        }
                        return Err(Error::Frame(FrameError::Truncated {
                            need,
                            got: self.filled,
                        }));
                    }
                }
                Err(FrameError::LengthMismatch {
                    declared,
                    available,
                }) => {
                    // 流上声明长度大于已到达字节：继续读满（参考 `io.ReadFull`）。
                    let need = self.filled + (declared - available);
                    if need > READ_BUF {
                        return Err(Error::Frame(FrameError::Oversize(declared)));
                    }
                    if !self.read_more(idle).await? {
                        // 读侧结束：缓冲为空 ⇒ 干净 EOF（半关闭），不是协议错误。
                        if self.filled == 0 {
                            return Ok(None);
                        }
                        // 读侧结束且仍不足 ⇒ 协议错误（fail-closed）。
                        return Err(Error::Frame(FrameError::LengthMismatch {
                            declared,
                            available,
                        }));
                    }
                }
                Err(other) => return Err(Error::Frame(other)),
            }
        }
    }

    /// 继续读入流上的字节。返回 `false` 表示读侧已结束（EOF）。
    async fn read_more(&mut self, idle: Duration) -> Result<bool, Error> {
        if self.filled == READ_BUF {
            // 缓冲已满却仍缺字节：帧超出可承载上限，fail-closed。
            return Err(Error::Frame(FrameError::Oversize(READ_BUF)));
        }
        let read = timeout(idle, self.reader.read(&mut self.buf[self.filled..]))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;
        if read == 0 {
            return Ok(false);
        }
        self.filled += read;
        Ok(true)
    }
}

/// 在一条已建立的 UDP 关联上双向中继，直到客户端读侧 EOF。
///
/// `payload_limit` 是单包载荷上限（超限 fail-closed）；`idle` 是单个读操作的
/// 空闲截止（参考 `CancelAfterInactivity` 的逐操作等价，见文档偏离清单）。
/// 客户端停止发送但仍接收时**不得提前断开**：读侧 EOF 之前，回程照常写出。
pub async fn relay<R, W>(
    reader: R,
    writer: W,
    payload_limit: usize,
    idle: Duration,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let config = PoolConfig {
        idle_timeout: idle,
        max_entries: crate::udp_pool::DEFAULT_MAX_ENTRIES,
        cone: false,
        payload_limit,
    };
    relay_with(reader, writer, config, idle).await
}

/// 与 `relay` 相同，但出站会话池的 **cone 模式**可配。
///
/// `cone = true` 时首包目标固定到整个关联，后续包自身的目标被忽略
/// （对齐参考 `server.go` 的 `if !s.cone || dest == nil { dest = &destination }`）。
pub async fn relay_with<R, W>(
    reader: R,
    mut writer: W,
    config: PoolConfig,
    idle: Duration,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if idle.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    let pool = UdpPool::new(config)?;
    let mut frames = FrameReader::new(reader);

    loop {
        tokio::select! {
            // 回程优先：先写回已到达的回程，再读新的请求。
            biased;
            inbound = pool.recv() => {
                let Some(inbound) = inbound else {
                    // 回程通道关闭（池被关闭）：按参考语义结束整条关联。
                    return Ok(());
                };
                let reply = encode_packet(&inbound.address, &inbound.payload)
                    .map_err(Error::Frame)?;
                // 参考：回程写回失败 ⇒ `cancel()` 整个会话。
                timeout(idle, async {
                    writer.write_all(&reply).await?;
                    writer.flush().await
                })
                .await
                .map_err(|_| Error::Timeout)??;
            }
            frame = frames.next_frame(config.payload_limit, idle) => {
                let Some((target, payload)) = frame? else {
                    // 客户端读侧干净结束：关闭池（释放全部出站 socket）。
                    pool.close().await;
                    return Ok(());
                };
                pool.dispatch(&target, &payload).await?;
            }
        }
    }
}

/// 读侧一次性收尾：把 `reader` 读到 EOF（用于产品侧的优雅收尾），带空闲截止。
pub async fn drain_to_eof<R: AsyncRead + Unpin>(
    reader: &mut R,
    idle: Duration,
) -> Result<(), Error> {
    if idle.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    let mut sink = [0u8; 2048];
    loop {
        let read = timeout(idle, reader.read(&mut sink))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;
        if read == 0 {
            return Ok(());
        }
    }
}
