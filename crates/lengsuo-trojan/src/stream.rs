//! Trojan 异步握手与 UDP 数据报帧（原语，不是完整协议服务）。
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

use std::time::Duration;

use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::codec::{self, Request};
use crate::credential::Credential;

/// 两处 CRLF 分隔符，与 `codec` 的线上格式相同。
const CRLF: [u8; 2] = *b"\r\n";

/// 请求头最大长度：哈希 56 + CRLF 2 + 命令 1 + 最长域名地址 259 + CRLF 2。
/// 用作续读上限，避免对异常长度前缀无界缓冲。
const MAX_HEADER_LEN: usize = 56 + 2 + 1 + (1 + 1 + 255 + 2) + 2;

/// SOCKS 地址最大长度：ATYP 1 + 域名长度 1 + 域名 255 + 端口 2。
const MAX_TARGET_LEN: usize = 1 + 1 + 255 + 2;

/// 流操作错误。包装 codec、`ss_core` 与 I/O 失败，并区分超时、非法截止时间、
/// 帧超长与坏 CRLF。Display/Debug 不含密码或哈希；凭据仍受隐私策略约束。
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

/// 写出请求头。头部之后的应用载荷由调用方继续写入同一 `stream`。
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
/// 由调用方关闭连接。
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
