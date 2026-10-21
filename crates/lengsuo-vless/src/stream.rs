//! 有截止时间的基础握手与 UDP 帧；传入流必须由调用方完成安全传输认证。
//! 请求发送与响应读取分离，允许首批应用数据随请求发送，避免等待响应死锁。
//!
//! ## VLESS 响应头的两种读法
//!
//! 参考 `proxy/vless/encoding/encoding.go` 的 `EncodeResponseHeader` 写出的是
//! **1 字节 version ＋ `EncodeHeaderAddons` 的 1 字节 addons 长度**（＋ 长度非 0
//! 时的 addons 载荷）。`EncodeHeaderAddons`（`encoding/addons.go:18`）只在
//! `Flow == XRV` 时写非 0 长度，而参考入站的响应固定用空 `Addons`
//! （`inbound.go:546` 的 `responseAddons` 未设 `Flow`）⇒ **线上响应头恒为
//! 2 字节 `00 00`**。
//!
//! - [`receive_response`]：**严格** 2 字节形态（version 0 ＋ addons 长度 0），
//!   多一个字节都不接受；用于普通 TCP/UDP 链路。
//! - [`receive_response_header`]：**通用**形态，按 addons 长度消费载荷；用于
//!   mux 承载连接（响应头与 mux 帧同属一条字节流，见 [`crate::mux_wire`]）。
use crate::header::{self, Request};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("协议字段无效：{0}")]
    Header(#[from] header::Error),
    #[error("认证失败")]
    Authentication,
    #[error("协议操作超时")]
    Timeout,
    #[error("截止时间必须大于零")]
    InvalidDeadline,
    #[error("数据帧长度超过限制")]
    FrameTooLarge,
    #[error("流操作失败：{0}")]
    Io(#[from] std::io::Error),
}

fn deadline(duration: Duration) -> Result<(), Error> {
    if duration.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    Ok(())
}

pub async fn send_request<W: AsyncWrite + Unpin>(
    stream: &mut W,
    request: &Request,
    credential: &[u8; 16],
    duration: Duration,
) -> Result<(), Error> {
    deadline(duration)?;
    let bytes = header::encode(request, credential)?;
    timeout(duration, async {
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(())
}

/// 单个已配置用户；凭据比较为常量时间，失败不返回请求或发送成功响应。
/// 不缓存或记录凭据，返回请求不包含用户标识。
pub async fn receive_request<R: AsyncRead + Unpin>(
    stream: &mut R,
    credential: &[u8; 16],
    duration: Duration,
) -> Result<Request, Error> {
    deadline(duration)?;
    timeout(duration, async {
        let mut prefix = [0; 17];
        stream.read_exact(&mut prefix).await?;
        if prefix[0] != 0 {
            return Err(header::Error::Unsupported.into());
        }
        if !bool::from(prefix[1..].ct_eq(credential)) {
            return Err(Error::Authentication);
        }
        let mut bytes = prefix.to_vec();
        loop {
            match header::decode(&bytes) {
                Ok((_, request, _)) => return Ok(request),
                Err(header::Error::Incomplete) => bytes.push(stream.read_u8().await?),
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
    .map_err(|_| Error::Timeout)?
}

/// 只有在认证通过且目标连接建立后才发送成功头。
pub async fn send_response<W: AsyncWrite + Unpin>(
    stream: &mut W,
    duration: Duration,
) -> Result<(), Error> {
    deadline(duration)?;
    timeout(duration, async {
        stream.write_all(&[0, 0]).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(())
}

pub async fn receive_response<R: AsyncRead + Unpin>(
    stream: &mut R,
    duration: Duration,
) -> Result<(), Error> {
    deadline(duration)?;
    timeout(duration, async {
        let mut bytes = [0; 2];
        stream.read_exact(&mut bytes).await?;
        if bytes != [0, 0] {
            return Err(header::Error::Unsupported.into());
        }
        Ok(())
    })
    .await
    .map_err(|_| Error::Timeout)?
}

/// VLESS 响应头（参考 `encoding.EncodeResponseHeader` 的产物）。
///
/// 线上形态：`1 字节 version ‖ 1 字节 addons 长度 ‖ addons 载荷`。
/// `addons` 载荷只在参考的 `Flow == XRV` 时非 0（`encoding/addons.go:18`），
/// 而参考入站的响应固定用空 `Addons` ⇒ 线上响应头恒为 `00 00`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHeader {
    /// 响应版本字节（参考 `request.Version`，线上为 0）。
    pub version: u8,
    /// addons 载荷长度（参考 `EncodeHeaderAddons` 写的那个长度字节）。
    pub addons: u8,
}

/// 读 VLESS 响应头并按 addons 长度消费载荷（参考 `DecodeResponseHeader`）。
///
/// 与 [`receive_response`] 的差别：**不要求** version/addons 为 0，而是按参考
/// `DecodeResponseHeader` 的通用形态消费——version 必须等于请求的 version（线上
/// 为 0），addons 长度字节决定后续还要读多少字节的载荷。
///
/// 用途：mux 承载连接上，响应头与 mux 帧流是**同一条字节流**；必须先消费掉
/// 响应头再解帧，且不能因为「后面还有帧」而多读/少读。详见 [`crate::mux_wire`]。
pub async fn receive_response_header<R: AsyncRead + Unpin>(
    stream: &mut R,
    duration: Duration,
) -> Result<ResponseHeader, Error> {
    deadline(duration)?;
    timeout(duration, async {
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await?;
        let version = prefix[0];
        if version != 0 {
            return Err(header::Error::Unsupported.into());
        }
        let addons_len = prefix[1];
        if addons_len > 0 {
            // 参考 `DecodeHeaderAddons`：按长度字节读满 addons 载荷。
            let mut payload = vec![0u8; usize::from(addons_len)];
            stream.read_exact(&mut payload).await?;
        }
        Ok(ResponseHeader {
            version,
            addons: addons_len,
        })
    })
    .await
    .map_err(|_| Error::Timeout)?
}

/// 每个数据报使用独立的两字节大端长度，不合并不同数据报。
pub async fn send_datagram<W: AsyncWrite + Unpin>(
    stream: &mut W,
    packet: &[u8],
    duration: Duration,
) -> Result<(), Error> {
    deadline(duration)?;
    let length = u16::try_from(packet.len()).map_err(|_| Error::FrameTooLarge)?;
    timeout(duration, async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(packet).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(())
}

/// 上层指定容量限制，在分配和读取载荷前检查。
pub async fn receive_datagram<R: AsyncRead + Unpin>(
    stream: &mut R,
    limit: u16,
    duration: Duration,
) -> Result<Vec<u8>, Error> {
    deadline(duration)?;
    timeout(duration, async {
        let length = stream.read_u16().await?;
        if length > limit {
            return Err(Error::FrameTooLarge);
        }
        let mut bytes = vec![0; length as usize];
        stream.read_exact(&mut bytes).await?;
        Ok(bytes)
    })
    .await
    .map_err(|_| Error::Timeout)?
}
