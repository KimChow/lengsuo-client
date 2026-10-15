//! 有截止时间的基础握手与 UDP 帧；传入流必须由调用方完成安全传输认证。
//! 请求发送与响应读取分离，允许首批应用数据随请求发送，避免等待响应死锁。
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
