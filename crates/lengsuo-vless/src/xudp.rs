//! XUDP 单连接单会话帧；不跨连接复用 global ID，禁止跨环境共享会话。
//! 参考基线与 header 模块一致；通用 TCP Mux 不属于本模块。
use crate::{
    header::{self},
    stream::Error,
};
use ss_core::target::TargetAddr;
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

/// 会话 ID 固定为零。其他会话、TCP 类型或不支持的状态均拒绝。
/// 一个实例只绑定一条已认证连接，不得在不同浏览器环境之间复用。
pub struct Session {
    client: bool,
    sent: bool,
    received: bool,
    target: Option<TargetAddr>,
}

impl Session {
    pub fn client(target: TargetAddr) -> Self {
        Self {
            client: true,
            sent: false,
            received: false,
            target: Some(target),
        }
    }
    pub fn server() -> Self {
        Self {
            client: false,
            sent: false,
            received: false,
            target: None,
        }
    }

    pub async fn send<W: AsyncWrite + Unpin>(
        &mut self,
        stream: &mut W,
        packet: &[u8],
        wait: Duration,
    ) -> Result<(), Error> {
        if wait.is_zero() {
            return Err(Error::InvalidDeadline);
        }
        let length = u16::try_from(packet.len()).map_err(|_| Error::FrameTooLarge)?;
        if length == 0 {
            return Err(Error::FrameTooLarge);
        }
        let target = self.target.as_ref().ok_or(header::Error::Unsupported)?;
        let mut metadata = vec![0, 0, if self.client && !self.sent { 1 } else { 2 }, 1, 2];
        header::encode_address(target, &mut metadata)?;
        let mut bytes = Vec::with_capacity(metadata.len() + packet.len() + 4);
        bytes.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&metadata);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(packet);
        timeout(wait, async {
            stream.write_all(&bytes).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| Error::Timeout)??;
        self.sent = true;
        Ok(())
    }

    /// 在容量限制内读取一个数据报；结束帧、异常标志和会话混用都返回失败。
    pub async fn receive<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
        limit: u16,
        wait: Duration,
    ) -> Result<(TargetAddr, Vec<u8>), Error> {
        if wait.is_zero() {
            return Err(Error::InvalidDeadline);
        }
        timeout(wait, async {
            let length = stream.read_u16().await? as usize;
            if !(4..=300).contains(&length) {
                return Err(header::Error::Unsupported.into());
            }
            let mut meta = vec![0; length];
            stream.read_exact(&mut meta).await?;
            if meta[..2] != [0, 0] || meta[3] != 1 {
                return Err(header::Error::Unsupported.into());
            }
            let new = meta[2] == 1;
            if (new && (self.client || self.received))
                || (!new && meta[2] != 2)
                || (!new && !self.client && !self.received)
            {
                return Err(header::Error::Unsupported.into());
            }
            let target = if length > 4 {
                if meta[4] != 2 {
                    return Err(header::Error::Unsupported.into());
                }
                let (target, consumed) = header::decode_address(&meta[5..])?;
                let remaining = length - 5 - consumed;
                if remaining != 0 && !(new && remaining == 8) {
                    return Err(header::Error::Unsupported.into());
                }
                target
            } else {
                if new {
                    return Err(header::Error::Unsupported.into());
                }
                self.target.clone().ok_or(header::Error::Unsupported)?
            };
            let length = stream.read_u16().await?;
            if length == 0 || length > limit {
                return Err(Error::FrameTooLarge);
            }
            let mut packet = vec![0; length as usize];
            stream.read_exact(&mut packet).await?;
            self.target = Some(target.clone());
            self.received = true;
            Ok((target, packet))
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}
