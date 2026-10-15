//! 认证消息必须在经过身份验证的 TLS 连接中发送；禁止日志输出密码或摘要。
use crate::Error;
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

pub struct Credential([u8; 32]);
impl Credential {
    pub fn new(password: &[u8]) -> Self {
        Self(Sha256::digest(password).into())
    }

    pub async fn send<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        padding: &[u8],
        wait: Duration,
    ) -> Result<(), Error> {
        if wait.is_zero() {
            return Err(Error::Invalid);
        }
        let length = u16::try_from(padding.len()).map_err(|_| Error::TooLarge)?;
        timeout(wait, async {
            stream.write_all(&self.0).await?;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(padding).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| Error::Timeout)??;
        Ok(())
    }

    /// 先完整读取容量内的 padding，再认证；超容量时立即拒绝并要求调用方关闭连接。
    pub async fn verify<R: AsyncRead + Unpin>(
        &self,
        stream: &mut R,
        max_padding: u16,
        wait: Duration,
    ) -> Result<(), Error> {
        if wait.is_zero() {
            return Err(Error::Invalid);
        }
        timeout(wait, async {
            let mut received = [0; 32];
            stream.read_exact(&mut received).await?;
            let length = stream.read_u16().await?;
            if length > max_padding {
                return Err(Error::TooLarge);
            }
            let mut remaining = length as usize;
            let mut scratch = [0; 1024];
            while remaining > 0 {
                let size = remaining.min(scratch.len());
                stream.read_exact(&mut scratch[..size]).await?;
                remaining -= size;
            }
            if !bool::from(received.ct_eq(&self.0)) {
                return Err(Error::Authentication);
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}
