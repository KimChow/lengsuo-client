//! shadowsocks 出站会话：TCP → 写首段明文（真实目标地址）→ AEAD chunk 流。
//!
//! 首段明文**只含地址**：SS 线格式要求地址在前、载荷随后，地址与首批载荷
//! 同批到达时服务端会把余量当载荷——这里首批载荷为空，避免多写一次。
//!
//! 参考：`proxy/shadowsocks/client.go` 的 `Process` —— 写完 salt + 目标地址
//! 后把连接交给转发循环。

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use lengsuo_shadowsocks::{TcpReader, TcpWriter};
use ss_core::target::TargetAddr;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use super::{LiveSession, OutboundReader, OutboundWriter, SessionError};
use crate::config::NodeConfig;
use crate::outbound::connect_tcp;

/// 建立 shadowsocks 出站会话并返回可转发的读 / 写两半。
pub(super) async fn open(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
) -> Result<LiveSession, SessionError> {
    let suite = crate::outbound_ss::suite_from_method(node.method.as_deref())?;
    let password = node.auth.secret_key.as_deref().ok_or_else(|| {
        crate::outbound::DialError::Rejected("shadowsocks 缺少 auth.secret_key".to_owned())
    })?;
    let stream = connect_tcp(node, wait).await?;
    let (read, write) = tokio::io::split(stream);
    let mut writer = TcpWriter::new(write, suite, password.as_bytes(), wait)?;
    let reader = TcpReader::new(read, suite, password.as_bytes(), wait)?;
    let mut head = Vec::new();
    target
        .encode_checked(&mut head)
        .map_err(|err| crate::outbound::DialError::Resolve(format!("目标地址编码失败：{err}")))?;
    writer.send(&head).await?;
    Ok(LiveSession {
        reader: Box::new(ShadowsocksReader {
            reader: Box::new(reader),
            pending: Vec::new(),
        }),
        writer: Box::new(ShadowsocksWriter { writer }),
    })
}

/// shadowsocks 读侧：AEAD chunk 解密读端（可能多出余量）。
struct ShadowsocksReader {
    /// 解密读端。
    reader: Box<TcpReader<ReadHalf<TcpStream>>>,
    /// 上一次解出的 chunk 里没被本次读走的余量。
    pending: Vec<u8>,
}

impl OutboundReader for ShadowsocksReader {
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        _wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<usize, SessionError>> + Send + 'a>> {
        Box::pin(async move {
            if !self.pending.is_empty() {
                let take = self.pending.len().min(buf.len());
                buf[..take].copy_from_slice(&self.pending[..take]);
                self.pending.drain(..take);
                return Ok(take);
            }
            match self.reader.recv().await? {
                Some(chunk) => {
                    let take = chunk.len().min(buf.len());
                    buf[..take].copy_from_slice(&chunk[..take]);
                    if take < chunk.len() {
                        self.pending.extend_from_slice(&chunk[take..]);
                    }
                    Ok(take)
                }
                None => Ok(0),
            }
        })
    }
}

/// shadowsocks 写侧：AEAD chunk 加密写端。
struct ShadowsocksWriter {
    writer: TcpWriter<WriteHalf<TcpStream>>,
}

impl OutboundWriter for ShadowsocksWriter {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
        _wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        Box::pin(async move { self.writer.send(payload).await.map_err(SessionError::from) })
    }

    fn half_close<'a>(
        &'a mut self,
        _wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        // `TcpWriter::shutdown` 写终止 chunk 并 flush 写侧；读侧仍可继续收数据。
        Box::pin(async move { self.writer.shutdown().await.map_err(SessionError::from) })
    }
}
