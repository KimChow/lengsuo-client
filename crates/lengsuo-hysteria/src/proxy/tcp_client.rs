//! 客户端侧 TCP 代理：一条 QUIC 双向流 = 一个代理连接。
//!
//! 首写内容为 `varint(0x401) + TCPRequest`（`TcpRequest::encode` 已含帧类型，
//! 与 `interConn.Write` 的 client 分支 + `WriteTCPRequest` 逐字节一致），
//! 随后读 `TCPResponse`（status/message/padding），status=0 才开始双向转发。
//! 响应帧后的字节属于目标数据，保留在 `leftover` 中不吞掉。

use crate::h3_auth;
use crate::padding::Range;
use crate::quic::HysteriaClient;
use crate::tcp::{Status, TcpRequest, TcpResponse};

use super::error::ProxyError;

/// TCPResponse 增量读取的缓冲上限：1 + 9 + 2048 + 9 + 4096 的上界。
const MAX_RESPONSE_BUFFER: usize = 8192;

/// TCP 代理流：TCPResponse 之后的 QUIC 流封装。
pub struct TcpProxyStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    leftover: Vec<u8>,
}

/// 打开到 `address`（`host:port`）的代理连接（对齐 client.go TCP 分支：
/// 写请求帧 → 读响应帧 → 成功后开始转发）。
pub async fn tcp_connect(
    client: &HysteriaClient,
    address: &str,
) -> Result<TcpProxyStream, ProxyError> {
    let (mut send, mut recv) = client.open_tcp().await?;

    // 首写：0x401 前缀 + 请求帧（padding 长度按 tcpRequestPadding [64,512)）
    let padding = h3_auth::random_padding(Range::TCP_REQUEST).into_bytes();
    let request = TcpRequest {
        address: address.to_string(),
        padding,
    }
    .encode()?;
    send.write_all(&request).await?;

    // 增量读 TCPResponse；帧后的字节留给应用读
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let response = loop {
        match TcpResponse::decode(&buf) {
            Ok((resp, consumed)) => {
                buf.drain(..consumed);
                break resp;
            }
            Err(crate::Error::Truncated { .. }) => {
                if buf.len() >= MAX_RESPONSE_BUFFER {
                    return Err(ProxyError::ResponseTooLarge);
                }
                match recv.read(&mut chunk).await? {
                    Some(n) => buf.extend_from_slice(&chunk[..n]),
                    None => return Err(ProxyError::PrematureEof),
                }
            }
            Err(e) => return Err(ProxyError::Frame(e)),
        }
    };
    if response.status != Status::Ok {
        return Err(ProxyError::Rejected(response.message));
    }
    Ok(TcpProxyStream {
        send,
        recv,
        leftover: buf,
    })
}

impl TcpProxyStream {
    /// 发送应用数据。首帧前缀逻辑已在 `tcp_connect` 完成，这里透写。
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), ProxyError> {
        self.send.write_all(buf).await?;
        Ok(())
    }

    /// 读应用数据：先消费 `leftover`（与响应帧同包到达的目标数据），
    /// 再读 QUIC 流。返回 0 表示流结束。
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, ProxyError> {
        if !self.leftover.is_empty() {
            let n = self.leftover.len().min(buf.len());
            buf[..n].copy_from_slice(&self.leftover[..n]);
            self.leftover.drain(..n);
            return Ok(n);
        }
        match self.recv.read(buf).await? {
            Some(n) => Ok(n),
            None => Ok(0),
        }
    }

    /// 半关闭（对齐 `interConn.Close`：发送侧 FIN）。
    pub fn finish(&mut self) -> Result<(), ProxyError> {
        self.send.finish()?;
        Ok(())
    }

    /// 停止接收（对齐 `interConn.Close` 的 `CancelRead(0)`）。
    pub fn stop_read(&mut self) {
        let _ = self.recv.stop(quinn::VarInt::from_u32(0));
    }
}
