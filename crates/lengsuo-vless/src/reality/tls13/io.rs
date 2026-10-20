//! TLS 1.3 客户端/服务端的**异步驱动**（记录层收发 + 握手消息编排）。
//!
//! 本模块把 [`super::handshake`]（纯消息）与 [`super::record`]（纯记录层）
//! 接到 `tokio` 的字节流上。对齐参考：
//!
//! * 客户端：`xtls/reality` `handshake_client_tls13.go` 的
//!   `readServerParameters` / `readServerCertificate` / `readServerFinished`
//!   / `sendClientFinished`。
//! * 服务端：`xtls/reality` `handshake_server_tls13.go` 的
//!   `sendServerParameters` / `sendServerCertificate` / `sendServerFinished`
//!   / `readClientFinished`。
//!
//! # 记录层分阶段
//!
//! TLS 1.3 的密钥是**分阶段**的：握手流量密钥只用于握手阶段密文，
//! 应用流量密钥用于其后的应用数据。因此每个方向要维护两个记录层实例，
//! 按阶段切换。

use std::collections::VecDeque;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::handshake::{HandshakeError, Transcript};
use super::messages::{handshake_type, parse_handshake};
use super::record::{content_type, RecordError, RecordLayer};

/// I/O 层的错误。
#[derive(Debug, thiserror::Error)]
pub enum IoError {
    /// 底层 I/O 失败。
    #[error("TLS io: {0}")]
    Io(#[from] std::io::Error),
    /// 握手层错误。
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    /// 记录层错误。
    #[error(transparent)]
    Record(#[from] RecordError),
    /// 超时。
    #[error("TLS io: timeout")]
    Timeout,
    /// 对端发来 `alert` 记录。
    #[error("TLS io: peer alert {0}")]
    Alert(u8),
}

impl From<crate::reality::client::ClientError> for IoError {
    /// 客户端状态机的错误降级成记录层错误。
    ///
    /// 握手驱动在记录层里跑，需要统一的错误类型才能用 `?` 传播。
    /// 语义保留在 `Handshake` / `Record` 变体里。
    fn from(error: crate::reality::client::ClientError) -> Self {
        match error {
            crate::reality::client::ClientError::Handshake(error) => Self::Handshake(error),
            crate::reality::client::ClientError::Record(error) => Self::Record(error),
            other => Self::Handshake(HandshakeError::Io(other.to_string())),
        }
    }
}

impl From<crate::reality::tls13::server::ServerHandshakeError> for IoError {
    /// 服务端状态机的错误降级成记录层错误。
    fn from(error: crate::reality::tls13::server::ServerHandshakeError) -> Self {
        match error {
            crate::reality::tls13::server::ServerHandshakeError::Handshake(error) => {
                Self::Handshake(error)
            }
            crate::reality::tls13::server::ServerHandshakeError::Record(error) => {
                Self::Record(error)
            }
            other => Self::Handshake(HandshakeError::Io(other.to_string())),
        }
    }
}

/// 一条待发送的记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// 明文握手记录（内容类型 `handshake`，未加密）。
    PlainHandshake(Vec<u8>),
    /// 明文 `change_cipher_spec` 兼容记录。
    PlainChangeCipherSpec,
    /// 加密后的握手记录。
    EncryptedHandshake(Vec<u8>),
    /// 加密后的应用数据记录。
    EncryptedApplication(Vec<u8>),
}

/// 收到的记录类别。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    /// 明文握手记录。
    PlainHandshake(Vec<u8>),
    /// 明文 `change_cipher_spec`（忽略）。
    PlainChangeCipherSpec,
    /// 加密记录（尚未解封）。
    Encrypted(Vec<u8>),
}

/// 记录层驱动器：负责把字节流切成记录、把记录转成 [`Inbound`]。
///
/// 明文阶段（ServerHello 之前/之后的首条）直接透传；进入加密阶段后，
/// 记录由 [`RecordLayer`] 解封。
pub struct RecordReader {
    /// 加密阶段的读记录层（`None` = 仍是明文阶段）。
    cipher: Option<RecordLayer>,
    /// 解封后的明文缓冲。
    decrypted: VecDeque<u8>,
}

impl RecordReader {
    /// 新建明文阶段的读记录器。
    pub fn new() -> Self {
        Self {
            cipher: None,
            decrypted: VecDeque::new(),
        }
    }

    /// 切换到加密阶段。
    pub fn enable_cipher(&mut self, layer: RecordLayer) {
        self.cipher = Some(layer);
    }

    /// 从字节流里取出一条记录。
    ///
    /// 返回 `None` 表示需要更多字节。
    ///
    /// **加密阶段的明文 `change_cipher_spec`**：TLS 1.3 的
    /// `change_cipher_spec` 兼容记录**永远不加密**。对端按参考
    /// （`xtls/reality` 的 `sendDummyChangeCipherSpec`）在 ServerHello
    /// 之后才发它，而本端的记录层在 ServerHello 之后才切到加密阶段，
    /// 于是这条记录会落在加密阶段被读到。此处按内容类型识别并**跳过**，
    /// 不做 AEAD 解封（否则会因长度不足而误报 `MalformedHeader`）。
    pub async fn next_record<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Inbound>, IoError> {
        loop {
            let mut header = [0u8; 5];
            if !self.read_plain(reader, &mut header).await? {
                return Ok(None);
            }
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let mut body = vec![0u8; length];
            if !self.read_plain(reader, &mut body).await? {
                return Ok(None);
            }
            if let Some(layer) = self.cipher.as_mut() {
                if header[0] == content_type::CHANGE_CIPHER_SPEC {
                    // 明文兼容记录：丢弃后继续读下一条。
                    continue;
                }
                let mut record = header.to_vec();
                record.extend_from_slice(&body);
                let (kind, payload) = layer.open(&record)?;
                if kind == content_type::ALERT {
                    return Err(IoError::Alert(payload.first().copied().unwrap_or(0)));
                }
                self.decrypted.extend(payload);
                // 把解封后的明文按「内容类型 + 载荷」交给上层。
                let mut framed = vec![kind];
                framed.extend(self.decrypted.drain(..));
                return Ok(Some(Inbound::Encrypted(framed)));
            }
            // 明文阶段。
            return match header[0] {
                content_type::HANDSHAKE => Ok(Some(Inbound::PlainHandshake(body))),
                content_type::CHANGE_CIPHER_SPEC => Ok(Some(Inbound::PlainChangeCipherSpec)),
                content_type::ALERT => Err(IoError::Alert(body.first().copied().unwrap_or(0))),
                _ => Ok(Some(Inbound::PlainHandshake(body))),
            };
        }
    }

    /// 读满 `buffer`；返回 `false` 表示流已结束。
    async fn read_plain<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        buffer: &mut [u8],
    ) -> Result<bool, IoError> {
        let mut filled = 0;
        while filled < buffer.len() {
            let read = reader.read(&mut buffer[filled..]).await?;
            if read == 0 {
                return Ok(false);
            }
            filled += read;
        }
        Ok(true)
    }
}

impl Default for RecordReader {
    fn default() -> Self {
        Self::new()
    }
}

/// 记录层写入器：把 [`Outbound`] 写进字节流。
pub struct RecordWriter {
    /// 加密阶段的写记录层（`None` = 仍是明文阶段）。
    cipher: Option<RecordLayer>,
}

impl RecordWriter {
    /// 新建明文阶段的写记录器。
    pub fn new() -> Self {
        Self { cipher: None }
    }

    /// 切换到加密阶段。
    pub fn enable_cipher(&mut self, layer: RecordLayer) {
        self.cipher = Some(layer);
    }

    /// 是否已进入加密阶段。
    pub fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    /// 写一条记录。
    pub async fn write<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        outbound: &Outbound,
    ) -> Result<(), IoError> {
        match outbound {
            Outbound::PlainHandshake(payload) => {
                let record = plain_record(content_type::HANDSHAKE, payload);
                writer.write_all(&record).await?;
            }
            Outbound::PlainChangeCipherSpec => {
                let record = plain_record(content_type::CHANGE_CIPHER_SPEC, &[1]);
                writer.write_all(&record).await?;
            }
            Outbound::EncryptedHandshake(payload) => {
                let layer = self
                    .cipher
                    .as_mut()
                    .ok_or(IoError::Handshake(HandshakeError::UnexpectedStep))?;
                let record = layer.seal_handshake(payload)?;
                writer.write_all(&record).await?;
            }
            Outbound::EncryptedApplication(payload) => {
                let layer = self
                    .cipher
                    .as_mut()
                    .ok_or(IoError::Handshake(HandshakeError::UnexpectedStep))?;
                let record = layer.seal_application(payload)?;
                writer.write_all(&record).await?;
            }
        }
        writer.flush().await?;
        Ok(())
    }
}

impl Default for RecordWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// 构造一条明文记录头 + 载荷。
fn plain_record(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(kind);
    record.extend_from_slice(&0x0303u16.to_be_bytes());
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

/// 握手消息的收集器：把记录层的字节流切成握手消息。
#[derive(Debug, Default)]
pub struct HandshakeCollector {
    buffer: Vec<u8>,
}

impl HandshakeCollector {
    /// 新建收集器。
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂入一段字节。
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// 取出一条完整握手消息（含 4 字节头）。
    pub fn take(&mut self) -> Result<Option<Vec<u8>>, HandshakeError> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([0, self.buffer[1], self.buffer[2], self.buffer[3]]) as usize;
        if self.buffer.len() < 4 + len {
            return Ok(None);
        }
        let message = self.buffer[..4 + len].to_vec();
        self.buffer.drain(..4 + len);
        Ok(Some(message))
    }
}

/// 从握手消息字节里取出类型与载荷。
pub fn split_message(message: &[u8]) -> Result<(u8, &[u8]), HandshakeError> {
    let (kind, payload, _) = parse_handshake(message)?;
    Ok((kind, payload))
}

/// 握手消息类型常量（供调用方判断）。
pub const TYPE_FINISHED: u8 = handshake_type::FINISHED;

/// 超时包装：所有网络操作都必须有截止时间（卡片硬约束）。
pub async fn with_deadline<F, T>(duration: Duration, future: F) -> Result<T, IoError>
where
    F: std::future::Future<Output = Result<T, IoError>>,
{
    match tokio::time::timeout(duration, future).await {
        Ok(result) => result,
        Err(_) => Err(IoError::Timeout),
    }
}

/// 便捷函数：一次读完一条**明文**握手记录。
pub async fn read_plain_handshake<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> Result<Vec<u8>, IoError> {
    let mut header = [0u8; 5];
    reader.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;
    buffer.extend_from_slice(&body);
    Ok(body)
}

/// 便捷函数：写一条**明文**握手记录。
pub async fn write_plain_handshake<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), IoError> {
    let record = plain_record(content_type::HANDSHAKE, payload);
    writer.write_all(&record).await?;
    writer.flush().await?;
    Ok(())
}

/// 便捷函数：写一条**明文** `change_cipher_spec` 记录。
pub async fn write_plain_change_cipher_spec<W: AsyncWrite + Unpin>(
    writer: &mut W,
) -> Result<(), IoError> {
    let record = plain_record(content_type::CHANGE_CIPHER_SPEC, &[1]);
    writer.write_all(&record).await?;
    writer.flush().await?;
    Ok(())
}

/// 便捷函数：从记录层解出内容类型与载荷。
pub fn unpack(record: &[u8]) -> Result<(u8, &[u8]), IoError> {
    if record.is_empty() {
        return Err(IoError::Handshake(HandshakeError::MalformedMessage));
    }
    Ok((record[0], &record[1..]))
}

/// 转录哈希的薄封装（供调用方在关键点取快照）。
pub fn transcript_hash(transcript: &Transcript) -> [u8; 32] {
    transcript.hash()
}
