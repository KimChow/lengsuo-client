//! ss2022（SIP022）出站会话：TCP → 请求流开场（真实目标）→ 响应流 salt 归属校验。
//!
//! 不复用 `outbound_ss2022::dial_ss2022`：它把 `b"lengsuo-node-dryrun"` 写进
//! 请求流的**变长头首批载荷**，那些字节会先于业务载荷到达目标，破坏
//! 「业务载荷逐字节原样往返」的断言。这里首批载荷留空，改用**随机 padding**
//! 满足 SIP022「变长头的载荷与 padding 至少一个非零」。
//!
//! 归属校验：响应流固定头**原样回传请求 salt**，是客户端判定「这条流属于我的
//! 那次请求」的唯一依据（对齐参考 `proxy/ss2022` 与 SIP022 §3.1.3）。

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use lengsuo_ss2022::crypto::Key;
use lengsuo_ss2022::tcp::receive::{clock_at, Association, Reader, SessionReplay};
use lengsuo_ss2022::tcp::{Direction, Writer};
use ss_core::target::TargetAddr;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use super::{LiveSession, OutboundReader, OutboundWriter, SessionError};
use crate::config::NodeConfig;
use crate::outbound::connect_tcp;

/// 变长头 padding 长度（SIP022 允许 0..=900；取 64 以满足「不得为空壳」）。
const PADDING_LEN: u16 = 64;
/// 本端请求 salt 的记忆保留期（SIP022 §3.1.4 最短 60 秒）。
const REPLAY_RETENTION: Duration = Duration::from_secs(60);

/// 建立 ss2022 出站会话并返回可转发的读 / 写两半。
pub(super) async fn open(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
) -> Result<LiveSession, SessionError> {
    let method = crate::outbound_ss2022::method_from_name(node.method.as_deref())?;
    let psk = psk_from_config(node, method)?;
    let key = Key::new(method, &psk)?;
    let stream = connect_tcp(node, wait).await?;
    let (mut read, mut write) = tokio::io::split(stream);

    // 请求流开场：salt 随机，时间戳取当前系统时间；变长头只带地址 + padding。
    let mut writer = Writer::random(&key, Direction::Request)?;
    writer
        .write_request_header(
            &mut write,
            target,
            &[],
            crate::outbound_ss2022::now_secs(),
            PADDING_LEN,
        )
        .await?;
    let request_salt = writer.salt().to_vec();

    // 响应流开场：固定头必须回带本端请求 salt，否则不是这条流的响应。
    let mut reader = Reader::new(key.clone(), Direction::Response, wait)?;
    let mut replay = SessionReplay::new(REPLAY_RETENTION)?;
    let mut opened = reader
        .open(
            &mut read,
            &mut replay,
            clock_at(crate::outbound_ss2022::now_secs(), Instant::now()),
            Some(&request_salt),
        )
        .await?;
    match &opened.association {
        Association::Response(salt) if salt == &request_salt => {}
        _ => return Err(SessionError::Ss2022(lengsuo_ss2022::Error::SessionPolicy)),
    }

    Ok(LiveSession {
        reader: Box::new(Ss2022Reader {
            reader,
            half: read,
            pending: std::mem::take(&mut opened.payload),
        }),
        writer: Box::new(Ss2022Writer {
            writer,
            half: write,
        }),
    })
}

/// PSK：SIP022 要求 base64 且长度等于方法密钥长度。
fn psk_from_config(
    node: &NodeConfig,
    method: lengsuo_ss2022::crypto::Method,
) -> Result<Vec<u8>, SessionError> {
    let raw = node.auth.secret_key.as_deref().ok_or_else(|| {
        crate::outbound::DialError::Rejected("ss2022 缺少 auth.secret_key".to_owned())
    })?;
    let decoded = crate::outbound_ss2022::base64_decode_public(raw).ok_or_else(|| {
        crate::outbound::DialError::Rejected("ss2022 PSK 不是合法 base64".to_owned())
    })?;
    if decoded.len() != method.key_len() {
        return Err(crate::outbound::DialError::Rejected(format!(
            "ss2022 PSK 长度 {} 字节，方法要求 {} 字节",
            decoded.len(),
            method.key_len()
        ))
        .into());
    }
    Ok(decoded)
}

/// ss2022 读侧：AEAD chunk 解密（响应方向）。
struct Ss2022Reader {
    reader: Reader,
    half: ReadHalf<TcpStream>,
    /// 服务端首批载荷（已在响应流开场里读到，先交付它）。
    pending: Vec<u8>,
}

impl OutboundReader for Ss2022Reader {
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
            let Self { reader, half, .. } = self;
            match reader
                .read_payload(half)
                .await
                .map_err(SessionError::Ss2022)?
            {
                Some(chunk) => {
                    let take = chunk.len().min(buf.len());
                    buf[..take].copy_from_slice(&chunk[..take]);
                    Ok(take)
                }
                // 终止 chunk：服务端方向到此为止。
                None => Ok(0),
            }
        })
    }
}

/// ss2022 写侧：AEAD chunk 加密（请求方向）。
struct Ss2022Writer {
    writer: Writer,
    half: WriteHalf<TcpStream>,
}

impl OutboundWriter for Ss2022Writer {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
        _wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        Box::pin(async move {
            let Self { writer, half, .. } = self;
            writer
                .write_payload(half, payload)
                .await
                .map_err(SessionError::Ss2022)
        })
    }

    fn half_close<'a>(
        &'a mut self,
        _wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        // 终止 chunk：请求方向到此为止，回程仍可继续收。
        Box::pin(async move {
            let Self { writer, half, .. } = self;
            writer
                .write_finish(half)
                .await
                .map_err(SessionError::Ss2022)
        })
    }
}
