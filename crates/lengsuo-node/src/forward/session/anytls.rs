//! anytls 出站会话：TLS + 认证 → Settings → SYN → PUSH(目标地址) → 帧中继。
//!
//! 协议要点（对齐 anytls-go `proxy/session/session.go` 客户端分支，与仓内
//! `lengsuo-anytls` 服务端 `server/session.rs` / `server/streams.rs` 配对）：
//!
//! - **目标地址不在 SYN 里**：服务端把流内**首个 PUSH 的载荷前段**当作 SOCKS5
//!   地址解析（`Stream::take_endpoint` → `TargetAddr::decode`），地址之后的字节
//!   才是业务载荷。因此客户端先发 SYN（空载荷），再发一条只含地址的 PUSH。
//! - **v2 下数据不得早于 SYNACK**：`ClientState::push` 对未 acked 的流直接拒绝，
//!   所以 `open` 在这里等 SYNACK——它同时是「服务端已为该目标建连」的正向证据
//!   （带错误文本的 SYNACK ⇒ 目标拨号失败 ⇒ fail-closed）。
//! - 发送方向 EOF 用 FIN 帧（半关闭），回程仍可继续收。
//!
//! 不硬凑跨线程共享：TLS 流 `split` 成两半，`ClientState`（只服务读方向）随读侧走。

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use lengsuo_anytls::client_state::{ClientState, Event};
use lengsuo_anytls::frame::{Command as AnyTlsCommand, Frame};
use ss_core::target::TargetAddr;
use tokio::io::{ReadHalf, WriteHalf};

use super::{LiveSession, OutboundReader, OutboundWriter, SessionError};
use crate::config::NodeConfig;
use crate::outbound::{dial_anytls, DialError, NodeTlsStream};

/// `open` 阶段等待 SYNACK 时最多处理的帧数（防对端用 Waste 帧无限拖住握手）。
const MAX_HANDSHAKE_FRAMES: usize = 64;

/// 建立 anytls 出站会话并返回可转发的读 / 写两半。
pub(super) async fn open(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
) -> Result<LiveSession, SessionError> {
    let outbound = dial_anytls(node, wait).await?;
    let mut state = outbound.state;
    let stream_id = state
        .open_stream()
        .map_err(|err| SessionError::AnyTlsState(err.to_string()))?;
    let (mut read, mut write) = tokio::io::split(outbound.stream);

    Frame {
        command: AnyTlsCommand::Syn,
        stream_id,
        data: Vec::new(),
    }
    .write(&mut write, wait)
    .await?;

    let mut address = Vec::new();
    target
        .encode_checked(&mut address)
        .map_err(|err| DialError::Resolve(format!("anytls 目标地址编码失败：{err}")))?;
    Frame {
        command: AnyTlsCommand::Push,
        stream_id,
        data: address,
    }
    .write(&mut write, wait)
    .await?;

    // 等 SYNACK（成功 = 空载荷；带文本 = 服务端拨号失败）。
    let mut pending: Vec<u8> = Vec::new();
    let mut acked = false;
    for _ in 0..MAX_HANDSHAKE_FRAMES {
        let frame = Frame::read(&mut read, u16::MAX, wait).await?;
        let event = state
            .accept(&frame)
            .map_err(|err| SessionError::AnyTlsState(err.to_string()))?;
        match event {
            Event::Ready(id) if id == stream_id => {
                acked = true;
                break;
            }
            Event::Rejected(id) if id == stream_id => {
                return Err(SessionError::AnyTlsState(format!(
                    "服务端拒绝流 {id}：{}",
                    String::from_utf8_lossy(&frame.data)
                )))
            }
            Event::Data(id) if id == stream_id => pending.extend_from_slice(&frame.data),
            Event::Alert => {
                return Err(SessionError::AnyTlsState(format!(
                    "服务端 Alert：{}",
                    String::from_utf8_lossy(&frame.data)
                )))
            }
            _ => {}
        }
    }
    if !acked {
        return Err(SessionError::AnyTlsState(
            "握手阶段帧数超限，未收到 SYNACK".to_owned(),
        ));
    }

    Ok(LiveSession {
        reader: Box::new(AnyTlsReader {
            half: read,
            state,
            stream_id,
            pending,
        }),
        writer: Box::new(AnyTlsWriter {
            half: write,
            stream_id,
        }),
    })
}

/// anytls 读侧：解帧后交出 PUSH 载荷。
struct AnyTlsReader {
    half: ReadHalf<NodeTlsStream>,
    state: ClientState,
    stream_id: u32,
    /// 握手阶段已到达的载荷，先交付。
    pending: Vec<u8>,
}

impl OutboundReader for AnyTlsReader {
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<usize, SessionError>> + Send + 'a>> {
        Box::pin(async move {
            loop {
                if !self.pending.is_empty() {
                    let take = self.pending.len().min(buf.len());
                    buf[..take].copy_from_slice(&self.pending[..take]);
                    self.pending.drain(..take);
                    return Ok(take);
                }
                let frame = Frame::read(&mut self.half, u16::MAX, wait).await?;
                let event = self
                    .state
                    .accept(&frame)
                    .map_err(|err| SessionError::AnyTlsState(err.to_string()))?;
                match event {
                    Event::Data(id) if id == self.stream_id => {
                        let take = frame.data.len().min(buf.len());
                        buf[..take].copy_from_slice(&frame.data[..take]);
                        if take < frame.data.len() {
                            self.pending.extend_from_slice(&frame.data[take..]);
                        }
                        return Ok(take);
                    }
                    // 服务端 FIN：该方向结束（半关闭，不是整条会话失败）。
                    Event::Closed(id) if id == self.stream_id => return Ok(0),
                    Event::Alert => {
                        return Err(SessionError::AnyTlsState(format!(
                            "服务端 Alert：{}",
                            String::from_utf8_lossy(&frame.data)
                        )))
                    }
                    // SYNACK 重复 / Waste / padding 更新 / 心跳：读方向继续。
                    _ => continue,
                }
            }
        })
    }
}

/// anytls 写侧：把业务载荷封成 PUSH 帧，半关闭发 FIN。
struct AnyTlsWriter {
    half: WriteHalf<NodeTlsStream>,
    stream_id: u32,
}

impl OutboundWriter for AnyTlsWriter {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        Box::pin(async move {
            Frame {
                command: AnyTlsCommand::Push,
                stream_id: self.stream_id,
                data: payload.to_vec(),
            }
            .write(&mut self.half, wait)
            .await
            .map_err(SessionError::AnyTls)
        })
    }

    fn half_close<'a>(
        &'a mut self,
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        Box::pin(async move {
            Frame {
                command: AnyTlsCommand::Fin,
                stream_id: self.stream_id,
                data: Vec::new(),
            }
            .write(&mut self.half, wait)
            .await
            .map_err(SessionError::AnyTls)
        })
    }
}
