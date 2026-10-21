//! 客户端侧 AnyTLS 会话（帧层 over 明文 TCP）：认证 → Settings → SYN/PUSH → 读帧。
//!
//! 半关闭用例需要两个判据，而本仓生产客户端出站尚未接线（见
//! `docs/anytls-status.md`「未实现 / 未验证」），故在测试内组装一个最小客户端：
//! 1. 客户端关写端后**读方向继续可收**，直到对端也关才 EOF；
//! 2. 读端必须区分「EOF 且缓冲空 = 干净 EOF（0 字节）」与
//!    「EOF 且残留半帧 = 协议错误（截断）」——两者不得混为一谈。
//!
//! 承载选明文 TCP：被测对象是 AnyTLS **帧/流层**的半关闭语义，帧层与传输无关
//! （TLS 装配另有 `tests/server_roundtrip.rs::tls_acceptor_serves_echo_after_handshake`
//! 覆盖）；用明文 TCP 才能精确控制「只关写端」这一原语。
//!
//! 认证块字节（[`auth_block`]）与 `Credential::send` 逐字节一致，供跨会话重放
//! 用例「录制 A 会话的字节、在 B 会话原样重放」。
use super::{default_md5, push_with_target, settings, Eof, FrameReader, WAIT};
use lengsuo_anytls::auth::Credential;
use lengsuo_anytls::frame::{Command, Frame};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 认证块字节：`SHA256(口令) | BE16 padding 长度 | padding`。
/// 与参考 `cmd/server/inbound_tcp.go` 的认证块同构：口令是运行时生成的假凭据，
/// 字节只在本用例内部流转，不写日志、不进断言文本。
pub fn auth_block(password: &[u8]) -> Vec<u8> {
    let mut block = Vec::with_capacity(34);
    block.extend_from_slice(&Sha256::digest(password));
    block.extend_from_slice(&0u16.to_be_bytes());
    block
}

/// 流结束的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminator {
    /// 对端发了 `cmdFIN`（协议层的流 EOF 标记）⇒ 干净 EOF。
    Fin,
    /// 传输层 EOF；`Eof` 区分「缓冲空（干净）」与「残留半帧（截断）」。
    TransportEof,
}

/// 读到流 EOF 时的结果。
#[derive(Debug)]
pub struct StreamOutcome {
    /// EOF 判定：干净 EOF 或残留半帧。
    pub eof: Eof,
    /// 结束原因。
    pub terminator: Terminator,
}

/// 客户端侧会话。
pub struct ClientSession {
    /// 底层连接（半关闭写端时直接用它）。
    pub stream: TcpStream,
    reader: FrameReader,
    pending: BTreeMap<u32, Vec<u8>>,
    finished: BTreeSet<u32>,
    eof: Option<Eof>,
    next_sid: u32,
}

impl ClientSession {
    /// 连接服务端（明文 TCP 回环）。
    pub async fn connect(addr: SocketAddr) -> Result<Self, String> {
        let stream = timeout(WAIT, TcpStream::connect(addr))
            .await
            .map_err(|_| "连接服务端超时".to_owned())?
            .map_err(|err| format!("连接服务端失败：{err}"))?;
        let _ = stream.set_nodelay(true);
        Ok(Self {
            stream,
            reader: FrameReader::new(),
            pending: BTreeMap::new(),
            finished: BTreeSet::new(),
            eof: None,
            next_sid: 0,
        })
    }

    /// 认证 + Settings(v=2)，并等待服务端的 ServerSettings。
    pub async fn handshake(&mut self, password: &[u8]) -> Result<(), String> {
        Credential::new(password)
            .send(&mut self.stream, b"", WAIT)
            .await
            .map_err(|err| format!("认证发送失败：{err}"))?;
        let settings_frame = settings(&default_md5());
        settings_frame
            .write(&mut self.stream, WAIT)
            .await
            .map_err(|err| format!("写 Settings 失败：{err}"))?;
        loop {
            let frame = self
                .pump()
                .await?
                .ok_or_else(|| "收到 ServerSettings 前传输层 EOF".to_owned())?;
            match frame.command {
                Command::ServerSettings => return Ok(()),
                Command::UpdatePadding => continue,
                other => {
                    return Err(format!(
                        "期望 ServerSettings，实际 {:?}（sid={}）",
                        other, frame.stream_id
                    ))
                }
            }
        }
    }

    /// 开一条新流：SYN + 首帧 PUSH（SOCKS 地址 + 载荷），返回流编号。
    pub async fn open_stream(&mut self, target: SocketAddr, payload: &[u8]) -> Result<u32, String> {
        self.next_sid += 1;
        let sid = self.next_sid;
        Frame {
            command: Command::Syn,
            stream_id: sid,
            data: Vec::new(),
        }
        .write(&mut self.stream, WAIT)
        .await
        .map_err(|err| format!("写 SYN 失败：{err}"))?;
        Frame {
            command: Command::Push,
            stream_id: sid,
            data: push_with_target(target, payload),
        }
        .write(&mut self.stream, WAIT)
        .await
        .map_err(|err| format!("写 PUSH 失败：{err}"))?;
        Ok(sid)
    }

    /// 发送 `cmdFIN`（协议层的流 EOF 标记：只关这一条流，不关会话）。
    pub async fn send_fin(&mut self, sid: u32) -> Result<(), String> {
        Frame {
            command: Command::Fin,
            stream_id: sid,
            data: Vec::new(),
        }
        .write(&mut self.stream, WAIT)
        .await
        .map_err(|err| format!("写 FIN 失败：{err}"))
    }

    /// 只关写端（TCP 半关闭）：读方向保持可用。
    pub async fn shutdown_write(&mut self) -> Result<(), String> {
        self.stream
            .shutdown()
            .await
            .map_err(|err| format!("半关闭写端失败：{err}"))
    }

    /// 读到某条流累计收到 `want` 字节（中途跨过的其他流帧按流归档）。
    pub async fn read_bytes(&mut self, sid: u32, want: usize) -> Result<Vec<u8>, String> {
        while self.pending.get(&sid).map_or(0, |buf| buf.len()) < want {
            match self.pump().await? {
                Some(frame) => self.route(frame),
                None => {
                    return Err(format!(
                        "传输层 EOF：sid={sid} 只收到 {} 字节，期望 {want}",
                        self.pending.get(&sid).map_or(0, |buf| buf.len())
                    ))
                }
            }
        }
        Ok(self.pending.get(&sid).cloned().unwrap_or_default())
    }

    /// 读到某条流的 EOF（`cmdFIN` 或传输层 EOF），返回载荷与 EOF 判定。
    pub async fn read_to_eof(&mut self, sid: u32) -> Result<StreamOutcome, String> {
        loop {
            if self.finished.contains(&sid) {
                self.pending.remove(&sid);
                return Ok(StreamOutcome {
                    eof: Eof::Clean,
                    terminator: Terminator::Fin,
                });
            }
            match self.pump().await? {
                Some(frame) => self.route(frame),
                None => {
                    let eof = self.eof.take().unwrap_or(Eof::Clean);
                    self.pending.remove(&sid);
                    return Ok(StreamOutcome {
                        eof,
                        terminator: Terminator::TransportEof,
                    });
                }
            }
        }
    }

    /// 读下一帧；`None` 表示传输层 EOF（判定记在 `self.eof`）。
    async fn pump(&mut self) -> Result<Option<Frame>, String> {
        loop {
            match self.reader.take() {
                Ok(Some(frame)) => return Ok(Some(frame)),
                Ok(None) => {}
                Err(err) => return Err(format!("帧解码失败：{err:?}")),
            }
            match self.reader.fill(&mut self.stream).await? {
                Some(eof) => {
                    self.eof = Some(eof);
                    return Ok(None);
                }
                None => continue,
            }
        }
    }

    /// 按流归档 PUSH 载荷，并记录 `cmdFIN`。
    fn route(&mut self, frame: Frame) {
        match frame.command {
            Command::Push => {
                self.pending
                    .entry(frame.stream_id)
                    .or_default()
                    .extend_from_slice(&frame.data);
            }
            Command::Fin => {
                self.finished.insert(frame.stream_id);
            }
            _ => {}
        }
    }
}
