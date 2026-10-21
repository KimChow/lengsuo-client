//! 传输层（TLS）篡改用例：帧载荷在 TLS 记录内被改 1 bit。
//!
//! ## 为什么这格必须放在 TLS 层
//!
//! AnyTLS 的帧**没有帧级 MAC**（参考 anytls-go `proxy/session/frame.go:37-49`
//! 的帧头只有 `cmd|sid|len`），而参考实现对每条连接**无条件**套 TLS
//! （`cmd/server/inbound_tcp.go:27`：`c = tls.Server(c, s.tlsConfig)`）。
//! 因此真实部署里「一帧的载荷被改 1 bit」只可能发生在 **TLS 记录内**——
//! 由 AEAD 检出并断连。
//!
//! ## 中间人形态：**不终结 TLS 的字节级转发器**
//!
//! 中间人只做 TCP 字节转发，**不**终结 TLS（不握手、不解密）——否则就无法把
//! 密文原样转发，服务端看到的就不是「被翻了 1 bit 的载荷」而是另一条会话。
//! TLS 记录头（类型/版本/长度）在链路上是明文，故转发器**能解析记录边界**，
//! 从而精确定位「承载 PUSH 的那条应用数据记录」并把其中 1 个字节翻位。
//!
//! ## 记录布局推导（TLS 1.3，rustls ring provider）
//!
//! - 记录 = `外层类型(1) | 版本(2) | 长度(2) | 记录体`（RFC 8446 §5.1）。
//! - TLS 1.3 记录体 = `密文 | 认证标签(16B)`，**无显式 nonce**
//!   （AES-GCM / ChaCha20-Poly1305 均为流式密钥）。
//! - rustls 在**加密前**把内层内容类型作为**明文**的最后一字节追加到载荷，
//!   随后整体加密并追加标签（rustls `crypto/ring/tls13.rs:211-219`：
//!   `payload.extend_from_slice(&msg.typ.to_array())` → `seal_in_place_append_tag`）。
//!   ⇒ 记录体长度 = 明文长度 + 1（内层类型）+ 16（标签）。
//!
//! ⛔ **关键口径（前一版实现的错法在此更正）**：内层内容类型的**取值在链路上
//! **不可读**——它与载荷一起被加密。中间人**不能**靠「读内层类型」区分应用数据
//! 记录与握手记录（前一版实现读 `body[body_len-17]` 拿到的是随机密文，
//! 条件永不成立 ⇒ **篡改从未真正发生**，用例因此「假绿」）。
//! 正确做法：用**记录体长度**（记录头是明文）定位目标记录，并断言
//! 「明文长度 = 目标长度」的加密记录**恰好一条**（唯一性），
//! 保证翻位落在承载 PUSH 的那条记录上；若推导与实现不符，
//! 唯一性断言会**直接失败**而不是静默通过。
#![allow(dead_code)]

use crate::harness::{push_with_target, spawn_target, PASSWORD, TOTAL, WAIT};
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    padding::PaddingScheme,
    server::{self, ServerConfig},
    tls::{ClientTrust, ServerIdentity},
    Error,
};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 测试口令（假凭据，不进日志）。
const PASSWORD_BYTES: &[u8] = PASSWORD;
/// 服务名（测试 PKI 的叶子 SAN 含 localhost）。
const SERVER_NAME: &str = "localhost";
/// TLS 1.3 记录体：内层内容类型(1) + 认证标签(16) 的固定开销。
const TLS13_BODY_OVERHEAD: usize = 1 + 16;
/// TLS 1.3 外层记录类型：加密后的应用数据 / 握手（两者外层类型相同，
/// 故**不能**靠外层类型区分，见 `TamperState::process` 的口径说明）。
const OUTER_ENCRYPTED: u8 = 0x17;

/// 中间人观察到的篡改事实（写进测试输出，供文档引用）。
#[derive(Debug, Clone)]
struct TamperReport {
    /// 被篡改记录的外层类型。
    outer_type: u8,
    /// 被篡改记录体长度。
    body_len: usize,
    /// 被翻位的字节在记录体中的下标。
    flipped_index: usize,
    /// 观察到的、与目标长度相同的加密记录条数（唯一性判据）。
    candidates: usize,
}

/// 中间人的篡改状态：按 TLS 记录解析客户端→服务端方向。
#[derive(Default)]
struct TamperState {
    /// 客户端→服务端的记录体缓冲。
    buffer: Vec<u8>,
    /// 目标记录体长度（唯一标识承载 PUSH 的那条记录）。
    target_body_len: usize,
    /// 目标记录体内的被篡改字节下标。
    target_index: usize,
    /// 是否已篡改。
    tampered: bool,
    /// 与目标长度相同的加密记录条数。
    candidates: usize,
    /// 观察报告。
    report: Option<TamperReport>,
}

impl TamperState {
    /// 吃进一段客户端→服务端字节，返回应转发给服务端的字节。
    fn process(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buffer.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(chunk.len());
        loop {
            if self.buffer.len() < 5 {
                break;
            }
            let outer_type = self.buffer[0];
            let body_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
            if self.buffer.len() < 5 + body_len {
                break;
            }
            let body_end = 5 + body_len;
            let mut body = self.buffer[5..body_end].to_vec();
            if outer_type == OUTER_ENCRYPTED && body_len > TLS13_BODY_OVERHEAD {
                // 记录头是明文：长度可信。内层内容类型**已加密**，不可读，
                // 故只能按「记录体长度」定位目标记录。
                if body_len == self.target_body_len {
                    self.candidates += 1;
                    if !self.tampered {
                        assert!(
                            self.target_index < body_len,
                            "被篡改下标 {} 超出记录体长度 {body_len}",
                            self.target_index
                        );
                        body[self.target_index] ^= 0x01;
                        self.tampered = true;
                        self.report = Some(TamperReport {
                            outer_type,
                            body_len,
                            flipped_index: self.target_index,
                            candidates: self.candidates,
                        });
                    }
                }
            }
            // ⛔ 必须转发**改过的** body：直接转发 `self.buffer` 会把翻位丢掉
            // （前一版实现就是这个错法 ⇒ 篡改从未真正上链，用例「假绿」）。
            out.extend_from_slice(&self.buffer[..5]);
            out.extend_from_slice(&body);
            self.buffer.drain(..body_end);
        }
        out
    }
}

/// 起一个真实 TLS + AnyTLS 服务端，返回端口。
async fn spawn_tls_server(pki: &crate::pki::Pki) -> u16 {
    let identity = ServerIdentity::new(&pki.chain_pem, &pki.key_pem).expect("服务端身份");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(identity));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听");
    let port = listener.local_addr().expect("地址").port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(stream) = timeout(WAIT, acceptor.accept(socket))
                    .await
                    .unwrap_or(Err(std::io::Error::other("握手超时")))
                {
                    let _ = server::serve(stream, ServerConfig::new(PASSWORD_BYTES, WAIT)).await;
                }
            });
        }
    });
    port
}

/// 起一个**字节级**中间人：客户端 →(中间人)→ 真实服务端。
///
/// 中间人不终结 TLS，只解析记录头（明文）并把目标记录里的 1 个字节翻位。
/// 返回 (监听端口, 篡改报告)。
async fn spawn_mitm(
    upstream: SocketAddr,
    target_body_len: usize,
    target_index: usize,
) -> (u16, Arc<Mutex<Option<TamperReport>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("中间人监听");
    let port = listener.local_addr().expect("地址").port();
    let report: Arc<Mutex<Option<TamperReport>>> = Arc::new(Mutex::new(None));
    let shared = Arc::clone(&report);
    tokio::spawn(async move {
        let Ok((client_side, _)) = listener.accept().await else {
            return;
        };
        let Ok(upstream_side) = TcpStream::connect(upstream).await else {
            return;
        };
        // `into_split` 返回 (OwnedReadHalf, OwnedWriteHalf)。
        let (mut from_client, mut to_client) = client_side.into_split();
        let (mut from_upstream, mut to_upstream) = upstream_side.into_split();

        let state = Arc::new(Mutex::new(TamperState {
            target_body_len,
            target_index,
            ..TamperState::default()
        }));

        // 客户端 → 服务端（经篡改）。
        let up_state = Arc::clone(&state);
        let up_shared = Arc::clone(&shared);
        let c2s = tokio::spawn(async move {
            let mut chunk = [0u8; 4096];
            loop {
                let count = match from_client.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(count) => count,
                };
                let forwarded = {
                    let mut guard = up_state.lock().expect("篡改状态锁");
                    let bytes = guard.process(&chunk[..count]);
                    *up_shared.lock().expect("报告锁") = guard.report.clone();
                    bytes
                };
                if to_upstream.write_all(&forwarded).await.is_err() {
                    break;
                }
                let _ = to_upstream.flush().await;
            }
            // 残留不足一整条记录（会话结束时的尾巴）原样转发。
            let rest = {
                let mut guard = up_state.lock().expect("篡改状态锁");
                std::mem::take(&mut guard.buffer)
            };
            if !rest.is_empty() {
                let _ = to_upstream.write_all(&rest).await;
                let _ = to_upstream.flush().await;
            }
        });

        // 服务端 → 客户端（原样转发）。
        let s2c = tokio::spawn(async move {
            let mut chunk = [0u8; 4096];
            loop {
                let count = match from_upstream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(count) => count,
                };
                if to_client.write_all(&chunk[..count]).await.is_err() {
                    break;
                }
                let _ = to_client.flush().await;
            }
        });

        let _ = s2c.await;
        let _ = c2s.await;
    });
    (port, report)
}

/// 读一帧并跳过 Waste 填充。
async fn next_semantic<S: AsyncReadExt + Unpin>(stream: &mut S) -> Frame {
    loop {
        let frame = Frame::read(stream, u16::MAX, WAIT).await.expect("读帧");
        if frame.command != Command::Waste {
            return frame;
        }
    }
}

/// 读一帧并跳过 Waste 填充；出错时返回错误而不 panic。
async fn try_next_semantic<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Frame, Error> {
    loop {
        let frame = Frame::read(stream, u16::MAX, WAIT).await?;
        if frame.command != Command::Waste {
            return Ok(frame);
        }
    }
}

/// 客户端 Settings 帧的编码字节。
fn settings_bytes() -> Vec<u8> {
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: format!(
            "v=2\nclient=lengsuo-test\npadding-md5={}",
            PaddingScheme::default_scheme().md5()
        )
        .into_bytes(),
    }
    .encode()
    .expect("编码 Settings")
}

/// 帧载荷在 TLS 记录内被改 1 bit ⇒ 服务端必须中止连接，篡改数据不得交给上层。
///
/// 判据：TLS 的 AEAD 记录认证（TLS 1.3 记录认证标签）——由 rustls 承担，
/// 记录校验失败即返回错误；`src/server/session.rs:108-109` 把读错误向上传播
/// ⇒ 会话以失败结束（fail-closed）。
#[tokio::test]
async fn on_path_payload_tampering_is_rejected() {
    timeout(TOTAL * 3, async {
        let Some(pki) = crate::pki::generate() else {
            eprintln!("跳过：无 openssl，无法生成测试 PKI");
            return;
        };
        let target = spawn_target().await;
        let server_port = spawn_tls_server(&pki).await;
        let server_addr = SocketAddr::from(([127, 0, 0, 1], server_port));

        // 记录明文布局：SYN(7) | PUSH 头(7) | SOCKS 地址(7) | 应用载荷。
        let syn_frame = Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        }
        .encode()
        .expect("编码 SYN");
        let app_payload = b"tls-tamper-payload-probe";
        let push_frame = Frame {
            command: Command::Push,
            stream_id: 1,
            data: push_with_target(target.addr, app_payload),
        }
        .encode()
        .expect("编码 PUSH");
        // 被翻位字节在记录体中的下标 = SYN + PUSH 头 + SOCKS 地址。
        let payload_offset = syn_frame.len() + 7 + 7;
        let body_len = syn_frame.len() + push_frame.len() + TLS13_BODY_OVERHEAD;

        let (mitm_port, report) = spawn_mitm(server_addr, body_len, payload_offset).await;

        // 被测客户端：连中间人（TLS 直通中间人，密钥只有两端知道）。
        let client_config = ClientTrust::new(&pki.ca_pem, SERVER_NAME).expect("客户端信任");
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
        let socket = TcpStream::connect(("127.0.0.1", mitm_port))
            .await
            .expect("连接中间人");
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(SERVER_NAME.to_owned())
            .expect("服务名");
        let mut stream = timeout(WAIT, connector.connect(name, socket))
            .await
            .expect("握手超时")
            .expect("TLS 握手（含 CA + 名称校验）");
        assert_eq!(
            stream.get_ref().1.protocol_version(),
            Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3),
            "本用例的记录布局推导只对 TLS 1.3 成立"
        );

        // 第 1 条应用数据记录：认证块 + Settings（合成一次 write ⇒ 一条记录）。
        let mut auth = Vec::new();
        Credential::new(PASSWORD_BYTES)
            .send(&mut auth, b"", WAIT)
            .await
            .expect("认证块");
        let mut first = auth;
        first.extend_from_slice(&settings_bytes());
        stream.write_all(&first).await.expect("写认证与 Settings");
        stream.flush().await.expect("刷新");
        let server_settings = next_semantic(&mut stream).await;
        assert_eq!(
            server_settings.command,
            Command::ServerSettings,
            "协商到 v2"
        );

        // 第 2 条应用数据记录：SYN + PUSH（中间人在这条记录里翻 1 bit）。
        let mut second = syn_frame.clone();
        second.extend_from_slice(&push_frame);
        stream.write_all(&second).await.expect("写 SYN 与 PUSH");
        stream.flush().await.expect("刷新");

        // 服务端必须因记录校验失败而中止：客户端读不到任何语义帧。
        // 注意：`timeout(...)` 成功时返回 `Ok(inner)`，故要判**内层**结果。
        let read = timeout(WAIT, try_next_semantic(&mut stream)).await;
        match read {
            Err(_elapsed) => {}
            Ok(Err(err)) => assert!(
                matches!(err, Error::Io(_)),
                "记录校验失败后服务端只能断开，不得回语义帧，实际错误：{err}"
            ),
            Ok(Ok(frame)) => panic!(
                "载荷被改 1 bit 后服务端不得回任何语义帧，实际收到 {:?} sid={} len={}",
                frame.command,
                frame.stream_id,
                frame.data.len()
            ),
        }

        // 篡改事实：中间人确实在目标记录里翻了 1 bit，且长度与推导一致。
        let observed = report.lock().expect("报告锁").clone();
        let observed = observed.expect("中间人未报告篡改");
        println!(
            "tamper report: outer_type={} body_len={} flipped_index={} candidates={}",
            observed.outer_type, observed.body_len, observed.flipped_index, observed.candidates
        );
        assert_eq!(
            observed.outer_type, OUTER_ENCRYPTED,
            "被篡改记录必须是加密记录"
        );
        assert_eq!(
            observed.body_len, body_len,
            "记录体长度必须等于 明文 + 内层类型(1) + 标签(16)"
        );
        assert_eq!(
            observed.flipped_index, payload_offset,
            "翻位落在 PUSH 载荷内"
        );
        assert_eq!(
            observed.candidates, 1,
            "承载 PUSH 的记录必须唯一：长度推导有歧义则本用例的篡改点不可信"
        );

        // 核心断言：篡改后的数据不得交给上层——目标既没被拨号，也没收到字节。
        assert_eq!(
            target.accepted.load(Ordering::SeqCst),
            0,
            "载荷被篡改的帧不得触发拨号"
        );
        assert!(
            target.received().is_empty(),
            "载荷被篡改的帧不得把数据交给上层"
        );
    })
    .await
    .expect("用例超时");
}

/// 篡改后**新开一条连接**必须能正常往返：证明拒绝路径没有污染后续会话。
///
/// 判据：服务端每条连接独立（`src/server/session.rs:72-88` 每次 `serve` 新建
/// 状态机），拒绝路径不写全局状态。
#[tokio::test]
async fn fresh_connection_after_tamper_round_trips_normally() {
    timeout(TOTAL * 3, async {
        let Some(pki) = crate::pki::generate() else {
            eprintln!("跳过：无 openssl，无法生成测试 PKI");
            return;
        };
        let target = spawn_target().await;
        let server_port = spawn_tls_server(&pki).await;
        let server_addr = SocketAddr::from(([127, 0, 0, 1], server_port));

        let syn_frame = Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        }
        .encode()
        .expect("编码 SYN");
        let push_frame = Frame {
            command: Command::Push,
            stream_id: 1,
            data: push_with_target(target.addr, b"tampered-then-fresh"),
        }
        .encode()
        .expect("编码 PUSH");
        let payload_offset = syn_frame.len() + 7 + 7;
        let body_len = syn_frame.len() + push_frame.len() + TLS13_BODY_OVERHEAD;
        let (mitm_port, report) = spawn_mitm(server_addr, body_len, payload_offset).await;

        let client_config = ClientTrust::new(&pki.ca_pem, SERVER_NAME).expect("客户端信任");
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(SERVER_NAME.to_owned())
            .expect("服务名");

        // 第 1 条连接：经中间人，载荷被改 1 bit。
        {
            let socket = TcpStream::connect(("127.0.0.1", mitm_port))
                .await
                .expect("连接中间人");
            let mut stream = timeout(WAIT, connector.connect(name.clone(), socket))
                .await
                .expect("握手超时")
                .expect("TLS 握手");
            let mut auth = Vec::new();
            Credential::new(PASSWORD_BYTES)
                .send(&mut auth, b"", WAIT)
                .await
                .expect("认证块");
            let mut first = auth;
            first.extend_from_slice(&settings_bytes());
            stream.write_all(&first).await.expect("写认证与 Settings");
            stream.flush().await.expect("刷新");
            assert_eq!(
                next_semantic(&mut stream).await.command,
                Command::ServerSettings
            );
            let mut second = syn_frame.clone();
            second.extend_from_slice(&push_frame);
            stream.write_all(&second).await.expect("写 SYN 与 PUSH");
            stream.flush().await.expect("刷新");
            match timeout(WAIT, try_next_semantic(&mut stream)).await {
                Err(_elapsed) => {}
                Ok(Err(err)) => assert!(
                    matches!(err, Error::Io(_)),
                    "记录校验失败后只能断开，实际错误：{err}"
                ),
                Ok(Ok(_frame)) => panic!("被篡改的连接不得收到任何语义帧"),
            }
            assert!(report.lock().expect("报告锁").is_some(), "中间人未报告篡改");
            let observed = report.lock().expect("报告锁").clone().expect("篡改报告");
            assert_eq!(
                observed.candidates, 1,
                "承载 PUSH 的记录必须唯一：长度推导有歧义则篡改点不可信"
            );
        }

        // 第 2 条连接：直连真实服务端（不经中间人），必须正常往返。
        let payload = b"fresh-connection-after-tamper";
        {
            let socket = TcpStream::connect(server_addr).await.expect("连接服务端");
            let mut fresh = timeout(WAIT, connector.connect(name, socket))
                .await
                .expect("握手超时")
                .expect("TLS 握手");
            let mut auth = Vec::new();
            Credential::new(PASSWORD_BYTES)
                .send(&mut auth, b"", WAIT)
                .await
                .expect("认证块");
            let mut first = auth;
            first.extend_from_slice(&settings_bytes());
            fresh.write_all(&first).await.expect("写认证与 Settings");
            fresh.flush().await.expect("刷新");
            assert_eq!(
                next_semantic(&mut fresh).await.command,
                Command::ServerSettings
            );
            let mut second = syn_frame.clone();
            second.extend_from_slice(
                &Frame {
                    command: Command::Push,
                    stream_id: 1,
                    data: push_with_target(target.addr, payload),
                }
                .encode()
                .expect("编码 PUSH"),
            );
            fresh.write_all(&second).await.expect("写 SYN 与 PUSH");
            fresh.flush().await.expect("刷新");
            let ack = next_semantic(&mut fresh).await;
            assert_eq!(ack.command, Command::SynAck, "新连接必须正常建流");
            let echoed = next_semantic(&mut fresh).await;
            assert_eq!(echoed.command, Command::Push);
            assert_eq!(echoed.data, payload, "新连接必须逐字节往返一致");
        }
        assert_eq!(
            target.accepted.load(Ordering::SeqCst),
            1,
            "只有第二条（干净）连接才允许拨号"
        );
        assert_eq!(target.received(), payload.to_vec(), "目标只收到干净载荷");
    })
    .await
    .expect("用例超时");
}
