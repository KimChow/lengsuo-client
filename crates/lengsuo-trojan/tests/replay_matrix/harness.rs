//! `tests/replay_matrix.rs` 的共享夹具：TLS 身份、回显业务目标、本仓服务端、
//! 以及**捕获参考客户端写出的请求头原始字节**的探针。
//!
//! 观测面纪律（与既有 `tests/exception_matrix.rs` 一致）：
//! - 业务目标的 **accept 计数**是「有没有真的建立到目标的连接」的独立观测面；
//! - 拒绝必须由对端**主动结束连接**表达，读超时不算拒绝证据；
//! - 所有异步读写都带截止时间；`read_to_end` 之前先关闭写端。
//!
//! 只用回环地址、临时端口与假凭据；不打印密码、哈希或载荷。

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient};
use lengsuo_trojan::server::{Inbound, Server, Timeouts, Validator};
use lengsuo_trojan::{codec, Command, Credential, Request, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// 头部捕获端放在独立模块（`capture.rs`），这里转出以便用例统一 `use`。
pub use super::capture::CaptureServer;

/// 单次读/写/任务回收的观察上限。
pub const WAIT: Duration = Duration::from_secs(8);
/// 用例总预算。
pub const TOTAL: Duration = Duration::from_secs(60);
/// 握手截止：短于参考默认（60s），让「静默后被拒」在有限时间内可观测。
pub const HANDSHAKE: Duration = Duration::from_secs(2);

/// 本卡专用的假口令（与其它测试文件取值不同，避免跨文件混淆）。
pub const PASSWORD: &str = "replay-matrix-good-password";
/// 另一个假口令，用于「跨用户」场景。
pub const OTHER_PASSWORD: &str = "replay-matrix-other-password";
/// 回显载荷。回显后端读满这么多字节后原样回写。
pub const PAYLOAD: &[u8] = b"replay-matrix-payload";

/// TLS 身份：现场自签证书 + 显式信任，客户端与服务端共用。
pub struct Identity {
    client: TlsClient,
    pub cert: rcgen::CertifiedKey,
}

impl Identity {
    pub fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        Self { client, cert }
    }

    /// 本仓服务端 TLS 入站。
    pub fn inbound(&self) -> Inbound {
        Inbound::new(
            vec![self.cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(self.cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .unwrap()
    }

    /// 建立到本仓服务端的已认证 TLS 连接。
    pub async fn connect(
        &self,
        port: u16,
    ) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
        self.client
            .connect(([127, 0, 0, 1], port).into())
            .await
            .unwrap()
    }

    /// 客户端侧 TLS 配置（供参考客户端使用）。
    pub fn client_settings(&self) -> serde_json::Value {
        serde_json::json!({"security":"tls","tlsSettings":{"serverName":"localhost",
            "disableSystemRoot":true,"certificates":[{"usage":"verify",
            "certificate":self.cert.cert.pem().lines().collect::<Vec<_>>()}]}})
    }
}

/// 业务目标：回显后端 + accept 计数（独立观测面）。
///
/// 行为：每条连接读满 `len` 字节后原样回写并关闭写端。
pub struct EchoTarget {
    pub port: u16,
    accepted: Arc<AtomicUsize>,
}

impl EchoTarget {
    /// 绑定回环回显后端。
    pub async fn spawn(len: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; len];
                    if socket.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let _ = socket.write_all(&buf).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { port, accepted }
    }

    /// 业务目标被连接的次数。
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// 本仓 trojan 请求头指向本回显后端。
    pub fn request(&self) -> Request {
        Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], self.port),
        }
    }
}

/// 本仓 trojan 服务端（单连接或 accept 循环）。
pub struct RustServer {
    pub port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl RustServer {
    /// 启动 accept 循环（每条连接并发处理），带 TLS 接入。
    pub async fn start(identity: &Identity, password: &str) -> Self {
        let mut validator = Validator::new();
        validator.add("replay@example.com", password).unwrap();
        let server = Server::with_tls(
            validator,
            Timeouts::new(HANDSHAKE, WAIT).unwrap(),
            identity.inbound(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let _ = server.accept_loop(listener).await;
        });
        Self { port, task }
    }

    /// 启动 accept 循环，**不带** TLS（纯 trojan，transport 由调用方负责）。
    pub async fn start_plain(password: &str) -> Self {
        let mut validator = Validator::new();
        validator.add("replay@example.com", password).unwrap();
        let server = Server::new(validator, Timeouts::new(HANDSHAKE, WAIT).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let _ = server.accept_loop(listener).await;
        });
        Self { port, task }
    }

    /// 停掉 accept 循环。
    pub async fn stop(self) {
        self.task.abort();
        let _ = tokio::time::timeout(WAIT, self.task).await;
    }
}

/// 本仓服务端的**单连接**形态：只接一条连接，交出其处理结果。
///
/// 用于「认证失败必须可判别」这类需要看到服务端错误变体的用例。
pub struct SingleConnection {
    pub port: u16,
    pub task: tokio::task::JoinHandle<Result<(), lengsuo_trojan::server::Error>>,
}

/// 单连接本仓服务端（纯 trojan，无 TLS）。
pub async fn spawn_single_plain(password: &str) -> SingleConnection {
    let mut validator = Validator::new();
    validator.add("replay@example.com", password).unwrap();
    let server = Server::new(validator, Timeouts::new(HANDSHAKE, WAIT).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        server.handle_tcp(socket).await
    });
    SingleConnection { port, task }
}

/// 记录型业务目标：读满 `len` 字节后记录并原样回写。
///
/// 与 `EchoTarget` 的差别：回显目标只计数（证明「有没有抵达业务」），
/// 记录型目标额外把**收到的原始字节**交出来，用于断言「重放的头部字节
/// 是被当作应用载荷转发给目标的，而不是被解析成第二条请求」。
pub struct RecordingTarget {
    pub port: u16,
    received: Arc<std::sync::Mutex<Vec<u8>>>,
    accepted: Arc<AtomicUsize>,
}

impl RecordingTarget {
    pub async fn spawn(len: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let accepted = Arc::new(AtomicUsize::new(0));
        let sink = received.clone();
        let counter = accepted.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let sink = sink.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; len];
                    if socket.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    sink.lock().unwrap().extend_from_slice(&buf);
                    let _ = socket.write_all(&buf).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self {
            port,
            received,
            accepted,
        }
    }

    /// 业务目标已收到的原始字节。
    pub fn received(&self) -> Vec<u8> {
        self.received.lock().unwrap().clone()
    }

    /// 业务目标被连接的次数（独立观测面：重放是否建立了第二条连接）。
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// 本仓 trojan 请求头指向本记录型目标。
    pub fn request(&self) -> Request {
        Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], self.port),
        }
    }
}

/// 把一段 trojan 头部的**目标地址**改成另一处（IPv4 + 端口）。
///
/// 头部布局（参考 `proxy/trojan/protocol.go`）：56 字节哈希 + 2 字节 CRLF +
/// 1 字节命令 + 1 字节 ATYP + 地址 + 2 字节 CRLF。IPv4 目标下：
/// 字节 59 = ATYP(0x01)、字节 60..64 = IPv4、字节 64..66 = 端口（大端）。
///
/// 用途：把「重放的头部」指向**另一个业务目标**，这样「重放被当成新请求解析」
/// 与「重放只是被当作载荷转发」就有了**决定性**的区分面——前者会拨到新目标，
/// 后者不会。字节 56..59（哈希、CRLF、命令）与 66..68（尾 CRLF）保持不变。
pub fn retarget_header(header: &[u8], ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut patched = header.to_vec();
    assert_eq!(
        patched[59], 0x01,
        "改写目标地址只支持 IPv4 头部（ATYP 必须为 0x01）"
    );
    patched[60..64].copy_from_slice(&ip);
    patched[64..66].copy_from_slice(&port.to_be_bytes());
    patched
}

/// 脚本化业务目标：每条连接按**事先排好的长度表**读满对应字节数，原样回写。
///
/// 为什么需要它：同一条用例里，不同连接的载荷长度不同（例如第一次会话是
/// 「载荷」，重放那次是「载荷 + 重放的头部」）。读满的字节数由用例在连接
/// 发生**之前**登记（先进先出），因此不依赖时序猜测。
pub struct ScriptedTarget {
    pub port: u16,
    accepted: Arc<AtomicUsize>,
    received: Arc<std::sync::Mutex<Vec<u8>>>,
    plan: Arc<std::sync::Mutex<Vec<usize>>>,
}

impl ScriptedTarget {
    /// 绑定脚本化目标；`plan` 是每条连接依次要读满的字节数。
    pub async fn spawn(plan: Vec<usize>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let plan = Arc::new(std::sync::Mutex::new(plan));
        let counter = accepted.clone();
        let sink = received.clone();
        let sizes = plan.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let sink = sink.clone();
                let sizes = sizes.clone();
                tokio::spawn(async move {
                    // 取本条连接应读满的字节数；表空则按 0 处理（即立刻回写空）。
                    let want = sizes.lock().unwrap().first().copied().unwrap_or(0);
                    if want > 0 {
                        sizes.lock().unwrap().remove(0);
                    }
                    let mut buf = vec![0u8; want];
                    if socket.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    sink.lock().unwrap().extend_from_slice(&buf);
                    let _ = socket.write_all(&buf).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self {
            port,
            accepted,
            received,
            plan,
        }
    }

    /// 追加一条连接的预期读满长度。
    pub fn push_len(&self, len: usize) {
        self.plan.lock().unwrap().push(len);
    }

    /// 业务目标已收到的原始字节（按连接顺序拼接）。
    pub fn received(&self) -> Vec<u8> {
        self.received.lock().unwrap().clone()
    }

    /// 业务目标被连接的次数。
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// 编码一条合法 trojan 请求头（56 字节密码哈希 + CRLF + 命令 + 地址 + CRLF）。
pub fn header(request: &Request, password: &str) -> Vec<u8> {
    codec::encode(request, &Credential::new(password)).unwrap()
}

/// 断言对端在 `within` 内**主动结束**连接（读到 `Ok(0)` 或 `Err`）。
///
/// 只读到超时即 panic——超时不是拒绝证据。
pub async fn assert_peer_closed<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, within: Duration) {
    let mut buf = [0u8; 32];
    let outcome = tokio::time::timeout(within, stream.read(&mut buf))
        .await
        .expect("对端必须在观察上限内主动结束连接（超时不算拒绝证据）");
    assert!(
        matches!(outcome, Ok(0) | Err(_)),
        "不得收到应答字节：{outcome:?}"
    );
}

/// 读满 `len` 字节回程；写端已由调用方关闭。
pub async fn read_exact<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    len: usize,
    within: Duration,
) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    tokio::time::timeout(within, stream.read_exact(&mut buf))
        .await
        .expect("回程超时")
        .expect("回程读失败");
    buf
}
