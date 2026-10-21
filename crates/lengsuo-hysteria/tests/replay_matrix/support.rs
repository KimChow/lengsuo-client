//! `replay_matrix` 测试目标的**共享支撑代码**（与 `tests/lifecycle.rs`
//! 同范式：共享代码放在本目录的 `support.rs`，由 `replay_matrix.rs`
//! 用 `#[path]` 引入）。
//!
//! ⚠️ **不得**修改 `tests/support/mod.rs`（仓库级共享支撑文件，由其它卡
//! 独占）；本文件是本卡**自带**的副本，只服务 `replay_matrix`。
//!
//! 提供：
//! - 运行时生成的假口令与临时目录；
//! - openssl 现场自签证书（SAN=DNS:localhost）；
//! - 本仓服务端（`HysteriaServer`）起停；
//! - 客户端配置与建连；
//! - **帧级**重放所需的原始 QUIC 双向流访问（绕过 `proxy::tcp_connect`
//!   的自动首写，以便**逐字节重放**同一段请求帧）；
//! - 本地 TCP 目标（记录收到的数据与接入次数）。
//!
//! UDP 中继 / JSON 转义 / 轮询等待 / 用例级墙钟上限放在同目录的
//! `relay.rs`（拆文件以控制单文件行数），此处**转出**以便调用方统一从
//! `support` 取用。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lengsuo_hysteria::quic::server::{HysteriaServer, ServerConfig};
use lengsuo_hysteria::quic::{ClientConfig, ConnectError, HysteriaClient};

pub(crate) use crate::relay::{
    case_within, json_escape, observe_never, wait_until, UdpRelay, CASE_DEADLINE,
};

/// 单次网络操作的上限（所有 IO 都套 `tokio::time::timeout`）。
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(20);
/// 轮询等待的总截止时间。
pub(crate) const RECLAIM_DEADLINE: Duration = Duration::from_secs(25);
/// 轮询间隔（只出现在轮询循环里）。
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// TLS 校验名（自签证书的 SAN 含 `DNS:localhost`）。
pub(crate) const SERVER_NAME: &str = "localhost";
/// TCPRequest 帧类型（对齐 `transport/internet/hysteria/config.go:29`）。
pub(crate) const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// 运行时生成的假口令：每条用例一份，不写死、不进日志。
pub(crate) fn fake_auth(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("lengsuo-replay-{tag}-{}-{nanos}", std::process::id())
}

pub(crate) fn test_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("lengsuo-hy-replay-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

/// openssl 现场自签（SAN=DNS:localhost），只用临时目录。
pub(crate) fn gen_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let out = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .args([
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ])
        .output()
        .expect("执行 openssl");
    assert!(
        out.status.success(),
        "openssl 生成自签证书失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (cert, key)
}

pub(crate) fn cert_der(cert: &Path, dir: &Path) -> Vec<u8> {
    let der_path = dir.join("cert.der");
    let out = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert)
        .args(["-outform", "DER", "-out"])
        .arg(&der_path)
        .output()
        .expect("执行 openssl x509");
    assert!(out.status.success(), "openssl 转 DER 失败");
    std::fs::read(der_path).expect("读取 DER 证书")
}

pub(crate) fn key_der(key: &Path) -> Vec<u8> {
    let out = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(key)
        .args(["-outform", "DER"])
        .output()
        .expect("执行 openssl pkey");
    assert!(out.status.success(), "openssl 转私钥 DER 失败");
    out.stdout
}

/// 确定性伪随机载荷（逐字节比对用）。
pub(crate) fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// 已绑定的本仓服务端。
pub(crate) struct Server {
    pub(crate) addr: SocketAddr,
    pub(crate) cert_der: Vec<u8>,
    pub(crate) auth: String,
    #[allow(dead_code)]
    pub(crate) dir: PathBuf,
    pub(crate) inner: Arc<HysteriaServer>,
    #[allow(dead_code)]
    pub(crate) task: tokio::task::JoinHandle<()>,
}

impl Server {
    /// 服务端端点上的 QUIC 连接数（连接级会话表计数）。
    pub(crate) fn open_connections(&self) -> usize {
        self.inner.endpoint().open_connections()
    }
}

/// 起一个本仓服务端（UDP 端口由系统分配）。
pub(crate) async fn start_server(tag: &str) -> Server {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let key_der = key_der(&key);
    let listen: SocketAddr = "127.0.0.1:0".parse().expect("监听地址");
    let auth = fake_auth(tag);
    let config = ServerConfig {
        listen_addr: listen,
        cert_chain_der: vec![der.clone()],
        key_der,
        auth: auth.clone(),
        brutal_down: 0,
        brutal_up: 0,
        udp_enabled: true,
        udp_idle_timeout_secs: 60,
        congestion: String::new(),
    };
    let server = Arc::new(HysteriaServer::bind(config).expect("服务端绑定失败"));
    let addr = server.local_addr().expect("读取监听地址");
    let srv = Arc::clone(&server);
    let task = tokio::spawn(async move { srv.accept_loop().await });
    Server {
        addr,
        cert_der: der,
        auth,
        dir,
        inner: server,
        task,
    }
}

pub(crate) fn client_config(server: &Server, auth: &str) -> ClientConfig {
    ClientConfig {
        server_addr: server.addr,
        server_name: SERVER_NAME.to_string(),
        auth: auth.to_string(),
        roots_der: vec![server.cert_der.clone()],
        brutal_down: 0,
        brutal_up: 0,
        congestion: String::new(),
        peer_cc_rx: None,
    }
}

/// 客户端建连（**带墙钟上限**）。
///
/// 超时上限 = [`IO_TIMEOUT`]；超时按 [`connect_timeout_error`] 报错，
/// 不静默重试（重试会掩盖「服务端没起来」这类真问题）。
pub(crate) async fn connect_with(
    server: &Server,
    auth: &str,
) -> Result<HysteriaClient, ConnectError> {
    match tokio::time::timeout(
        IO_TIMEOUT,
        HysteriaClient::connect(client_config(server, auth)),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(connect_timeout_error()),
    }
}

/// 建连超时用的错误值。
///
/// `ConnectError` 没有专门的「超时」变体，用 `Quic` 变体承载
/// `quinn::ConnectionError::TimedOut` —— 它**确实是**一个合法的连接
/// 失败原因，且 `Display` 会如实说明是超时，不会掩盖成因。
pub(crate) fn connect_timeout_error() -> ConnectError {
    ConnectError::Quic(quinn::ConnectionError::TimedOut)
}

// ===========================================================================
// 帧级重放：原始 QUIC 双向流
// ===========================================================================

/// 一条**原始** QUIC 双向流（不做任何自动首写）。
///
/// 用它而不是 `proxy::tcp_connect`：后者首写会带上随机 padding
/// （`proxy.rs:73` `h3_auth::random_padding(Range::TCP_REQUEST)`），
/// 无法拿到「同一段字节」去逐字节重放。本结构让调用方自己编码
/// TCPRequest 帧并**原样写两次**。
pub(crate) struct RawStream {
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
    /// 本流的 QUIC 流 ID（用于对照「重放与流 ID 的关系」）。
    pub(crate) stream_id: u64,
}

impl RawStream {
    /// 打开一条原始双向流（**带墙钟上限**）。
    pub(crate) async fn open(client: &HysteriaClient) -> Result<Self, ConnectError> {
        let (send, recv) = match tokio::time::timeout(IO_TIMEOUT, client.open_tcp()).await {
            Ok(result) => result?,
            Err(_) => return Err(connect_timeout_error()),
        };
        let stream_id = u64::from(send.id());
        Ok(Self {
            send,
            recv,
            stream_id,
        })
    }

    /// 写一段字节（**不**自动补帧类型、**不**自动加 padding）。
    ///
    /// **带墙钟上限**：写超时不返回「半个成功」，而是**报错**，
    /// 避免调用方误以为整段字节已发出（重放语义依赖「字节完全一致」）。
    pub(crate) async fn write_raw(&mut self, bytes: &[u8]) -> Result<(), quinn::WriteError> {
        match tokio::time::timeout(IO_TIMEOUT, self.send.write_all(bytes)).await {
            Ok(result) => result,
            // 写超时 = 流被应用中止（quinn 用 `Stopped` 表达「本端不再
            // 接受写入」）。错误码 0 = 无具体原因，仅用于**测试**路径。
            Err(_) => Err(quinn::WriteError::Stopped(quinn::VarInt::from_u32(0))),
        }
    }

    /// 结束写端（发 FIN）。
    pub(crate) fn finish(&mut self) {
        let _ = self.send.finish();
    }

    /// 读出服务端的 **TCPResponse 帧**（status + message + padding）。
    ///
    /// 服务端在建立出站后回一帧 `TCPResponse`（对齐参考
    /// `proxy/hysteria/server.go:179` `WriteTCPResponse(bufferedWriter, true, "")`）。
    /// 帧后的字节是目标数据，本方法只取帧本身。
    ///
    /// **带墙钟上限**：读超时按 `ReadError::ClosedStream` 报出（读不出来
    /// 与流被关闭对调用者的含义相同：拿不到帧）。
    pub(crate) async fn read_response_frame(&mut self) -> Result<(u8, Vec<u8>), quinn::ReadError> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 2048];
        loop {
            if let Ok((resp, consumed)) = lengsuo_hysteria::tcp::TcpResponse::decode(&buf) {
                buf.drain(..consumed);
                return Ok((resp.status.as_byte(), resp.message.into_bytes()));
            }
            match tokio::time::timeout(IO_TIMEOUT, self.recv.read(&mut chunk)).await {
                Ok(Ok(None)) => return Err(quinn::ReadError::ClosedStream),
                Ok(Ok(Some(n))) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(quinn::ReadError::ClosedStream),
            }
        }
    }
}

/// 编码一条 TCPRequest 帧（`varint(0x401) ‖ varint(addr_len) ‖ addr ‖
/// varint(pad_len) ‖ padding`），与 `src/tcp.rs` 的 `TcpRequest::encode`
/// 逐字节一致，但 padding 由调用方指定（重放需要**固定**字节）。
pub(crate) fn encode_tcp_request(address: &str, padding: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + address.len() + padding.len());
    out.extend_from_slice(&varint_bytes(FRAME_TYPE_TCP_REQUEST));
    out.extend_from_slice(&varint_bytes(address.len() as u64));
    out.extend_from_slice(address.as_bytes());
    out.extend_from_slice(&varint_bytes(padding.len() as u64));
    out.extend_from_slice(padding);
    out
}

/// QUIC varint 的最短编码（与 `src/varint.rs::append` 一致）。
pub(crate) fn varint_bytes(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    lengsuo_hysteria::varint::append(value, &mut out).expect("varint 编码失败");
    out
}

// ===========================================================================
// 本地 TCP 目标
// ===========================================================================

/// 本地 TCP 目标的观测面。
#[derive(Default)]
pub(crate) struct TargetState {
    /// 每次接入累计收到的字节。
    pub(crate) received: Vec<u8>,
    /// 接入次数（服务端出站 TCP 连接的条数）。
    pub(crate) accepts: usize,
}

/// 本地 TCP 目标：记录收到的全部字节 + 接入次数；收到数据后原样回写。
pub(crate) struct TcpTarget {
    pub(crate) addr: SocketAddr,
    state: Arc<Mutex<TargetState>>,
}

impl TcpTarget {
    /// 目标累计收到的全部字节。
    pub(crate) fn received(&self) -> Vec<u8> {
        self.state.lock().expect("目标缓冲锁中毒").received.clone()
    }

    /// 目标被接入的次数。
    pub(crate) fn accepts(&self) -> usize {
        self.state.lock().expect("目标缓冲锁中毒").accepts
    }
}

/// 起一个本地 TCP 目标：每次接入独立处理，读到字节就原样回写（echo），
/// 并把「本次接入收到的字节数」作为事件上报。
pub(crate) async fn spawn_tcp_target() -> TcpTarget {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定本地 TCP 目标");
    let addr = listener.local_addr().expect("目标地址");
    let state = Arc::new(Mutex::new(TargetState::default()));
    let sink = Arc::clone(&state);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            {
                let mut guard = sink.lock().expect("目标缓冲锁中毒");
                guard.accepts += 1;
            }
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                let _ = sock.set_nodelay(true);
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            sink.lock()
                                .expect("目标缓冲锁中毒")
                                .received
                                .extend_from_slice(&buf[..n]);
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    TcpTarget { addr, state }
}
