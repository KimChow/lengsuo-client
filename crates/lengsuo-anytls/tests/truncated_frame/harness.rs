//! 截断帧用例的共用夹具：本仓服务端（真实 TCP）、可观测回环目标、握手助手。
//!
//! 形态照抄 `tests/tamper_matrix/harness.rs`（同一套「RustServer + Target」
//! 范式），但**不复用**它的模块：`tests/tamper_matrix/**` 已进官方门禁登记，
//! ⛔ 不得改动，故此处另起一份等价夹具。
//!
//! 全部夹具只用回环地址、临时端口与运行时生成的假口令；口令不进入任何日志
//! 或断言文本。
#![allow(dead_code)]
use lengsuo_anytls::{
    auth::Credential,
    frame::{self, Command, Eof, Frame},
    padding::PaddingScheme,
    server::{self, ServerConfig},
    Error,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 单次网络操作的等待上限。
pub const WAIT: Duration = Duration::from_secs(2);
/// 整条会话的等待上限。
pub const TOTAL: Duration = Duration::from_secs(10);

/// 运行时生成的假口令：只在本进程内使用，不写入任何日志或断言文本。
pub fn fake_password() -> Vec<u8> {
    // 每次运行取不同内容 ⇒ 不可能与任何真实凭据撞上；仅用于本机回环。
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("系统时钟")
        .as_nanos();
    format!("w4-anytls-trunc-{nanos:x}").into_bytes()
}

/// 会话结局：干净收尾 / fail-closed。
#[derive(Debug, Clone)]
pub enum Outcome {
    /// 服务端返回 `Ok(stats)`。
    Clean { streams_opened: usize },
    /// 服务端返回 `Err`。
    Failed {
        /// 错误描述（不含口令与载荷）。
        reason: String,
        /// EOF 分类（`None` = 不是 EOF 类错误，例如超时 / 连接重置）。
        eof: Option<Eof>,
    },
}

/// 本仓服务端夹具：真实 TCP 监听，收集每条连接的会话结局。
pub struct RustServer {
    pub addr: SocketAddr,
    outcomes: Arc<Mutex<Vec<Outcome>>>,
}

impl RustServer {
    pub async fn spawn(password: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听");
        let addr = listener.local_addr().expect("地址");
        let outcomes: Arc<Mutex<Vec<Outcome>>> = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&outcomes);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let password = password.clone();
                let collected = Arc::clone(&collected);
                tokio::spawn(async move {
                    let outcome =
                        match server::serve(socket, ServerConfig::new(&password, WAIT)).await {
                            Ok(stats) => Outcome::Clean {
                                streams_opened: stats.streams_opened,
                            },
                            Err(err) => Outcome::Failed {
                                reason: err.to_string(),
                                eof: frame::eof_kind(&err),
                            },
                        };
                    collected.lock().expect("结局锁").push(outcome);
                });
            }
        });
        Self { addr, outcomes }
    }

    /// 轮询等待第 `index` 条连接结束；超期即失败（不静默通过）。
    pub async fn await_outcome(&self, index: usize) -> Outcome {
        let deadline = std::time::Instant::now() + TOTAL;
        loop {
            if let Some(outcome) = self.outcomes.lock().expect("结局锁").get(index).cloned() {
                return outcome;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "第 {index} 条连接未在期限内结束"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// 可观测的回环目标：记录收到的全部字节与连接次数，并原样回显。
pub struct Target {
    pub addr: SocketAddr,
    pub accepted: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<u8>>>,
}

impl Target {
    pub fn received(&self) -> Vec<u8> {
        self.received.lock().expect("目标缓冲锁").clone()
    }
}

pub async fn spawn_target() -> Arc<Target> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("target 监听");
    let addr = listener.local_addr().expect("target 地址");
    let accepted = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(Mutex::new(Vec::new()));
    let (accept_sink, recv_sink) = (Arc::clone(&accepted), Arc::clone(&received));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            accept_sink.fetch_add(1, Ordering::SeqCst);
            let recv_sink = Arc::clone(&recv_sink);
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            recv_sink
                                .lock()
                                .expect("目标缓冲锁")
                                .extend_from_slice(&buffer[..count]);
                            // 原样回显：让服务端把回程 PUSH 送回客户端。
                            if socket.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Arc::new(Target {
        addr,
        accepted,
        received,
    })
}

/// 把 `Frame` 的 `Ok` 折叠成 `()`。
///
/// `Frame` **故意不派生 `Debug`**（免得应用载荷进诊断日志），因此
/// `Result<Frame, Error>` 不能直接用 `expect_err`。折叠后再断言错误。
pub fn discard(result: Result<Frame, Error>) -> Result<(), Error> {
    result.map(|_| ())
}

/// 客户端 Settings 帧（与参考一致：`v` / `client` / `padding-md5` 三项齐全）。
pub fn settings_frame() -> Frame {
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: format!(
            "v=2\nclient=lengsuo-test\npadding-md5={}",
            PaddingScheme::default_scheme().md5()
        )
        .into_bytes(),
    }
}

/// 认证 + Settings 协商，返回收到的第一条语义帧（跳过 Waste 填充）。
pub async fn handshake(stream: &mut TcpStream, password: &[u8]) -> Frame {
    Credential::new(password)
        .send(stream, b"", WAIT)
        .await
        .expect("认证发送");
    settings_frame()
        .write(stream, WAIT)
        .await
        .expect("写 Settings");
    loop {
        let frame = Frame::read(stream, u16::MAX, WAIT)
            .await
            .expect("读服务端帧");
        if frame.command != Command::Waste {
            return frame;
        }
    }
}

/// 目标地址 + 载荷拼成首帧 PUSH（参考：地址是 SOCKS5 格式）。
pub fn push_with_target(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let std::net::IpAddr::V4(v4) = addr.ip() else {
        panic!("测试固定 IPv4 回环");
    };
    let mut data = vec![0x01];
    data.extend_from_slice(&v4.octets());
    data.extend_from_slice(&addr.port().to_be_bytes());
    data.extend_from_slice(payload);
    data
}

/// 断开写端并排空读端，避免 close 时残留未读数据触发 RST。
pub async fn shutdown_write(stream: &mut TcpStream) {
    stream.shutdown().await.expect("半关闭写端");
    let mut sink = Vec::new();
    let _ = timeout(WAIT, stream.read_to_end(&mut sink)).await;
}
