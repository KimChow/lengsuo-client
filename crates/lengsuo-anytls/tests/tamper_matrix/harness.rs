//! 篡改矩阵共用夹具：duplex 会话夹具、可观测回环目标、真实 TCP 服务端。
//!
//! 形态照抄 `tests/lifecycle.rs`（`Harness`/`Target`/`RustServer`），
//! 但**不复用**它的模块：`tests/lifecycle.rs` 与 `tests/lifecycle/` 已进官方
//! 门禁登记，⛔ 不得改动，故此处另起一份等价夹具。
//!
//! 全部夹具只用回环地址、临时端口与假凭据；口令不进入任何日志或断言文本。
#![allow(dead_code)]
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    padding::PaddingScheme,
    server::{self, ServerConfig},
    Error,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

/// 单次网络操作的等待上限。
pub const WAIT: Duration = Duration::from_secs(2);
/// 整条会话的等待上限。
pub const TOTAL: Duration = Duration::from_secs(10);
/// 测试口令：仅本模块内部使用，不出现在任何日志或断言文本里。
pub const PASSWORD: &[u8] = b"tamper-fixture-password";

/// duplex 管道上的会话夹具：服务端跑 `server::serve`，客户端半交回调用方。
pub struct Harness {
    /// 客户端半（可直接写原始字节做篡改）。
    pub client: tokio::io::DuplexStream,
    task: tokio::task::JoinHandle<Result<server::SessionStats, Error>>,
}

impl Harness {
    /// 建连接并完成认证（客户端侧）。
    pub async fn start(password: &[u8]) -> Self {
        let (client, server_side) = tokio::io::duplex(64 * 1024);
        let config = ServerConfig::new(password, WAIT);
        let task = tokio::spawn(server::serve(server_side, config));
        let mut harness = Self { client, task };
        Credential::new(password)
            .send(&mut harness.client, b"", WAIT)
            .await
            .expect("认证发送");
        harness
    }

    /// 写一帧。
    pub async fn send(&mut self, frame: Frame) {
        frame.write(&mut self.client, WAIT).await.expect("写帧");
    }

    /// 直接写出原始字节（用于送出篡改后的帧字节）。
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        timeout(WAIT, async {
            self.client.write_all(bytes).await.expect("写原始字节");
            self.client.flush().await.expect("刷新");
        })
        .await
        .expect("写原始字节超时");
    }

    /// 读一帧（跳过 Waste 填充帧）；出错时返回错误而不 panic。
    pub async fn try_recv(&mut self) -> Result<Frame, Error> {
        loop {
            let frame = Frame::read(&mut self.client, u16::MAX, WAIT).await?;
            if frame.command != Command::Waste {
                return Ok(frame);
            }
        }
    }

    /// 读一帧（跳过 Waste 填充帧）。
    pub async fn recv(&mut self) -> Frame {
        self.try_recv().await.expect("读帧")
    }

    /// 读一帧并断言命令；返回帧。
    pub async fn expect(&mut self, command: Command) -> Frame {
        let frame = self.recv().await;
        assert_eq!(
            frame.command,
            command,
            "帧命令不符：期望 {command:?}，实际 {:?}（sid={}, len={}）",
            frame.command,
            frame.stream_id,
            frame.data.len()
        );
        frame
    }

    /// 杀掉客户端半，让服务端读到 EOF，返回会话统计（`Err` = 会话以失败结束）。
    pub async fn finish(self) -> Result<server::SessionStats, Error> {
        drop(self.client);
        timeout(TOTAL, self.task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic")
    }

    /// **不**关闭客户端半，等服务端自己的读超时先触发，返回会话统计。
    ///
    /// 用于「长度改大」这类判据：若先把客户端半关掉，EOF 会掩盖
    /// 「等不到那么多字节」这个真正的拒绝原因。
    pub async fn settle(self) -> Result<server::SessionStats, Error> {
        let Self { client, task } = self;
        let result = timeout(TOTAL, task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic");
        drop(client);
        result
    }
}

/// 客户端 Settings 帧：本仓 `ServerState` 要求 v + client + padding-md5。
pub fn settings() -> Frame {
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

/// 可观测的回环目标：记录收到的全部字节与连接次数，并原样回显。
pub struct Target {
    /// 目标地址（供首帧 PUSH 携带）。
    pub addr: SocketAddr,
    /// 接受的连接数：用于断言「流只被打开一次」或「从未被拨号」。
    pub accepted: AtomicUsize,
    received: Mutex<Vec<u8>>,
}

impl Target {
    /// 目标收到的全部字节。
    pub fn received(&self) -> Vec<u8> {
        self.received.lock().expect("目标缓冲锁").clone()
    }
}

/// 启动可观测的回环目标（回显）。
pub async fn spawn_target() -> Arc<Target> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("target 监听");
    let addr = listener.local_addr().expect("target 地址");
    let target = Arc::new(Target {
        addr,
        accepted: AtomicUsize::new(0),
        received: Mutex::new(Vec::new()),
    });
    let handle = Arc::clone(&target);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            handle.accepted.fetch_add(1, Ordering::SeqCst);
            let handle = Arc::clone(&handle);
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            handle
                                .received
                                .lock()
                                .expect("目标缓冲锁")
                                .extend_from_slice(&buffer[..count]);
                            if socket.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    target
}

/// 会话结局：干净收尾 or fail-closed。
#[derive(Debug, Clone)]
pub enum Outcome {
    /// 干净收尾（对端正常关闭，或 EOF 时缓冲为空）。
    Clean {
        /// 打开的流数。
        streams_opened: usize,
    },
    /// fail-closed：协议违规或传输错误。
    Failed {
        /// 错误描述（不含口令与载荷）。
        reason: String,
    },
}

/// 已启动的本仓服务端：监听地址 + 各连接的会话结局。
pub struct RustServer {
    /// 监听地址。
    pub addr: SocketAddr,
    outcomes: Arc<Mutex<Vec<Outcome>>>,
}

impl RustServer {
    /// 启动本仓 AnyTLS 服务端（真实 TCP），返回监听地址与会话结局收集器。
    pub async fn spawn(password: &[u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("监听");
        let addr = listener.local_addr().expect("地址");
        let outcomes: Arc<Mutex<Vec<Outcome>>> = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&outcomes);
        let password = password.to_vec();
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
                            },
                        };
                    collected.lock().expect("结局锁").push(outcome);
                });
            }
        });
        Self { addr, outcomes }
    }

    /// 已结束的连接数。
    pub fn finished(&self) -> usize {
        self.outcomes.lock().expect("结局锁").len()
    }

    /// 第 `index` 个连接的结局（`None` = 该连接尚未结束）。
    pub fn outcome(&self, index: usize) -> Option<Outcome> {
        self.outcomes.lock().expect("结局锁").get(index).cloned()
    }

    /// 轮询等待第 `index` 个连接结束；超期即失败（不静默通过）。
    pub async fn await_outcome(&self, index: usize, total: Duration) -> Outcome {
        let deadline = Instant::now() + total;
        loop {
            if let Some(outcome) = self.outcome(index) {
                return outcome;
            }
            assert!(Instant::now() < deadline, "第 {index} 条连接未在期限内结束");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// 帧字节的偏移：命令字节 / 长度字段（参考 `proxy/session/frame.go:37-49`）。
pub const CMD_OFFSET: usize = 0;
/// 长度字段（BE16）偏移。
pub const LEN_OFFSET: usize = 5;

/// 对已编码的帧做单比特翻转（用于「改 1 bit」类篡改）。
pub fn flip_bit(bytes: &mut [u8], offset: usize) {
    bytes[offset] ^= 0x01;
}

/// 覆写帧头里的长度字段（BE16）。
pub fn set_length(bytes: &mut [u8], length: u16) {
    bytes[LEN_OFFSET..LEN_OFFSET + 2].copy_from_slice(&length.to_be_bytes());
}

/// 取帧头里声明的长度（BE16）。
pub fn declared_length(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[LEN_OFFSET], bytes[LEN_OFFSET + 1]])
}
