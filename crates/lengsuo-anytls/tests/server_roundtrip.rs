//! 服务端会话（`lengsuo_anytls::server`）的 Rust↔Rust 端到端用例。
//!
//! 这些用例**不需要**参考二进制，默认执行：用 `tokio::io::duplex` 直接驱动
//! `server::serve` 的帧循环，逐帧断言协议时序（Settings → ServerSettings/SYNACK、
//! 心跳回包、目标地址解析、字节转发、FIN 收尾），并用一条经真实 TLS 的用例覆盖
//! `server::tls` 的接受器装配。参考二进制互通另见 `interop_server_full.rs`（`#[ignore]`）。
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    padding::PaddingScheme,
    server::{self, tls, ServerConfig},
    Error,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(2);
const TOTAL: Duration = Duration::from_secs(10);
const PASSWORD: &[u8] = b"unit-test-password";

/// 在 `duplex` 管道的服务端半上跑会话，客户端半交回调用方。
struct Harness {
    client: tokio::io::DuplexStream,
    task: tokio::task::JoinHandle<Result<server::SessionStats, Error>>,
}

impl Harness {
    /// 建连接并完成认证（客户端侧）。
    async fn start(password: &[u8]) -> Self {
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

    async fn send(&mut self, frame: Frame) {
        frame.write(&mut self.client, WAIT).await.expect("写帧");
    }

    async fn recv(&mut self) -> Frame {
        // 服务端会按 padding 方案插入 Waste 填充帧（参考 writeConn）；参考客户端
        // recvLoop 对 cmdWaste 一律静默丢弃，这里同样跳过，只看真实语义帧。
        loop {
            let frame = Frame::read(&mut self.client, u16::MAX, WAIT)
                .await
                .expect("读帧");
            if frame.command != Command::Waste {
                return frame;
            }
        }
    }

    /// 读一帧并断言命令；返回帧。
    async fn expect(&mut self, command: Command) -> Frame {
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

    /// 杀掉客户端半，让服务端读到 EOF，返回会话统计。
    async fn finish(self) -> Result<server::SessionStats, Error> {
        drop(self.client);
        timeout(TOTAL, self.task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic")
    }
}

/// 回环 echo 目标：连接后原样回写直到 EOF。
async fn spawn_echo() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("echo 监听");
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            if socket.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// 客户端 Settings 帧：本模块的 `ServerState` 要求 v + client + padding-md5。
fn settings(padding_md5: &str) -> Frame {
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: format!("v=2\nclient=lengsuo-test\npadding-md5={padding_md5}").into_bytes(),
    }
}

/// 目标地址 + 载荷拼成首帧 PUSH（参考：地址是 SOCKS5 格式）。
fn push_with_target(addr: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let std::net::IpAddr::V4(v4) = addr.ip() else {
        panic!("测试固定 IPv4 回环");
    };
    let mut data = vec![0x01];
    data.extend_from_slice(&v4.octets());
    data.extend_from_slice(&addr.port().to_be_bytes());
    data.extend_from_slice(payload);
    data
}

// 用例按主题拆到 `tests/server_roundtrip/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。
//
// - `stream.rs`：正向路径 3 条（完整往返 / 跨帧地址 / 心跳）+ 真 TLS 装配那条，
//   以及它专属的助手（`next_semantic` / `TestPki` / `test_pki` / `tls_client`）。
// - `rejections.rs`：4 条 fail-closed 类（缺 Settings / 错误口令 / 空口令 / 超容量）。

include!("server_roundtrip/stream.rs");
include!("server_roundtrip/rejections.rs");
