//! Xray 互通用例的**共享脚手架**：端口、回环 echo、时钟、PSK。
//!
//! 参考端固定为 `/home/ubuntu/ref/bin/xray`（Xray v26.3.27, d2758a0），
//! 由 `scripts/check_no_source_leak` 之外的 `support::launch` 校验基线版本。

use std::{
    net::Ipv4Addr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use lengsuo_ss2022::receiver::Clock;
use tokio::net::UdpSocket;

/// SS2022 ChaCha 方法名（参考 `shadowaead_2022/protocol.go:60`）。
pub(crate) const METHOD_NAME: &str = "2022-blake3-chacha20-poly1305";

/// 载荷档位：1 B 最小体 / 1500 B MTU 级 / 8000 B 大分片。
///
/// ⚠️ 不取 8192 B：Xray 走 sing `buf.Size = 8192`，超过即静默丢弃
/// （本仓 `tests/xray_udp.rs` 已实测：AES-128 对照组同样失败，与本卡改动无关）。
pub(crate) const PAYLOADS: [usize; 3] = [1, 1500, 8000];

/// 假 PSK：32 字节，与本卡固定向量同族但不同值（避免与固定向量混为一谈）。
pub(crate) fn psk() -> Vec<u8> {
    vec![0x5au8; 32]
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟应晚于纪元")
        .as_secs()
}

pub(crate) fn clock() -> Clock {
    Clock {
        unix_seconds: now_secs(),
        monotonic: Instant::now(),
    }
}

/// 起一个回环 echo：收到什么回什么。返回端口与任务句柄。
///
/// 只用于**本仓 → Xray** 方向：Xray 的 SS2022 入站解密后把载荷转发到这里，
/// echo 的明文回程再由 Xray 按 SS2022 响应方向加密送回。
pub(crate) async fn spawn_echo(expected: usize) -> (u16, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("echo 应可绑定");
    let port = socket.local_addr().expect("echo 应有本地地址").port();
    let handle = tokio::spawn(async move {
        let mut buffer = [0u8; 16384];
        for _ in 0..expected {
            let (received, peer) = socket.recv_from(&mut buffer).await.expect("echo 应收到包");
            socket
                .send_to(&buffer[..received], peer)
                .await
                .expect("echo 应回包");
        }
    });
    (port, handle)
}

/// 供 `xray_interop` 用的回环常量：无人监听的端口。
///
/// SS2022 的 UDP 线路上只承载「目标地址 + 载荷」，本仓直接回封同一载荷
/// 充当回程（与本仓 `tests/xray_udp.rs` 同款做法），不需要真的有 echo 服务。
pub(crate) const UNLISTENED_PORT: u16 = 18001;

/// Xray 客户端用的回环地址。
pub(crate) const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// 互通用例的兜底超时。
pub(crate) const INTEROP_TIMEOUT: Duration = Duration::from_secs(96);
