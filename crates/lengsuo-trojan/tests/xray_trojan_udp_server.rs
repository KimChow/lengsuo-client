//! **Xray 客户端 → 本仓 UDP 服务端**（反方向）互通（默认忽略）。
//!
//! 方向：Xray 以 socks5 入站（`udp: true`）+ trojan 出站的身份，把 UDP 流量
//! 经 trojan UDP 关联打到**本仓**的 trojan 服务端，由本仓转发到真实回环 UDP
//! 回显后端，回程再逐字节回到 Xray 与本用例。
//!
//! 夹具写法照抄 `tests/xray_trojan_client.rs`（rcgen 现场自签 + 显式信任、
//! 临时端口、假口令、回环回显后端），只是把方向反过来。
//!
//! 载荷分档按**参考侧实测上限** 8180 字节取（`tests/xray_trojan_udp.rs:34-38`
//! 有实测口径）：Xray 的 `PacketReader` 把整帧读入 `buf.Size = 8192` 的缓冲，
//! 帧头占用后余量有限，边界附近（8182 起）参考侧回程开始不稳定——那是**参考侧**
//! 限制，不是本仓限制；本仓 `udp::MAX_PAYLOAD_LEN` 仍按协议线上的 65535。
//! 因此**不用 65535 去卡参考侧**。

mod support;
mod udp_pool_support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::Value;
use support::{free_port, launch, WAIT};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use udp_pool_support::{
    socks5_udp_associate, socks5_udp_recv, socks5_udp_send, spawn_rust_tls_server, v4, Echo,
    Identity, REF_MAX,
};

const PASSWORD: &str = "trojan-udp-server-interop-password";
const TOTAL: Duration = Duration::from_secs(60);

/// Xray 客户端 → 本仓 UDP 服务端：1 / 512 / 8180 三档载荷逐字节回显。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_client_to_rust_udp_server_echo() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let echo = Echo::spawn().await;
        let (rust_port, rust_task) = spawn_rust_tls_server(&identity, PASSWORD).await;

        let socks = free_port();
        let config = udp_pool_support::xray_config(socks, rust_port, PASSWORD, &identity);
        let reference = launch(config, socks).await;

        // SOCKS5 UDP 关联：回程中继地址由服务端应答给出。
        let (relay, _control) = socks5_udp_associate(socks)
            .await
            .expect("socks UDP 关联失败");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = v4(echo.port);

        for size in [1usize, 512, REF_MAX] {
            let payload = vec![0x5au8; size];
            socks5_udp_send(&socket, relay, &target, &payload)
                .await
                .expect("发送 UDP 数据报失败");
            let (address, reply) = timeout(WAIT, socks5_udp_recv(&socket))
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{size} 字节：回程超时（回显后端累计收包 {}）",
                        echo.total.load(Ordering::SeqCst)
                    )
                })
                .unwrap_or_else(|error| panic!("{size} 字节：回程读失败 {error}"));
            assert_eq!(address, target, "{size} 字节：回程地址须与请求一致");
            assert_eq!(reply, payload, "{size} 字节：回程须逐字节一致");
        }

        // 独立观测面：回显后端确实收到三包（不是“回程看起来对”）。
        assert_eq!(echo.total.load(Ordering::SeqCst), 3, "回显后端应收到三包");
        assert_eq!(
            echo.peers.load(Ordering::SeqCst),
            1,
            "三包应来自同一个出站 socket"
        );

        drop(reference);
        rust_task.abort();
        let _ = timeout(WAIT, rust_task).await;
    })
    .await
    .unwrap();
}

/// Xray 客户端 → 本仓 UDP 服务端：同一关联内先后打两个不同目标，
/// 各自回程地址与载荷都必须对得上（不串包）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_client_to_rust_udp_server_two_targets() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let first = Echo::spawn().await;
        let second = Echo::spawn().await;
        let (rust_port, rust_task) = spawn_rust_tls_server(&identity, PASSWORD).await;

        let socks = free_port();
        let config = udp_pool_support::xray_config(socks, rust_port, PASSWORD, &identity);
        let reference = launch(config, socks).await;

        let (relay, _control) = socks5_udp_associate(socks)
            .await
            .expect("socks UDP 关联失败");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        for (echo, tag) in [(&first, 0x11u8), (&second, 0x22u8)] {
            let target = v4(echo.port);
            let payload = vec![tag; 32];
            socks5_udp_send(&socket, relay, &target, &payload)
                .await
                .expect("发送 UDP 数据报失败");
            let (address, reply) = timeout(WAIT, socks5_udp_recv(&socket))
                .await
                .expect("回程超时")
                .expect("回程读失败");
            assert_eq!(address, target, "回程地址不得被首包地址覆盖");
            assert_eq!(reply, payload, "回程载荷须逐字节一致");
        }

        // 独立观测面：两个后端各收一包。
        assert_eq!(first.total.load(Ordering::SeqCst), 1, "首目标须收到一包");
        assert_eq!(second.total.load(Ordering::SeqCst), 1, "次目标须收到一包");

        drop(reference);
        rust_task.abort();
        let _ = timeout(WAIT, rust_task).await;
    })
    .await
    .unwrap();
}

/// 反方向的失败矩阵：错误密码时 UDP 关联必须被拒（回环回显零收包），
/// 且连接被主动断开；用正确密码对照组证明观测面有效。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_client_wrong_password_udp_rejected() {
    timeout(TOTAL, async {
        const BAD_PASSWORD: &str = "trojan-udp-server-interop-wrong";
        let identity = Identity::new();
        let echo = Echo::spawn().await;
        let (rust_port, rust_task) = spawn_rust_tls_server(&identity, PASSWORD).await;

        // 对照组：正确密码真的建立关联并把包送到业务后端。
        {
            let socks = free_port();
            let config = udp_pool_support::xray_config(socks, rust_port, PASSWORD, &identity);
            let reference = launch(config, socks).await;
            let (relay, _control) = socks5_udp_associate(socks)
                .await
                .expect("socks UDP 关联失败");
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = v4(echo.port);
            socks5_udp_send(&socket, relay, &target, b"probe")
                .await
                .expect("发送 UDP 数据报失败");
            let (address, reply) = timeout(WAIT, socks5_udp_recv(&socket))
                .await
                .expect("回程超时")
                .expect("回程读失败");
            assert_eq!(address, target);
            assert_eq!(reply, b"probe");
            drop(reference);
        }
        assert_eq!(
            echo.total.load(Ordering::SeqCst),
            1,
            "对照组必须抵达业务后端"
        );

        // 错误密码：不得把包送到业务后端。
        let before = echo.total.load(Ordering::SeqCst);
        let socks = free_port();
        let config = udp_pool_support::xray_config(socks, rust_port, BAD_PASSWORD, &identity);
        let reference = launch(config, socks).await;
        let (relay, _control) = socks5_udp_associate(socks)
            .await
            .expect("socks UDP 关联失败");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = v4(echo.port);
        socks5_udp_send(&socket, relay, &target, b"leak")
            .await
            .expect("发送 UDP 数据报失败");
        // 观察窗内不得有回程：服务端已拒绝 ⇒ 不写回任何字节。
        let leaked = timeout(Duration::from_millis(800), socks5_udp_recv(&socket))
            .await
            .is_ok();
        assert!(!leaked, "错误密码不得收到任何回程");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            echo.total.load(Ordering::SeqCst),
            before,
            "错误密码不得把包送到业务后端"
        );

        drop(reference);
        rust_task.abort();
        let _ = timeout(WAIT, rust_task).await;
    })
    .await
    .unwrap();
}

/// 配置只读断言：确保反方向用的是 socks5（UDP 开启）+ trojan 出站组合。
#[test]
fn xray_config_shape_is_socks_udp_to_trojan() {
    let identity = Identity::new();
    let config: Value = udp_pool_support::xray_config(1234, 5678, "pw", &identity);
    assert_eq!(config["inbounds"][0]["protocol"], "socks");
    assert_eq!(config["inbounds"][0]["settings"]["udp"], true);
    assert_eq!(config["outbounds"][0]["protocol"], "trojan");
}
