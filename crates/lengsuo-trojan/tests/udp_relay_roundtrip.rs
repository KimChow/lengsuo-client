//! UDP 关联中继的 Rust↔Rust 端到端用例（非忽略，不需要参考二进制）。
//!
//! 用 `tokio::io::duplex` 承载流侧，用真实回环 `UdpSocket` 承载出站侧，
//! 覆盖：三档载荷逐字节回显、同一关联内两个不同目标（不缓存首包地址）、
//! 零长度 keepalive、超长包 fail-closed、半关闭（停发仍收）。强度上限：这是本仓
//! 自建回环，**不**宣称与参考互通——参考互通见 `tests/xray_trojan_udp.rs`。

use std::net::SocketAddr;
use std::time::Duration;

use lengsuo_trojan::udp_relay::relay;
use lengsuo_trojan::{udp, TargetAddr};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(3);
/// 默认单包上限取参考服务端策略值。
const LIMIT: usize = lengsuo_trojan::stream::REFERENCE_MAX_DATAGRAM_PAYLOAD;

/// 起一个 UDP 回显服务：原样回写收到的每个数据报，返回其端口。
async fn spawn_udp_echo() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    port
}

fn v4_target(port: u16) -> TargetAddr {
    TargetAddr::V4([127, 0, 0, 1], port)
}

/// 本机的 `localhost` 是否**首选**解析到 IPv4 回环。
///
/// 平台差异：Windows 的 hosts 同时给出 `::1` 与 `127.0.0.1`，且 `ToSocketAddrs`
/// **先返回 `::1`**；Linux 多数发行版先返回 `127.0.0.1`。relay 拨号取
/// `to_socket_addrs` 的**首个**结果，因此判据必须是「首个是 IPv4 回环」——
/// 用 `any` 会在 Windows 上错误放行，然后必然失败并看起来像协议缺陷。
fn localhost_resolves_to_v4_loopback() -> bool {
    use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
    match ("localhost", 1u16).to_socket_addrs() {
        Ok(mut it) => {
            matches!(it.next(), Some(addr) if addr.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST))
        }
        Err(_) => false,
    }
}

/// 读回一个回程报文（流侧）。缓冲足以容纳最长地址 + 2 字节长度 + CRLF + 8 KiB 载荷。
async fn read_reply<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> (TargetAddr, Vec<u8>) {
    let mut buf = vec![0u8; 1 + 1 + 255 + 2 + 2 + 2 + 8192];
    let mut filled = 0usize;
    loop {
        match udp::decode_packet(&buf[..filled], LIMIT) {
            Ok(((addr, payload), _)) => return (addr, payload.to_vec()),
            Err(udp::Error::Truncated { .. }) => {
                use tokio::io::AsyncReadExt;
                let n = timeout(WAIT, reader.read(&mut buf[filled..]))
                    .await
                    .expect("回程超时")
                    .expect("回程读失败");
                assert!(n > 0, "对端在回程到达前关闭");
                filled += n;
            }
            Err(other) => panic!("回程报文非法 {other:?}"),
        }
    }
}

#[tokio::test]
async fn relay_echoes_three_payload_sizes_byte_exact() {
    timeout(WAIT, async {
        let echo_port = spawn_udp_echo().await;
        let target = v4_target(echo_port);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move { relay(server_read, server_write, LIMIT, WAIT).await });

        for size in [1usize, 512, 8192] {
            let payload = vec![0x42u8; size];
            let frame = udp::encode_packet(&target, &payload).unwrap();
            use tokio::io::AsyncWriteExt;
            client.write_all(&frame).await.unwrap();
            client.flush().await.unwrap();
            let (addr, reply) = read_reply(&mut client).await;
            assert_eq!(addr, target, "{size} 字节：回程地址须与请求一致");
            assert_eq!(reply, payload, "{size} 字节：回程须逐字节一致");
        }
        drop(client);
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_does_not_cache_first_packet_address() {
    timeout(WAIT, async {
        let first_port = spawn_udp_echo().await;
        let second_port = spawn_udp_echo().await;
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move { relay(server_read, server_write, LIMIT, WAIT).await });
        use tokio::io::AsyncWriteExt;

        // 同一关联内先后打两个不同目标，各自回程地址必须与各自请求一致。
        for (port, tag) in [(first_port, 0x01u8), (second_port, 0x02u8)] {
            let target = v4_target(port);
            let payload = vec![tag; 8];
            client
                .write_all(&udp::encode_packet(&target, &payload).unwrap())
                .await
                .unwrap();
            client.flush().await.unwrap();
            let (addr, reply) = read_reply(&mut client).await;
            assert_eq!(addr, target, "第 {tag} 包地址不得被首包地址覆盖");
            assert_eq!(reply, payload);
        }
        drop(client);
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_handles_zero_length_keepalive() {
    timeout(WAIT, async {
        let echo_port = spawn_udp_echo().await;
        let target = v4_target(echo_port);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move { relay(server_read, server_write, LIMIT, WAIT).await });
        use tokio::io::AsyncWriteExt;

        // 零长度包合法（keepalive 语义）：回程也是零长度，地址一致。
        client
            .write_all(&udp::encode_packet(&target, b"").unwrap())
            .await
            .unwrap();
        client.flush().await.unwrap();
        let (addr, reply) = read_reply(&mut client).await;
        assert_eq!(addr, target);
        assert!(reply.is_empty());
        drop(client);
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_rejects_oversize_packet_fail_closed() {
    timeout(WAIT, async {
        let echo_port = spawn_udp_echo().await;
        let target = v4_target(echo_port);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        // 上限压到 16：声明 32 字节载荷即 fail-closed。
        let task = tokio::spawn(async move { relay(server_read, server_write, 16, WAIT).await });
        use tokio::io::AsyncWriteExt;
        let payload = vec![0x7eu8; 32];
        client
            .write_all(&udp::encode_packet(&target, &payload).unwrap())
            .await
            .unwrap();
        client.flush().await.unwrap();
        let outcome = task.await.unwrap();
        assert!(
            matches!(outcome, Err(lengsuo_trojan::udp_relay::Error::Frame(_))),
            "超长包必须 fail-closed，得到 {outcome:?}"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_keeps_receiving_after_client_stops_sending() {
    timeout(WAIT, async {
        // 一个延迟回显的 UDP 目标：收到请求后先等一会再回，模拟“客户端停发仍收”。
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = socket.send_to(&buf[..n], peer).await;
        });
        let target = v4_target(port);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move { relay(server_read, server_write, LIMIT, WAIT).await });
        use tokio::io::AsyncWriteExt;

        // 发一包后**不再发**，休眠期读侧静默；回程仍须写出（不得因停发提前断开）。
        client
            .write_all(&udp::encode_packet(&target, b"late").unwrap())
            .await
            .unwrap();
        client.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        let (addr, reply) = read_reply(&mut client).await;
        assert_eq!(addr, target);
        assert_eq!(reply, b"late");
        drop(client);
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_reports_clean_eof_at_frame_boundary() {
    timeout(WAIT, async {
        let (client, server) = tokio::io::duplex(1024);
        let (server_read, server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move { relay(server_read, server_write, LIMIT, WAIT).await });
        // 无任何报文即关闭：在帧边界干净结束。
        drop(client);
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_reports_truncated_frame_as_error() {
    timeout(WAIT, async {
        let (mut client, server) = tokio::io::duplex(1024);
        let (server_read, server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move { relay(server_read, server_write, LIMIT, WAIT).await });
        use tokio::io::AsyncWriteExt;
        // 半帧（地址 + 长度字段，缺 CRLF 与载荷）随关闭一起送达 → fail-closed。
        let addr = v4_target(9999);
        let mut half = Vec::new();
        addr.encode_into(&mut half);
        half.extend_from_slice(&8u16.to_be_bytes());
        client.write_all(&half).await.unwrap();
        client.flush().await.unwrap();
        drop(client);
        let outcome = task.await.unwrap();
        assert!(
            matches!(outcome, Err(lengsuo_trojan::udp_relay::Error::Frame(_))),
            "残留半帧必须报错，得到 {outcome:?}"
        );
    })
    .await
    .unwrap();
}

/// 域名目标：经 `lookup_host` 解析 localhost，验证域名字段端到端可用。
#[tokio::test]
async fn relay_resolves_domain_target() {
    timeout(WAIT, async {
        // ⚠️ 实机取证（2026-10-20，本机 Windows）：`localhost` 的解析结果**随平台而异** ——
        // Windows 先返回 `[::1]`、Linux 通常先返回 `127.0.0.1`。本用例的 echo 只监听
        // IPv4 回环，若 relay 把域名解析到 `::1` 就永远收不到回程。
        // 这里先确认「本机把 localhost 解析到 IPv4 回环」，否则跳过（不冒充通过）。
        if !localhost_resolves_to_v4_loopback() {
            println!("skip relay_resolves_domain_target：本机 localhost 不解析到 IPv4 回环");
            return;
        }
        let echo_port = spawn_udp_echo().await;
        let target = TargetAddr::Domain("localhost".to_owned(), echo_port);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move { relay(server_read, server_write, LIMIT, WAIT).await });
        use tokio::io::AsyncWriteExt;
        client
            .write_all(&udp::encode_packet(&target, b"domain").unwrap())
            .await
            .unwrap();
        client.flush().await.unwrap();
        let (addr, reply) = read_reply(&mut client).await;
        // 回程地址是解析后的真实源（IPv4 回环），载荷逐字节一致。
        assert_eq!(addr, TargetAddr::V4([127, 0, 0, 1], echo_port));
        assert_eq!(reply, b"domain");
        drop(client);
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

/// 出站 socket 确实绑定到回环目标，收包源地址可核对（防“假转发”）。
#[tokio::test]
async fn relay_source_is_a_real_socket() {
    timeout(WAIT, async {
        let echo_port = spawn_udp_echo().await;
        let target = v4_target(echo_port);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move { relay(server_read, server_write, LIMIT, WAIT).await });
        use tokio::io::AsyncWriteExt;
        client
            .write_all(&udp::encode_packet(&target, b"probe").unwrap())
            .await
            .unwrap();
        client.flush().await.unwrap();
        let (addr, reply) = read_reply(&mut client).await;
        assert_eq!(reply, b"probe");
        // 回程地址的端口必须是目标端口（不是 0/伪造），地址族为 IPv4。
        match addr {
            TargetAddr::V4(ip, port) => {
                assert_eq!(ip, [127, 0, 0, 1]);
                assert_eq!(port, echo_port);
                let _ = SocketAddr::from((ip, port));
            }
            other => panic!("期望 IPv4 回程地址，得到 {other:?}"),
        }
        drop(client);
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}
