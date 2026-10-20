//! Brutal 拥塞器的**端到端**验证：协商速率真的把实际吞吐限制在协商值以内。
//!
//! # 覆盖范围（与任务书一致）
//!
//! 本卡要求的端到端用例是「本仓客户端 + 本仓服务端」。那需要
//! `lengsuo-hysteria` 的 QUIC 客户端/服务端 + H3 认证 + CC 头协商，
//! 而 `crates/lengsuo-hysteria` 正被另一张卡（`w4-hysteria-0rtt-server`）
//! 占用，**本卡不得触碰**（touches 越界）。故此处用**同一份协商值**接入
//! 一个 quinn-to-quinn 的回环连接来验证拥塞器内核：把
//! `negotiate_*_rate` 的产物（字节/秒）经 `BrutalConfig::from_bytes_per_sec`
//! 注入 `TransportConfig`，实测吞吐**不高于**协商值。
//!
//! 跨 crate 的完整接线（客户端/服务端 + CC 头）由主理人在 0-RTT 卡收尾后
//! 统一做，详见 `docs/congestion-status.md` 的「接线建议」。
//!
//! # 断言策略
//!
//! 吞吐断言用**宽松区间 + 总超时**，不做精确值断言（避免抖动导致假失败）。
//! 上界取协商值的 3 倍（留足余量给窗口/节奏闸门的实现差异与调度抖动），
//! 下界取协商值的 1/8（证明「速率确实生效」而不是「完全没在传」）。

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::runtime::{block_on, StdRuntime};
use lengsuo_congestion::brutal::BrutalConfig;
use quinn::Runtime;

/// 端到端用例的总超时。
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);

/// 协商速率（字节/秒）：1 MiB/s。
const NEGOTIATED_BYTES_PER_SEC: u64 = 1024 * 1024;

/// 实测吞吐的**上界**倍数（宽松区间，避免抖动导致假失败）。
const UPPER_SLACK: f64 = 2.0;

/// 实测吞吐的**下界**比例（证明确实在传数据）。
const LOWER_RATIO: f64 = 0.125;

/// 传输时长（测量窗口）。
const MEASURE: Duration = Duration::from_secs(2);

/// 构造服务端 `TransportConfig`（按变体选择拥塞器）。
fn server_transport(variant: Variant) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    match variant {
        Variant::Brutal => {
            // 注入协商速率：与协议 crate 的 `BrutalConfig::from_bytes_per_sec` 同一路径。
            let config = BrutalConfig::from_bytes_per_sec(NEGOTIATED_BYTES_PER_SEC, 0)
                .expect("协商速率合法");
            transport.congestion_controller_factory(Arc::new(config));
        }
        Variant::Cubic => {
            // 对照组：quinn 默认 CUBIC。
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
    }
    Arc::new(transport)
}

/// 构造客户端 `TransportConfig`（按变体选择拥塞器）。
fn client_transport(variant: Variant) -> Arc<quinn::TransportConfig> {
    server_transport(variant)
}

/// 拥塞器选择：Brutal（注入协商速率）或 CUBIC（quinn 默认）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    /// 注入 Brutal 拥塞器（协商速率生效）。
    Brutal,
    /// quinn 默认 CUBIC（对照组）。
    Cubic,
}

/// 跑一轮「客户端持续发送 → 服务端接收」并返回实测速率（字节/秒）。
fn measure_throughput(variant: Variant) -> f64 {
    let runtime = Arc::new(StdRuntime);

    // ---- 服务端 ----
    let server_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("绑定服务端");
    server_socket.set_nonblocking(true).expect("非阻塞");
    let server_addr = server_socket.local_addr().expect("服务端地址");

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(common::tls::server_config())
            .expect("QUIC 服务端 TLS"),
    ));
    server_config.transport_config(server_transport(variant));

    let server = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        server_socket,
        runtime.clone(),
    )
    .expect("服务端端点");

    // ---- 客户端 ----
    let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("绑定客户端");
    client_socket.set_nonblocking(true).expect("非阻塞");

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(common::tls::client_config())
            .expect("QUIC 客户端 TLS"),
    ));
    client_config.transport_config(client_transport(variant));

    let mut client = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        client_socket,
        runtime.clone(),
    )
    .expect("客户端端点");
    client.set_default_client_config(client_config);

    // ---- 服务端任务：收满即回 ACK 计数 ----
    let received = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let received_task = Arc::clone(&received);
    let server_runtime = Arc::clone(&runtime);
    let server_endpoint = server.clone();
    let spawn_runtime = Arc::clone(&runtime);
    spawn_runtime.spawn(Box::pin(async move {
        while let Some(incoming) = server_endpoint.accept().await {
            let counter = Arc::clone(&received_task);
            let inner_runtime = Arc::clone(&server_runtime);
            let spawner = Arc::clone(&inner_runtime);
            spawner.spawn(Box::pin(async move {
                let connection = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                while let Ok(mut stream) = connection.accept_uni().await {
                    let counter = Arc::clone(&counter);
                    let stream_runtime = Arc::clone(&inner_runtime);
                    let stream_spawner = Arc::clone(&stream_runtime);
                    stream_spawner.spawn(Box::pin(async move {
                        // 增量读取：流未结束时也能累计已收字节。
                        loop {
                            match stream.read_chunk(usize::MAX, false).await {
                                Ok(Some(chunk)) => {
                                    counter.fetch_add(
                                        chunk.bytes.len() as u64,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                }
                                Ok(None) => break,
                                Err(_) => break,
                            }
                        }
                    }));
                }
            }));
        }
    }));

    // ---- 客户端：建连 + 持续发送 ----
    let connecting = client.connect(server_addr, "localhost").expect("发起连接");
    let connection = block_on(connecting, TOTAL_TIMEOUT).expect("握手完成");

    let mut send = block_on(connection.open_uni(), TOTAL_TIMEOUT).expect("开流");

    let payload = vec![0u8; 64 * 1024];
    let start = Instant::now();
    let mut sent = 0u64;
    while start.elapsed() < MEASURE {
        // 写超时保护：单个流写入超过 10 秒就放弃（避免整体卡死）。
        match block_on(
            async {
                send.write_all(&payload).await?;
                Ok::<(), std::io::Error>(())
            },
            Duration::from_secs(10),
        ) {
            Ok(()) => sent += payload.len() as u64,
            Err(_) => break,
        }
    }
    let elapsed = start.elapsed().as_secs_f64();

    // 等待服务端收完（宽裕一点）。
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && received.load(std::sync::atomic::Ordering::Relaxed) < sent {
        std::thread::sleep(Duration::from_millis(50));
    }

    let got = received.load(std::sync::atomic::Ordering::Relaxed);
    client.close(0u32.into(), b"done");
    server.close(0u32.into(), b"done");

    if elapsed <= 0.0 {
        return 0.0;
    }
    got as f64 / elapsed
}

/// 端到端：协商速率真的生效（实测吞吐不高于协商值的宽松上界）。
#[test]
fn negotiated_rate_caps_actual_throughput() {
    let rate = measure_throughput(Variant::Brutal);
    let expected = NEGOTIATED_BYTES_PER_SEC as f64;
    eprintln!("实测吞吐 {rate} B/s（协商值 {expected} B/s）");

    assert!(
        rate > 0.0,
        "端到端未测到任何吞吐（{rate} B/s），用例无法证明速率生效"
    );
    assert!(
        rate <= expected * UPPER_SLACK,
        "实测吞吐 {rate} B/s 超过协商值 {expected} B/s 的 {UPPER_SLACK} 倍上界"
    );
    assert!(
        rate >= expected * LOWER_RATIO,
        "实测吞吐 {rate} B/s 远低于协商值 {expected} B/s 的下界（比率 {LOWER_RATIO}）"
    );
}

/// 端到端对照：Brutal 的吞吐被协商速率压住，而 CUBIC 不受此约束。
///
/// 这个对照组的意义：如果去掉 Brutal 拥塞器（改用 quinn 默认 CUBIC），
/// 吞吐会显著**高于**协商值 ⇒ 证明上界是拥塞器**主动限速**的结果，
/// 而不是回环网络本身的吞吐上限。
///
/// 断言用宽松区间（CUBIC 至少要比 Brutal 高 2 倍），避免抖动导致假失败。
#[test]
fn brutal_is_slower_than_cubic_at_the_same_negotiated_rate() {
    let brutal = measure_throughput(Variant::Brutal);
    let cubic = measure_throughput(Variant::Cubic);
    eprintln!(
        "实测：brutal={brutal} B/s, cubic={cubic} B/s（协商值 {NEGOTIATED_BYTES_PER_SEC} B/s）"
    );

    assert!(
        brutal > 0.0 && cubic > 0.0,
        "对照组未测到吞吐（brutal={brutal} B/s, cubic={cubic} B/s）"
    );
    assert!(
        cubic > brutal * 2.0,
        "CUBIC 吞吐 {cubic} B/s 未显著高于 Brutal 的 {brutal} B/s —— \
         无法证明协商速率真的在限速"
    );
}
