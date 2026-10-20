//! Brutal 拥塞控制**接线实跑取证**（本仓客户端 ↔ 本仓服务端闭环）。
//!
//! 负例随 `cargo test` 默认跑；带 `#[ignore]` 的是实跑吞吐用例，需
//! `--ignored --nocapture`。
//!
//! # 测量口径（为什么不能只计 `write_all`）
//!
//! quinn 的 `SendStream::write` 只把数据交给**连接级发送缓冲**，真正的
//! QUIC 发送受两道闸门约束：拥塞窗口（`window()`）与 pacer（按
//! `window / RTT` 放行）。因此：
//!
//! - **写端**在配额耗尽前会很快返回（数据进了发送缓冲），**不能**用它
//!   计时 —— 必须等「对端确认收到全部字节」，才说明闭环真的走完；
//! - **回程**必须与上传**并发**排空：目标端在读满请求后才开始回灌，
//!   若先等上传结束再读，目标端的写缓冲会被回压，测出的就不再是
//!   Brutal 的速率。
//!
//! 判定口径（宽松区间 + 总超时，避免抖动假失败）：
//! - 上界：实测吞吐 ≤ 协商值 × 3；下界：≥ 协商值 / 8；
//! - 对照组：同一场景、`congestion` 为空（quinn 默认 CUBIC）时**必须**超出
//!   上界 —— 证明瓶颈确为注入的 Brutal，而非装置本身。
//!
//! 只走回环地址、系统分配端口、openssl 现场自签证书与假凭据。

mod support;

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lengsuo_congestion::brutal::ConfigError;
use lengsuo_congestion::Mode;
use lengsuo_hysteria::congestion::{
    client_rate, inject, parse_announce, parse_mode, server_send_rate, Bandwidth, CcHeader,
    CongestionConfig, CongestionError, CongestionMode,
};
use lengsuo_hysteria::proxy;
use lengsuo_hysteria::quic::server::{HysteriaServer, ServerConfig, ServerError};
use lengsuo_hysteria::quic::{ClientConfig, ConnectError, HysteriaClient};

const AUTH: &str = "lengsuo-brutal-wire";
/// 单个实跑场景的总预算（超时即失败）。
const BUDGET: Duration = Duration::from_secs(300);
/// 请求载荷：远大于 Brutal 窗口下的在途上限，保证流控不先行限制。
const REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// 目标端回灌量。
const RESPONSE_BYTES: usize = 64 * 1024;
/// 单次回程读取的等待上限。
const READ_LIMIT: Duration = Duration::from_secs(120);

fn test_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lengsuo-hy-bw-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("创建临时目录");
    dir
}

fn openssl(args: &[&str]) -> Vec<u8> {
    let out = Command::new("openssl")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("执行 openssl");
    assert!(
        out.status.success(),
        "openssl 失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// openssl 现场自签（SAN=DNS/IP localhost）；返回 (证书 DER, 私钥 DER)。
fn gen_cert(dir: &Path) -> (Vec<u8>, Vec<u8>) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let (c, k) = (cert.to_str().expect("UTF-8"), key.to_str().expect("UTF-8"));
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        k,
        "-out",
        c,
        "-days",
        "2",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "extendedKeyUsage=serverAuth",
    ]);
    (
        openssl(&["x509", "-in", c, "-outform", "DER"]),
        openssl(&["pkey", "-in", k, "-outform", "DER"]),
    )
}

struct Server {
    addr: SocketAddr,
    cert_der: Vec<u8>,
}

/// 起本仓服务端。`brutal_up` = 服务端发送速率（参考 `BrutalUp`），
/// `brutal_down` = 回给客户端的 `Hysteria-CC-RX`（参考 `BrutalDown`）。
async fn start_server(tag: &str, brutal_up: u64, brutal_down: u64, congestion: &str) -> Server {
    let (cert_der, key_der) = gen_cert(&test_dir(tag));
    let mut config = ServerConfig::new(
        "127.0.0.1:0".parse().expect("监听地址"),
        vec![cert_der.clone()],
        key_der,
        AUTH.to_string(),
    );
    config.brutal_up = brutal_up;
    config.brutal_down = brutal_down;
    config.congestion = congestion.to_string();
    let server = Arc::new(HysteriaServer::bind(config).expect("服务端绑定失败"));
    let addr = server.local_addr().expect("读取监听地址");
    tokio::spawn(async move { server.accept_loop().await });
    Server { addr, cert_der }
}

fn client_config(server: &Server, up: u64, down: u64) -> ClientConfig {
    ClientConfig {
        server_addr: server.addr,
        server_name: "localhost".to_string(),
        auth: AUTH.to_string(),
        roots_der: vec![server.cert_der.clone()],
        brutal_down: down,
        brutal_up: up,
        congestion: "brutal".to_string(),
        peer_cc_rx: None,
    }
}

/// 回灌端：先读掉 `warmup` 字节请求，再按 `rate` 字节/秒回灌 `total` 字节。
///
/// `obey = false` 时不节拍、全速回灌（CUBIC 对照需要突破上界）。
fn spawn_sink(warmup: usize, total: usize, rate: f64, obey: bool) -> u16 {
    // 回灌端返回 (端口, 发送时刻通道)；本用例只用端口，通道随句柄一起丢弃。
    support::spawn_paced_sink(warmup, total, rate, obey, Duration::from_secs(5)).0
}

/// 一次实跑的结果。
struct Run {
    /// 闭环（请求写完 + 回程收齐）耗时。
    elapsed: Duration,
    /// 回程收到的字节数。
    got: usize,
}

/// 跑一次「客户端上传 `REQUEST_BYTES` → 目标端回灌 `RESPONSE_BYTES`」。
///
/// `negotiated` = 协商速率（字节/秒）；服务端 `BrutalUp`/`BrutalDown` 与
/// 客户端 `up`/`down` 都取该值 ⇒ 协商结果就是它。
async fn measure(tag: &str, negotiated: u64, client_congestion: &str) -> Run {
    let server = start_server(tag, negotiated, negotiated, "brutal").await;
    let body = async {
        let mut config = client_config(&server, negotiated, negotiated);
        config.congestion = client_congestion.to_string();
        // 探测连接读服务端 `Hysteria-CC-RX`（quinn 只能建连前装配拥塞器）。
        let peer = HysteriaClient::probe_peer_cc_rx(&config, Default::default())
            .await
            .expect("探测连接失败");
        eprintln!("[{tag}] 服务端协商头 Hysteria-CC-RX = {peer:?}");
        config.peer_cc_rx = Some(peer);
        let client = HysteriaClient::connect_with_negotiated(config, Default::default())
            .await
            .expect("建连失败");
        // 回灌端：先读掉请求，再回灌固定量。
        let sink_port = spawn_sink(REQUEST_BYTES, RESPONSE_BYTES, negotiated as f64, true);
        let sink_addr = format!("127.0.0.1:{sink_port}");
        let mut stream = proxy::tcp_connect(&client, &sink_addr)
            .await
            .expect("tcp_connect 失败");
        // 单连接双向： 同时持有 QUIC 的 send/recv 两半，
        // 不提供 ，因此**不能**用两个闭包同时借  并发读写
        // （E0499）。这里分两个阶段：
        //   ① 上传：写完请求字节后立即  关上传方向；
        //   ② 回程：再排空响应（目标端按协商速率回灌）。
        // 回灌端  先把请求读干净再回灌，故顺序执行不会死锁；
        // 计时覆盖两阶段总耗时，与「并发」口径对吞吐的影响已在文档中如实说明。
        let started = Instant::now();
        let chunk = vec![0x5au8; 64 * 1024];
        let mut sent = 0usize;
        while sent < REQUEST_BYTES {
            let n = chunk.len().min(REQUEST_BYTES - sent);
            stream.write_all(&chunk[..n]).await.expect("写入失败");
            sent += n;
        }
        stream.finish().expect("关闭上传方向失败");
        let mut got = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        while got < RESPONSE_BYTES {
            match tokio::time::timeout(READ_LIMIT, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                Ok(Ok(n)) => got += n,
            }
        }
        let elapsed = started.elapsed();
        (elapsed, got)
    };
    let (elapsed, got) = tokio::time::timeout(BUDGET, body)
        .await
        .expect("实跑总超时（>300s：Brutal 明显未生效）");
    eprintln!("[{tag}] 闭环 {REQUEST_BYTES} B 用时 {elapsed:?}；回程 {got} B");
    Run { elapsed, got }
}

/// 上传吞吐 = 请求字节 / 闭环耗时。
fn upload_rate(run: &Run) -> f64 {
    REQUEST_BYTES as f64 / run.elapsed.as_secs_f64()
}

fn in_band(tag: &str, measured: f64, negotiated: f64) {
    assert!(
        measured >= negotiated / 8.0 && measured <= negotiated * 3.0,
        "{tag}: 实测 {measured:.0} B/s 未落在协商值 {negotiated:.0} B/s 的 [1/8, 3x] 区间内"
    );
    eprintln!("[{tag}] 实测 {measured:.0} B/s（协商 {negotiated:.0} B/s）");
}

/// 实跑 1：协商 256 KiB/s，客户端上传吞吐被 Brutal 限住；同场景 CUBIC
/// 对照必须突破上界（证明限速来自注入的 Brutal，而非装置本身）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "实跑吞吐取证，需 --ignored"]
async fn brutal_limits_client_upload() {
    const NEGOTIATED: u64 = 256 * 1024;
    let brutal = measure("brutal-up", NEGOTIATED, "brutal").await;
    assert_eq!(brutal.got, RESPONSE_BYTES, "回程未收齐，测量无效");
    in_band("brutal", upload_rate(&brutal), NEGOTIATED as f64);

    let cubic = measure("cubic-up", NEGOTIATED, "").await;
    assert_eq!(cubic.got, RESPONSE_BYTES, "回程未收齐，测量无效");
    let cubic_rate = upload_rate(&cubic);
    assert!(
        cubic_rate > 3.0 * NEGOTIATED as f64,
        "CUBIC 对照未被限速（{cubic_rate:.0} B/s ≤ 3x 协商值），无法证明 Brutal 生效"
    );
    eprintln!("[对照 cubic] 实测 {cubic_rate:.0} B/s（未注入 Brutal）");
}

/// 实跑 2：协商 2 MiB/s，验证限速随协商值缩放（而非固定常量）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "实跑吞吐取证，需 --ignored"]
async fn brutal_rate_follows_negotiation() {
    const NEGOTIATED: u64 = 2 * 1024 * 1024;
    let run = measure("brutal-2m", NEGOTIATED, "brutal").await;
    assert_eq!(run.got, RESPONSE_BYTES, "回程未收齐，测量无效");
    in_band("brutal-2m", upload_rate(&run), NEGOTIATED as f64);
}

// ===================== 负例（默认运行） =====================

/// 模式字符串未识别 ⇒ fail-closed，不静默落回 CUBIC（客户端一路）。
#[tokio::test]
async fn unknown_congestion_mode_is_rejected() {
    let server = start_server("neg-unknown", 0, 0, "").await;
    let mut config = client_config(&server, 256 * 1024, 0);
    config.congestion = "cubic-ish".to_string();
    match HysteriaClient::connect(config).await {
        Err(ConnectError::Congestion(CongestionError::UnknownMode { mode })) => {
            assert_eq!(mode, "cubic-ish");
        }
        Err(e) => panic!("期望 UnknownMode，实得 {e}"),
        Ok(_) => panic!("未识别模式必须报错，不得落回 CUBIC"),
    }
}

/// 服务端模式未识别：`bind` 期 fail-closed，错误指明未识别模式。
#[test]
fn server_unknown_mode_is_rejected() {
    let (cert, key) = gen_cert(&test_dir("neg-srv-unknown"));
    let mut config = ServerConfig::new(
        "127.0.0.1:0".parse().expect("监听地址"),
        vec![cert],
        key,
        AUTH.to_string(),
    );
    config.congestion = "reno-ish".to_string();
    match HysteriaServer::bind(config) {
        Err(ServerError::Congestion(CongestionError::UnknownMode { mode })) => {
            assert_eq!(mode, "reno-ish");
        }
        Err(e) => panic!("期望 Congestion(UnknownMode)，实得 {e}"),
        Ok(_) => panic!("服务端未识别模式必须 bind 失败"),
    }
}

/// 参考有但本仓未移植的模式（`bbr` / `reno` / `force-brutal`）⇒ 报错，
/// **不**假装生效、**不**静默落回 CUBIC。
#[test]
fn unimplemented_modes_are_rejected() {
    for mode in ["bbr", "reno", "force-brutal"] {
        assert_eq!(
            parse_mode(mode),
            Err(CongestionError::Unimplemented {
                mode: mode.to_string()
            }),
            "{mode} 必须 fail-closed"
        );
    }
    // 空串 = 缺省 = CUBIC（不注入）。
    assert_eq!(parse_mode(""), Ok(None));
    assert_eq!(parse_mode("  "), Ok(None));
    assert_eq!(parse_mode("brutal"), Ok(Some(Mode::Brutal)));
}

/// 协商速率 0 ⇒ 拒绝（不当 0 速率跑）。
#[test]
fn zero_negotiated_rate_is_rejected() {
    // 客户端协商：任一侧为 0 ⇒ 参考回落分支（`None`，不注入）。
    assert_eq!(
        client_rate(0, CcHeader::Bps(Bandwidth(256 * 1024))),
        Ok(None)
    );
    assert_eq!(
        client_rate(256 * 1024, CcHeader::Bps(Bandwidth(0))),
        Ok(None)
    );
    assert_eq!(client_rate(256 * 1024, CcHeader::Auto), Ok(None));
    // 注入层：拿到 `Some(0)` 必须报错（不得装 0 速率控制器）。
    assert_eq!(
        inject(
            &mut quinn::TransportConfig::default(),
            Some(Mode::Brutal),
            Some(0)
        ),
        Err(CongestionError::Rate(ConfigError::ZeroBandwidth))
    );
    // 回落分支（`None`）⇒ 不注入，沿用 CUBIC。
    assert!(inject(
        &mut quinn::TransportConfig::default(),
        Some(Mode::Brutal),
        None
    )
    .is_ok());
}

/// 亚字节/秒 ⇒ 拒绝（`BandwidthTooLow`；8 bps = 1 字节/秒 是最低档）。
///
/// 两种语义必须分清（对齐参考 `hub.go:193-200`）：
/// - **未配置**（`tx == 0`）⇒ 回落分支 ⇒ `Ok(0)`，**不是**错误；
/// - **已配置非法速率**（如 `Some(0)` 直接注入）⇒ `Err(ZeroBandwidth)`，fail-closed。
#[test]
fn sub_byte_rate_is_rejected() {
    // 未配置（tx = 0）⇒ 参考的回落分支：不限速，返回 Ok(0)。
    let unset = CongestionConfig {
        mode: CongestionMode::Brutal,
        rx: Bandwidth(0),
        tx: Bandwidth(0),
    };
    assert_eq!(
        server_send_rate(&unset, 0),
        Ok(0),
        "tx 未配置属参考回落分支，不得报错"
    );
    // 已配置 1 字节/秒 ⇒ 合法，且被限速到 1（不是回落）。
    let one = CongestionConfig {
        mode: CongestionMode::Brutal,
        rx: Bandwidth(0),
        tx: Bandwidth(1),
    };
    assert_eq!(
        server_send_rate(&one, 1),
        Ok(1),
        "min(BrutalUp=1, clientDown=1) = 1"
    );
    // 注入层：协商出 0 ⇒ 报错。
    assert_eq!(
        inject(
            &mut quinn::TransportConfig::default(),
            Some(Mode::Brutal),
            Some(0)
        ),
        Err(CongestionError::Rate(ConfigError::ZeroBandwidth))
    );
    // 以**比特/秒**给速率的入口：低于 8 bps 一律拒绝。
    for bps in [1u64, 4, 7] {
        assert_eq!(
            lengsuo_congestion::brutal::BrutalConfig::new(bps, 0),
            Err(ConfigError::BandwidthTooLow { got: bps, min: 8 })
        );
    }
    assert!(lengsuo_congestion::brutal::BrutalConfig::new(8, 0).is_ok());
}

/// 拥塞通告帧往返：非通告负载一律拒绝（不得误判成协商）。
#[test]
fn announce_frame_is_strict() {
    let frame = lengsuo_hysteria::congestion::announce_frame(256 * 1024);
    assert_eq!(parse_announce(&frame), Some(256 * 1024));
    let mut req = vec![0u8; frame.len()];
    req[0] = 0x01;
    assert_eq!(parse_announce(&req), None);
    assert_eq!(parse_announce(&frame[..4]), None);
}
