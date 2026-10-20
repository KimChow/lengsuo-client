//! 公网真实流量重组取证：SS2022 原语 → anytls TLS 隧道 → 公网 → VPS。
//!
//! 与 `vps_tcp.rs` 的分工：后者只断言「读到真实公网 SSH banner」，本文件断言
//! **回程重组后的字节流与发出载荷逐字节相等**，覆盖重组（跨 SS2022 chunk、跨 TCP
//! 分片）而不是只读首片，并逐档留证。
//!
//! 两条公网路径跑同一套逐档断言：
//! - [`Transport::LocalXray`]：本仓原语 → 本机 Xray SS2022 入站（回环）→ socks →
//!   anytls-client → **anytls TLS 隧道（公网）** → VPS anytls-server → VPS 回显服务。
//!   载荷字节经公网传输，对端是参考 Xray SS2022 服务端。
//! - [`Transport::VpsReference`]：本仓原语 → 本机 socks → anytls-client → **anytls
//!   TLS 隧道（公网）** → VPS anytls-server → **VPS 参考 Xray SS2022 入站** → VPS
//!   回显服务。此路径上**本仓 SS2022 线上字节本身全程经公网传输**，且由参考 Xray
//!   SS2022 服务端收发。
//!
//! ⚠️ anytls 的 SOCKS5 目标地址是**在 VPS 一侧**解析的（参考
//! `anytls-go/cmd/server/outbound_tcp.go`：`proxyOutboundTCP` 用
//! `SystemDialer.DialContext` 直连 `destination.String()`），因此路径 B 的中继
//! 地址必须写成 VPS 能自己解析到的形式（回环地址）。
//!
//! 参考对齐（`sing-shadowsocks` 参考树，commit 33d5391）：
//! - `shadowaead_2022/protocol.go`：`MaxPacketSize = 65535`，写侧按此切分 ⇒ 大档位
//!   的回程必然跨多个 SS2022 chunk，验证的是「重组」而不是「读首片」。
//! - `shadowaead_2022/service.go`：`serverConn.writeResponse` 把响应固定头与首批载荷
//!   合并，响应方向没有变长头；本 crate 的 `Reader::open` 按此解析。
//! - `shadowaead/aead.go`：`Reader.Read` 单次只取一个 chunk 的内容并缓存余量 ⇒
//!   重组由调用方按 chunk 边界累积。
//!
//! 运行前提（仓外注入；仓内不写真实公网地址、主机绝对路径与真实凭据）：
//! - `SS2022_VPS=1`：显式开启公网用例（未设置时默认跳过，CI 默认套件不跑）。
//! - `SS2022_ECHO_TARGET`：VPS 侧回显服务 `host:port`（默认 `127.0.0.1:9000`）。
//! - `SS2022_VPS_RELAY`：VPS 上参考 Xray SS2022 入站的 `host:port`（公网地址）。
//! - `SS2022_PSK_BYTES`：口令原始字节，逗号分隔十进制（默认假口令 16×0x11）。
use lengsuo_ss2022::crypto::{Key, Method};
use lengsuo_ss2022::tcp::receive::clock_at;
use lengsuo_ss2022::tcp::{Direction, Reader, SessionReplay, Writer};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 本机 Xray SS2022 入站（回环）；其出站是 socks → anytls-client → 公网。
const LOCAL_SS2022_INBOUND: &str = "127.0.0.1:25002";
/// 本机 anytls-client 的 socks5 入口（回环）；出站是 anytls TLS 隧道 → 公网。
const LOCAL_SOCKS5: &str = "127.0.0.1:31080";
/// 单条用例总超时（秒）：覆盖全部载荷档位。
const CASE_TIMEOUT_SECS: u64 = 240;
/// 单次 chunk 读超时（秒）。
const READ_TIMEOUT_SECS: u64 = 30;
/// 变长头 padding 长度（字节）：SIP022 允许 0..=900。
const HEADER_PADDING: u16 = 8;
/// 单个载荷 chunk 上限（SIP022 `MaxPacketSize = 65535`）。
const CHUNK_MAX: usize = 65535;
/// 逐档载荷长度（字节）。末档 131071 = 65535×2+1，必然跨多个 SS2022 chunk 与
/// 多个 TCP 分片。
const SIZE_LADDER: [usize; 6] = [1, 64, 1024, 8192, 65535, 131_071];

/// 公网链路开关：必须显式 `SS2022_VPS=1`。
fn public_link_enabled() -> bool {
    std::env::var("SS2022_VPS").as_deref() == Ok("1")
}

/// VPS 侧回显服务地址（`host:port`），仓外注入。
fn echo_target() -> String {
    std::env::var("SS2022_ECHO_TARGET").unwrap_or_else(|_| "127.0.0.1:9000".to_string())
}

/// VPS 上参考 Xray SS2022 入站地址（`host:port`），仓外注入。
fn vps_relay() -> Option<String> {
    std::env::var("SS2022_VPS_RELAY")
        .ok()
        .filter(|v| !v.is_empty())
}

/// 口令原始字节：仓外注入，缺省用仓内假口令（16×0x11）。
fn psk_bytes() -> Vec<u8> {
    match std::env::var("SS2022_PSK_BYTES") {
        Ok(raw) => raw
            .split(',')
            .filter_map(|part| part.trim().parse::<u8>().ok())
            .collect(),
        Err(_) => vec![0x11; 16],
    }
}

/// 把 `host:port` 解析成目标地址；IPv4 字面量走 `TargetAddr::V4`，其余走域名。
fn parse_target(spec: &str) -> ss_core::target::TargetAddr {
    let (host, port) = spec.rsplit_once(':').expect("目标必须是 host:port");
    let port: u16 = port.parse().expect("端口必须是 u16");
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => ss_core::target::TargetAddr::V4(ip.octets(), port),
        Err(_) => ss_core::target::TargetAddr::Domain(host.to_string(), port),
    }
}

/// 最小 SOCKS5 客户端（无认证）：用于把 SS2022 线上字节送进 anytls-client。
async fn socks5_connect(proxy: &str, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 协商失败",
        ));
    }
    let mut request = vec![0x05, 0x01, 0x00];
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            request.push(0x03);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "SOCKS5 CONNECT 被拒",
        ));
    }
    // 丢弃 BND.ADDR/BND.PORT。
    match reply[3] {
        0x01 => {
            let mut bound = [0u8; 4 + 2];
            stream.read_exact(&mut bound).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut bound = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut bound).await?;
        }
        0x04 => {
            let mut bound = [0u8; 16 + 2];
            stream.read_exact(&mut bound).await?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 地址类型未知",
            ))
        }
    }
    Ok(stream)
}

/// 公网链路的两条走法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// 本仓原语 → 本机 Xray SS2022 入站 → socks → anytls → 公网 → VPS 回显。
    LocalXray,
    /// 本仓原语 → socks → anytls → 公网 → VPS 参考 Xray SS2022 入站 → VPS 回显。
    VpsReference,
}

impl Transport {
    fn label(self) -> &'static str {
        match self {
            Self::LocalXray => "本机 Xray SS2022 入站 → anytls 隧道 → 公网 → VPS 回显",
            Self::VpsReference => "本机 socks → anytls 隧道 → 公网 → VPS 参考 Xray SS2022 入站",
        }
    }
}

/// 一条已建立的 SS2022 会话（本仓客户端方向）。
struct Session {
    stream: TcpStream,
    writer: Writer,
    reader: Reader,
    replay: SessionReplay,
    /// 本端请求 salt：响应固定头必须原样回传它。
    request_salt: Vec<u8>,
    /// 请求头写出的 Unix 秒：响应固定头的时间戳按此做 ±30 秒窗口校验。
    now: u64,
    /// 响应方向开场已收到的首批载荷（参考服务端把首批载荷并入响应固定头）。
    first_payload: Vec<u8>,
}

/// 按指定走法建立 SS2022 会话（只写请求头，**不**读响应）。
///
/// 参考 `shadowaead_2022/service.go` 的 `serverConn.writeResponse` 只有在上游
/// 真的产生数据时才写出响应固定头；所以请求侧必须先把载荷送出去，响应头才会在
/// 上游回数据时到达。开局与载荷写出解耦，见 [`Session::read_response_header`]。
async fn open_session(transport: Transport, target: &ss_core::target::TargetAddr) -> Session {
    let key = Key::new(Method::Aes128, &psk_bytes()).expect("口令长度必须匹配套件");
    let stream = match transport {
        Transport::LocalXray => TcpStream::connect(LOCAL_SS2022_INBOUND)
            .await
            .expect("连接本机 Xray SS2022 入站"),
        Transport::VpsReference => {
            let relay = vps_relay().expect("需要 SS2022_VPS_RELAY 指向 VPS 参考 Xray SS2022 入站");
            let (host, port) = relay.rsplit_once(':').expect("中继地址必须是 host:port");
            let port: u16 = port.parse().expect("中继端口必须是 u16");
            socks5_connect(LOCAL_SOCKS5, host, port)
                .await
                .expect("经 anytls socks 建立到 VPS 参考 Xray SS2022 入站的隧道")
        }
    };
    let mut stream = stream;
    let mut writer = Writer::random(&key, Direction::Request).expect("请求 writer");
    let request_salt = writer.salt().to_vec();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("系统时钟")
        .as_secs();
    writer
        .write_request_header(&mut stream, target, b"", now, HEADER_PADDING)
        .await
        .expect("请求头");
    let reader = Reader::new(
        key,
        Direction::Response,
        Duration::from_secs(READ_TIMEOUT_SECS),
    )
    .expect("响应 reader");
    let replay = SessionReplay::new(Duration::from_secs(60)).expect("重放记忆池");
    Session {
        stream,
        writer,
        reader,
        replay,
        request_salt,
        now,
        first_payload: Vec::new(),
    }
}

/// 发出载荷：按 SIP022 `MaxPacketSize` 上限切分写出，首批留空。
///
/// 载荷 = `长度前缀(u32be) | 载荷体`。长度前缀是 VPS 侧回显服务的应用层协议：
/// 它据此知道何时收齐整段并回送，避免依赖「客户端半关闭」这种与服务端实现
/// 绑定的触发方式。
async fn send_payload(session: &mut Session, payload: &[u8]) {
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    let mut written = 0usize;
    while written < framed.len() {
        let take = framed.len().min(CHUNK_MAX).min(framed.len() - written);
        session
            .writer
            .write_payload(&mut session.stream, &framed[written..written + take])
            .await
            .expect("写出载荷 chunk");
        written += take;
    }
}

impl Session {
    /// 读取并认证响应固定头（参考服务端的响应固定头兼第一个 length chunk）。
    async fn read_response_header(&mut self) {
        let opened = self
            .reader
            .open(
                &mut self.stream,
                &mut self.replay,
                clock_at(self.now, Instant::now()),
                Some(self.request_salt.as_slice()),
            )
            .await
            .expect("公网响应头应通过认证");
        self.first_payload = opened.payload;
    }
}

/// 读回**恰好** `expected` 字节：有界读取，绝不 `read_to_end`。
///
/// 返回 (字节流, 收到的 chunk 数)。chunk 数用于证明大档位确实跨多个 chunk
/// 重组，而不是只读到首片。
async fn read_exact_bytes(session: &mut Session, expected: usize) -> (Vec<u8>, usize) {
    let mut received = Vec::with_capacity(expected);
    let mut chunks = 0usize;
    if !session.first_payload.is_empty() {
        received.extend_from_slice(&session.first_payload);
        chunks += 1;
    }
    while received.len() < expected {
        match session.reader.read_payload(&mut session.stream).await {
            Ok(Some(chunk)) => {
                received.extend_from_slice(&chunk);
                chunks += 1;
            }
            Ok(None) => break,
            Err(error) => panic!(
                "读取回程载荷失败（已收 {} 字节）：{error:?}",
                received.len()
            ),
        }
    }
    (received, chunks)
}

/// 逐档跑完长度阶梯并逐字节断言。
async fn run_ladder(transport: Transport) {
    let target = parse_target(&echo_target());
    for size in SIZE_LADDER {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let mut session = open_session(transport, &target).await;
        // 先发载荷：参考 SS2022 服务端只有在上游产生数据后才写响应固定头。
        send_payload(&mut session, &payload).await;
        session.read_response_header().await;
        let (received, chunks) = read_exact_bytes(&mut session, size).await;
        assert_eq!(
            received.len(),
            size,
            "长度 {size} 档：回程字节数应与发出载荷相同"
        );
        assert_eq!(
            received, payload,
            "长度 {size} 档：回程重组后的字节流必须与发出载荷逐字节相等"
        );
        // 参考写侧按 `MaxPacketSize = 65535` 切分 ⇒ 超过该长度的档位回程必然跨
        // 多个 SS2022 chunk（进而跨多个 TCP 分片）。chunk 数 ≥ 2 即证明断言验的是
        // **重组**而不是「读首片就当全部」。
        if size > CHUNK_MAX {
            assert!(
                chunks >= 2,
                "长度 {size} 档：回程应跨多个 SS2022 chunk，实际只有 {chunks} 个"
            );
        }
        println!(
            "长度 {size} 档：回程重组 {size} 字节（{chunks} 个 SS2022 chunk），逐字节相等 ✓（{}）",
            transport.label()
        );
        // 关闭连接，让 VPS 侧回显服务的读侧收尾。
        drop(session);
    }
}

/// 路径 A：本仓原语 ↔ 本机 Xray SS2022 入站；载荷经 anytls TLS 隧道过公网到 VPS。
#[tokio::test]
#[ignore = "需要公网 VPS 环境"]
async fn public_link_reassembly_via_local_xray() {
    if !public_link_enabled() {
        eprintln!("跳过：需要 SS2022_VPS=1 与公网隧道");
        return;
    }
    timeout(
        Duration::from_secs(CASE_TIMEOUT_SECS),
        run_ladder(Transport::LocalXray),
    )
    .await
    .expect("路径 A 总超时");
}

/// 路径 B：本仓 SS2022 线上字节本身经 anytls TLS 隧道过公网，由 VPS 参考 Xray
/// SS2022 入站收发。
#[tokio::test]
#[ignore = "需要公网 VPS 环境"]
async fn public_link_reassembly_via_vps_reference_server() {
    if !public_link_enabled() {
        eprintln!("跳过：需要 SS2022_VPS=1 与公网隧道");
        return;
    }
    if vps_relay().is_none() {
        eprintln!("跳过：需要 SS2022_VPS_RELAY 指向 VPS 参考 Xray SS2022 入站");
        return;
    }
    timeout(
        Duration::from_secs(CASE_TIMEOUT_SECS),
        run_ladder(Transport::VpsReference),
    )
    .await
    .expect("路径 B 总超时");
}

/// 公网对端身份取证：同一条公网链路上读到**另一台机器**的 SSH banner。
#[tokio::test]
#[ignore = "需要公网 VPS 环境"]
async fn public_link_reads_remote_ssh_banner() {
    if !public_link_enabled() {
        eprintln!("跳过：需要 SS2022_VPS=1 与公网隧道");
        return;
    }
    timeout(Duration::from_secs(CASE_TIMEOUT_SECS), async {
        let target = ss_core::target::TargetAddr::V4([127, 0, 0, 1], 22);
        let mut session = open_session(Transport::LocalXray, &target).await;
        // SSH 服务端主动先发 banner；参考 SS2022 服务端收到上游数据时才写响应
        // 固定头（`serverConn.writeResponse`），所以这里**不需要**先发载荷。
        session.read_response_header().await;
        let mut banner = session.first_payload.clone();
        while banner.len() < 8 {
            match session.reader.read_payload(&mut session.stream).await {
                Ok(Some(chunk)) => banner.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(error) => panic!("读取 SSH banner 失败：{error:?}"),
            }
        }
        let text = String::from_utf8_lossy(&banner).to_string();
        println!("经公网隧道读到的 SSH banner: {}", text.trim_end());
        assert!(
            banner.starts_with(b"SSH-"),
            "公网隧道后必须读到真实 SSH banner"
        );
    })
    .await
    .expect("SSH banner 取证总超时");
}
