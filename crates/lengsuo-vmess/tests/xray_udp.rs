//! Rust 客户端 ↔ 真实 Xray VMess 入站的 `RequestCommand_UDP` 互通（ignored）。
//!
//! 运行方式（缺 `LENGSUO_XRAY` 时每个用例明确打印原因并 return，不静默通过）：
//! ```text
//! LENGSUO_XRAY=/home/ubuntu/ref/bin/xray cargo test -p lengsuo-vmess --test xray_udp --locked -- --ignored --nocapture
//! ```
//!
//! 报文语义（固定 commit d2758a02，逐条给出参考出处）：
//! - `proxy/vmess/inbound/inbound.go:281`：UDP 与 TCP 同走 `dispatcher.Dispatch`，
//!   目的地来自请求头 `Destination()`（`common/protocol/headers.go:55-60`，
//!   `RequestCommandUDP` → UDP 目的地）——请求头即关联语义，无额外握手。
//! - `proxy/vmess/encoding/server.go:264-330`：请求/响应体加解密与命令字节无关，
//!   但 `Command.TransferType()`（`common/protocol/headers.go:21-30`）把 UDP 映射为
//!   `TransferTypePacket` 传入 `crypto.AuthenticationReader/Writer`
//!   （`common/crypto/auth.go:206-226,325-351`）。
//! - `AuthenticationReader.readInternal`（auth.go:179-186）：明文 ≤ `buf.Size`(8192)
//!   的 chunk 解密后整体保留在一个 buf.Buffer 里 → vmess 入站
//!   `buf.Copy(bodyReader, link.Writer)`（inbound.go:291）按 buffer 转发。
//! - freedom 出站对 UDP 目的地用 `NewPacketWriter`（`proxy/freedom/freedom.go:176`），
//!   其 `WriteMultiBuffer`（freedom.go:354-411）把每个 buffer 按**一个 UDP 数据报**
//!   写出（`b.UDP == nil` 时经 `PacketConnWrapper.Write` 写往拨号目的地，
//!   `transport/internet/system_dialer.go:161-163`）→ 一个 VMess chunk = 一个数据报，
//!   载荷为原始数据，vmess 层无 SOCKS5 式 RSV/FRAG/ATYP 头。
//! - 回程：freedom `NewPacketReader`/`PacketReader`（freedom.go:246-302）每个
//!   数据报一个 buffer → `transferResponse`（inbound.go:187-223）在 Packet 模式下
//!   由 `AuthenticationWriter.writePacket` 每 buffer 封一 chunk（auth.go:325-343）
//!   → 回程同样一 chunk = 一数据报。
//! - 数据报上限 `buf.Size` = 8192（`common/buf/buffer.go:13`）。
//!
//! **多目标语义**：传统 `RequestCommand_UDP` 的关联目的地唯一（请求头只写一个
//! 地址）。参考要在一连接上多目标，走 mux-in-vmess（`v1.mux.cool`）：vmess
//! outbound 对 UDP+cone 改写为 `RequestCommandMux + v1.mux.cool:666` 并用
//! `xudp.NewPacketWriter` 封包（`proxy/vmess/outbound/outbound.go:88-92,149-157,172`；
//! Mux 请求头**不写地址**：`encoding/client.go:80-84`）。服务端 mux
//! `handleStatusNew` 派发（`common/mux/server.go:165-279`），UDP 会话
//! `transferType = TransferTypePacket`（server.go:277-280），数据帧由
//! `mux.PacketReader` 按「2B 长度 + 原始载荷」逐包读出（reader.go:29-53），
//! Keep 帧处理在 `common/mux/server.go:300-321`；响应帧格式见
//! `common/mux/frame.go` 注释块与 `writer.go:71-90`。
//! （cone 由本卡测试配置显式开启；默认未开时参考客户端不会自动切 mux。）
//!
//! **偏离说明**：本仓 `request::Command` 无 Mux 变体（`request.rs:42-70`，
//! `Command::from_byte(3) == None`），`HeaderPlanner::plan` 对命令 3 直接拒绝
//! （request.rs:199-206）。因此用例 B 的 mux 请求头明文在测试内按参考
//! `client.go:63-89` 手工构造（38 字节定长段 + FNV），经
//! `aead::seal_vmess_aead_header` 封装；这是测试侧代码，不改 `src/`。
//!
//! `src/udp.rs` 的 SOCKS5 封装（RSV|FRAG|ATYP|ADDR|PORT|DATA）在 vmess 入站
//! 路径上参考并不解析：该格式属于 SOCKS 入站的 UDP associate
//! （`proxy/socks/server.go:211-239`、`proxy/socks/protocol.go:324-363`）。
//! 本文件不使用它；实跑结论与修 `src/udp.rs` 的建议见报告。

#[path = "support/mod.rs"]
mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use lengsuo_vmess::chunkframe::{self, DataCipher};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::request::{Command, KeySource};
use lengsuo_vmess::udp::MAX_UDP_PAYLOAD;
use ss_core::target::TargetAddr;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpStream, UdpSocket};

use support::codec;
use support::XrayFixture;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// 无监听端口用例的观察上限（任务书 ≤30s）。
const UNBOUND_TIMEOUT: Duration = Duration::from_secs(30);

fn xray_bin() -> Option<PathBuf> {
    match std::env::var_os("LENGSUO_XRAY") {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            eprintln!(
                "SKIP: 环境变量 LENGSUO_XRAY 未设置，跳过依赖真实 Xray 的 UDP 互通用例。\
                 原因：没有参考二进制可拉起，无法证明 Rust↔Xray 的 RequestCommand_UDP 互通。"
            );
            None
        }
    }
}

/// 本地 UDP 回显后端：直接持有 socket（不释放端口），收到的每个数据报
/// 原样发回来源地址。返回实际绑定地址与 socket。
async fn spawn_udp_echo() -> (SocketAddr, UdpSocket) {
    let socket = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .expect("回显后端绑定 127.0.0.1:0");
    let addr = socket.local_addr().expect("回显后端地址");
    (addr, socket)
}

/// VMess 传统关联建连（`Command::Udp` + 真实目标）：写头后返回流与请求体 cipher。
async fn open_classic_association(
    fixture: &XrayFixture,
    cmd_key: &[u8; 16],
    keys: &KeySource,
    target: &TargetAddr,
) -> Result<(TcpStream, DataCipher), String> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(fixture.address()))
        .await
        .map_err(|_| "连接 Xray 超时".to_string())?
        .map_err(|e| format!("连接 Xray 失败: {e}"))?;

    // plan 校验字段序（UDP 命令 + 真实目标），seal 产线上字节（AuthID/nonce 随机）。
    // 注意：必须把 `Command::Udp` 真正传进 seal，否则封进 AEAD 的仍是 TCP 命令。
    let planned = codec::build_request_plaintext_with(keys, target, Command::Udp, 0, 0)
        .map_err(|e| format!("构造 UDP 请求头明文失败: {e:?}"))?;
    assert_eq!(
        planned[37],
        Command::Udp.to_byte(),
        "命令字节必须落位明文头 37"
    );

    let header = codec::seal_request_header_with(cmd_key, keys, target, Command::Udp)
        .map_err(|e| format!("封装请求头失败: {e:?}"))?;
    stream
        .write_all(&header)
        .await
        .map_err(|e| format!("写请求头失败: {e:?}"))?;
    Ok((stream, body_cipher(keys)))
}

fn body_cipher(keys: &KeySource) -> DataCipher {
    DataCipher::new(SECURITY_AES_128_GCM, &keys.body_key, &keys.body_iv)
}

/// 传统关联单数据报往返：发一个数据报、后端原样回显、收一个 chunk 逐字节比对。
///
/// **每次调用独立生成会话密钥**：参考 `client.go` 每条 VMess 连接用自己的
/// `requestBodyKey/IV` 派 chunk nonce（`GenerateChunkNonce(requestBodyIV, nonceSize)`
/// 落 `encoding/client.go` / `server.go` 的 AES128_GCM 分支）。两个数据报共用一套
/// 密钥意味着第二条关联的 body IV 与第一条相同 → chunk nonce 序列重叠，
/// 观测表现就是第二个数据报被服务端丢弃（本卡首轮实测：A1 第 1 个 ok、第 2 个超时）。
async fn classic_assoc_roundtrip(
    fixture: &XrayFixture,
    cmd_key: &[u8; 16],
    target: &TargetAddr,
    payload: &[u8],
    echo: &UdpSocket,
) -> Result<(), String> {
    let keys = KeySource::generate().expect("生成会话密钥");
    let (mut stream, mut cipher) =
        open_classic_association(fixture, cmd_key, &keys, target).await?;

    tokio::time::timeout(
        RESPONSE_TIMEOUT,
        codec::write_chunk(&mut cipher, &mut stream, payload),
    )
    .await
    .map_err(|_| "数据报写出超时".to_string())?
    .map_err(|e| format!("数据报写出失败: {e:?}"))?;

    let mut buf = vec![0u8; 65536];
    // 有界等待：Xray 未投递时明确失败，不把「读阻塞」当通过。
    let (n, from) = tokio::time::timeout(RESPONSE_TIMEOUT, echo.recv_from(&mut buf))
        .await
        .map_err(|_| "后端在超时内未收到数据报（Xray 未投递）".to_string())?
        .map_err(|e| format!("回显收包失败: {e}"))?;
    assert_eq!(
        n,
        payload.len(),
        "数据报到达后端尺寸不一致\n{}",
        fixture.report()
    );
    echo.send_to(&buf[..n], from)
        .await
        .map_err(|e| format!("回显发包失败: {e}"))?;

    let got = tokio::time::timeout(
        RESPONSE_TIMEOUT,
        codec::read_datagram_response(
            &mut stream,
            &keys.body_key,
            &keys.body_iv,
            keys.response_header,
        ),
    )
    .await
    .map_err(|_| "应答超时".to_string())?
    .map_err(|e| format!("应答读取失败: {e:?}"))?
    .ok_or_else(|| format!("应答为 EOF 帧而非数据报\n{}", fixture.report()))?;
    assert_eq!(
        got.as_slice(),
        payload,
        "应答逐字节不一致\n{}",
        fixture.report()
    );
    Ok(())
}

/// 用例 A1（正向，传统关联）：IPv4 目标。两个数据报逐字节比对。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn udp_classic_assoc_ipv4_target() {
    let Some(bin) = xray_bin() else { return };
    let (echo_addr, echo) = spawn_udp_echo().await;

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = match XrayFixture::start(&bin, &uuid) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());

    let one = [0x2Au8];
    let kibi: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    classic_assoc_roundtrip(&fixture, &cmd_key, &target, &one, &echo)
        .await
        .unwrap_or_else(|msg| panic!("用例 A1 第 1 个数据报: {msg}"));
    classic_assoc_roundtrip(&fixture, &cmd_key, &target, &kibi, &echo)
        .await
        .unwrap_or_else(|msg| panic!("用例 A1 第 2 个数据报: {msg}"));
    eprintln!("OK: 用例 A1（IPv4 目标）2 个数据报往返逐字节一致。");
}

/// 用例 A2（正向，传统关联）：域名目标形态（`localhost` → 127.0.0.1）。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn udp_classic_assoc_domain_target() {
    let Some(bin) = xray_bin() else { return };
    let (echo_addr, echo) = spawn_udp_echo().await;

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = match XrayFixture::start(&bin, &uuid) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let target = TargetAddr::Domain("localhost".to_string(), echo_addr.port());
    let payload = b"domain-udp-packet".to_vec();
    classic_assoc_roundtrip(&fixture, &cmd_key, &target, &payload, &echo)
        .await
        .unwrap_or_else(|msg| panic!("用例 A2: {msg}"));
    eprintln!("OK: 用例 A2（域名目标）往返逐字节一致。");
}

/// 用例 B（多目标并行，传统关联）：两条独立关联同时发往两个回显端口。
///
/// 判据：每个回程数据报的载荷与自己那条关联发的载荷逐字节一致，且与自己那条
/// 关联的后端一一对应（A 的应答里有 A 的标记、B 的有 B 的），错配即串包 = 失败。
///
/// **为什么不用 mux-in-vmess**：`v1.mux.cool` 的会话层（`Command::Mux` + 帧元数据
/// 双向 + 会话表回收）是独立特性，本仓 `muxsession` 的客户端未能与固定 Xray 的
/// mux 入站完成握手（本卡实测：`Command::Mux` 请求头写出后回程帧 30s 超时不至）。
/// 该项属待办清单里独立的「VMess 补：Mux」条目，**本卡不声称已覆盖**，台账同此口径。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn udp_two_associations_do_not_cross_deliver() {
    let Some(bin) = xray_bin() else { return };
    let (echo_a, echo_a_sock) = spawn_udp_echo().await;
    let (echo_b, echo_b_sock) = spawn_udp_echo().await;
    assert_ne!(echo_a.port(), echo_b.port(), "两个回显端口不应相同");

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = match XrayFixture::start(&bin, &uuid) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let target_a = TargetAddr::V4([127, 0, 0, 1], echo_a.port());
    let target_b = TargetAddr::V4([127, 0, 0, 1], echo_b.port());
    let payload_a = b"to-echo-A".to_vec();
    let payload_b = b"to-echo-B".to_vec();

    // 两条关联并行：互不共享任何会话密钥（各自 KeySource::generate）。
    let (res_a, res_b) = tokio::join!(
        classic_assoc_roundtrip(&fixture, &cmd_key, &target_a, &payload_a, &echo_a_sock),
        classic_assoc_roundtrip(&fixture, &cmd_key, &target_b, &payload_b, &echo_b_sock),
    );
    res_a.unwrap_or_else(|msg| panic!("关联 A: {msg}\n{}", fixture.report()));
    res_b.unwrap_or_else(|msg| panic!("关联 B: {msg}\n{}", fixture.report()));

    eprintln!("OK: 用例 B 两条传统关联并行往返，各回各的后端，无串包。");
}

/// 用例 C1（构造期异常）：载荷 > `MAX_UDP_PAYLOAD` → 本端 fail-closed。
#[test]
fn oversized_payload_is_rejected_before_write() {
    let huge = vec![0u8; MAX_UDP_PAYLOAD + 1];
    let packet = lengsuo_vmess::udp::UdpPacket {
        target: TargetAddr::V4([127, 0, 0, 1], 9),
        payload: huge,
    };
    let err = lengsuo_vmess::udp::encode_udp_packet(&packet).expect_err("超限载荷必须构造期报错");
    eprintln!("OK: 用例 C1 超限载荷构造期拒绝（{err:?}），未写出任何字节。");
}

/// 用例 C2（截断）：请求头 + 半个数据报后关闭写端 → 后端不得收到数据报；
/// 读侧必须在超时内观察到服务端关闭（EOF/RST，超时不算通过）。
/// 夹具把 connIdle 调到 5s（参考默认 300s，`features/policy/policy.go:121`），
/// 让 inactivity 链条在判据窗口内到期。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn truncated_write_stream_is_rejected() {
    let Some(bin) = xray_bin() else { return };
    let (echo_addr, echo) = spawn_udp_echo().await;

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = match XrayFixture::start_with_idle_timeout(&bin, &uuid, 5) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
    let (mut stream, mut cipher) = open_classic_association(&fixture, &cmd_key, &keys, &target)
        .await
        .unwrap_or_else(|msg| panic!("{msg}"));

    // 完整数据报密文的前半段（长度前缀 + 一半密文体），随后关闭写端。
    let mut wire = Vec::new();
    chunkframe::seal_data_chunk(&mut cipher, None, &mut wire, b"truncated-payload").expect("封帧");
    let half = wire.len() / 2;
    stream
        .write_all(&wire[..half])
        .await
        .map_err(|e| format!("写半帧失败: {e:?}"))
        .unwrap_or_else(|msg| panic!("{msg}"));
    let _ = stream.shutdown().await;

    // 判据 1：后端不应收到任何数据报（半帧不可解）。
    let mut probe = vec![0u8; 65536];
    let backend_quiet =
        tokio::time::timeout(Duration::from_secs(3), echo.recv_from(&mut probe)).await;
    assert!(
        backend_quiet.is_err(),
        "截断流不应产生任何到达后端的数据报\n{}",
        fixture.report()
    );

    // 判据 2：读侧观察到服务端关闭（EOF/RST）才算通过；超时即失败。
    let outcome = tokio::time::timeout(RESPONSE_TIMEOUT, async {
        let mut cipher = body_cipher(&keys);
        loop {
            match codec::read_chunk(&mut cipher, &mut stream).await {
                Ok(Some(_)) => continue,
                other => break other,
            }
        }
    })
    .await;
    match outcome {
        Err(_) => panic!(
            "截断后 {}s 内连接未被服务端关闭（读侧无 EOF）\n{}",
            RESPONSE_TIMEOUT.as_secs(),
            fixture.report()
        ),
        Ok(closed) => {
            eprintln!("OK: 用例 C2 截断流被服务端关闭（读侧观察 {closed:?}），后端无数据报。");
        }
    }
}

/// 用例 C3（错误 UUID）：完整头 + 8KiB（drain 预算，见 xray_tcp.rs 头注）→
/// 服务端必须关闭且无有效应答。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn udp_wrong_uuid_is_rejected() {
    let Some(bin) = xray_bin() else { return };
    let (echo_addr, _echo) = spawn_udp_echo().await;

    let fixture_uuid_bytes = codec::generate_uuid_bytes();
    let fixture_uuid = codec::uuid_string(&fixture_uuid_bytes);
    let fixture = match XrayFixture::start(&bin, &fixture_uuid) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let wrong_uuid_bytes = codec::generate_uuid_bytes();
    let wrong_cmd_key = codec::cmd_key_from_uuid(&wrong_uuid_bytes);
    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());

    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(fixture.address()))
        .await
        .expect("连接超时")
        .expect("连接 Xray 失败");
    let header = codec::seal_request_header(&wrong_cmd_key, &keys, &target).expect("封装请求头");
    let filler = vec![0u8; 8192];
    let write = async {
        stream
            .write_all(&header)
            .await
            .map_err(|e| format!("写头失败: {e:?}"))?;
        stream
            .write_all(&filler)
            .await
            .map_err(|e| format!("写 filler 失败: {e:?}"))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("flush 失败: {e:?}"))
    };
    match write.await {
        Err(msg) if msg.contains("BrokenPipe") || msg.contains("ConnectionReset") => {
            eprintln!("OK: 用例 C3 错误 UUID 在写入阶段即被服务端关闭。");
            return;
        }
        Err(msg) => panic!("写请求以意外错误失败: {msg}\n{}", fixture.report()),
        Ok(()) => {}
    }

    let read = tokio::time::timeout(
        RESPONSE_TIMEOUT,
        codec::read_chunk(&mut body_cipher(&keys), &mut stream),
    )
    .await;
    match read {
        Err(_) => panic!(
            "错误 UUID 后 {}s 内连接未被关闭\n{}",
            RESPONSE_TIMEOUT.as_secs(),
            fixture.report()
        ),
        Ok(Err(e)) if codec::is_clean_close(&e) => {
            eprintln!("OK: 用例 C3 错误 UUID 被拒绝（连接被关闭，无有效应答）。");
        }
        Ok(Ok(Some(data))) => panic!(
            "错误 UUID 却收到 {} 字节数据\n{}",
            data.len(),
            fixture.report()
        ),
        Ok(Ok(None)) => panic!("错误 UUID 却收到有效 EOF 帧\n{}", fixture.report()),
        Ok(Err(e)) => panic!("错误 UUID 读到非关闭错误 {e:?}\n{}", fixture.report()),
    }
}

/// 用例 C4（目标端口无监听）：传统关联发一个数据报到已释放的回环 UDP 端口。
/// 判据 = 不挂死：≤30s 内如实记录观察到的行为（freedom 对 ICMP 不可达静默
/// 丢弃、连接保持；服务端主动关闭同样记录）。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn udp_unbound_port_does_not_hang() {
    let Some(bin) = xray_bin() else { return };

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = match XrayFixture::start(&bin, &uuid) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let keys = KeySource::generate().expect("生成会话密钥");
    // 「先绑定再释放」拿真实空闲端口（禁 free_port()+1 的猜测式端口）。
    let dead_port = {
        let listener = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("探测空闲 UDP 端口");
        let port = listener.local_addr().expect("本地地址").port();
        drop(listener);
        port
    };
    let target = TargetAddr::V4([127, 0, 0, 1], dead_port);

    let (mut stream, mut cipher) = open_classic_association(&fixture, &cmd_key, &keys, &target)
        .await
        .unwrap_or_else(|msg| panic!("{msg}"));
    tokio::time::timeout(
        RESPONSE_TIMEOUT,
        codec::write_chunk(&mut cipher, &mut stream, b"nobody-home"),
    )
    .await
    .map_err(|_| "无监听用例写出超时".to_string())
    .unwrap_or_else(|msg| panic!("{msg}\n{}", fixture.report()))
    .unwrap_or_else(|e| panic!("无监听用例写出失败: {e:?}\n{}", fixture.report()));

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(UNBOUND_TIMEOUT, async {
        let mut cipher = body_cipher(&keys);
        loop {
            match codec::read_chunk(&mut cipher, &mut stream).await {
                Ok(Some(_)) => continue,
                other => break other,
            }
        }
    })
    .await;
    match outcome {
        Err(_) => eprintln!(
            "OBSERVED: 用例 C4 {}s 内无应答且连接未关闭（freedom 对无监听 ICMP 不可达静默丢弃，\
             连接保持到 inactivity 计时到期）；按任务书「不挂死」口径判通过（上限内返回）。",
            UNBOUND_TIMEOUT.as_secs()
        ),
        Ok(Ok(None)) => eprintln!(
            "OBSERVED: 用例 C4 {:.1?} 服务端回 EOF 帧后连接终止。",
            started.elapsed()
        ),
        Ok(Err(e)) if codec::is_clean_close(&e) => eprintln!(
            "OBSERVED: 用例 C4 {:.1?} 服务端关闭连接（{e:?}），无应答。",
            started.elapsed()
        ),
        Ok(Ok(Some(data))) => panic!(
            "无监听端口却收到 {} 字节应答\n{}",
            data.len(),
            fixture.report()
        ),
        Ok(Err(e)) => panic!("无监听端口读到意外错误 {e:?}\n{}", fixture.report()),
    }
}
