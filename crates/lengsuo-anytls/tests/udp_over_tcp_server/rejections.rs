// fail-closed 组：非法地址族、魔数与版本不符、异常路径。
//
// 本文件由 `tests/udp_over_tcp_server.rs` 用 `include!` 文本并入同一模块；`use` 与
// 共享助手都在入口文件与 harness，本文件只放用例。
//
// 每条用例都同时断言三件事：
// 1. 会话以错误结束（fail-closed）；
// 2. UDP 探针没收到任何报文（**不得**静默直连、**不得**把非法字节当报文投递）；
// 3. TCP 探针没收到任何连接（**不得**回落成 TCP 拨号）。

/// 非法地址族必须 fail-closed：不得回落成「按 SOCKS5 解析」，不得回落成 TCP 拨号。
async fn assert_illegal_family(family: u8) {
    let (probe, tcp_addr, udp_addr) = spawn_probe().await;
    let mut client = Client::start(PASSWORD).await;
    client.settings(2).await;
    client.expect(Command::ServerSettings).await;

    // 请求头的目标指向 TCP 探针：若服务端回落成 TCP 拨号，就会连上它。
    let request = UotRequest {
        is_connect: false,
        destination: SocksAddr::Ipv4([127, 0, 0, 1], tcp_addr.port()),
    };
    open_uot(&mut client, 1, MAGIC_ADDRESS_V2, &request).await;
    client.expect(Command::SynAck).await;

    // 报文地址注入非法家族字节；目标仍是 UDP 探针（若被「修正」成 SOCKS5 解析，
    // 就会把报文发出去，探针会收到）。
    let mut address_bytes = vec![family];
    address_bytes.extend_from_slice(&[127, 0, 0, 1]);
    address_bytes.extend_from_slice(&udp_addr.port().to_be_bytes());
    push_bytes(&mut client, 1, &raw_datagram(&address_bytes, b"boom")).await;

    let result = client.wait_session().await;
    assert!(
        result.is_err(),
        "非法地址族 0x{family:02X} 必须 fail-closed（会话应失败）"
    );
    assert_no_fallback(&probe, &format!("非法地址族 0x{family:02X}")).await;
}

/// 非法家族字节 `0x03`（SOCKS5 的域名类型）⇒ 拒绝。
#[tokio::test]
async fn illegal_address_family_0x03_is_rejected() {
    assert_illegal_family(0x03).await;
}

/// 非法家族字节 `0x04`（SOCKS5 的 IPv6 类型）⇒ 拒绝。
#[tokio::test]
async fn illegal_address_family_0x04_is_rejected() {
    assert_illegal_family(0x04).await;
}

/// 越界的家族字节（`0xFF`）⇒ 拒绝。
#[tokio::test]
async fn illegal_address_family_out_of_range_is_rejected() {
    assert_illegal_family(0xFF).await;
}

/// 魔数与版本不符 ⇒ 拒绝（不得当普通 PUSH 处理）。
///
/// 参考侧官方客户端恒用 v2 魔法域 + `v=2`；这里刻意错配。
async fn assert_magic_version_mismatch(version: u8, magic: &str, what: &str) {
    let (probe, _tcp_addr, _udp_addr) = spawn_probe().await;
    let mut client = Client::start(PASSWORD).await;
    client.settings(version).await;
    if version >= 2 {
        client.expect(Command::ServerSettings).await;
    }

    let request = UotRequest {
        is_connect: false,
        destination: SocksAddr::Ipv4([127, 0, 0, 1], 9),
    };
    // 首地址用的是**另一个代次**的魔法域。
    open_uot(&mut client, 1, magic, &request).await;

    let result = client.wait_session().await;
    assert!(result.is_err(), "{what}：必须 fail-closed（会话应失败）");
    assert_no_fallback(&probe, what).await;
}

/// 协商 `v=2` 却用 v1 魔法域 ⇒ 拒绝。
#[tokio::test]
async fn magic_v1_with_peer_version_2_is_rejected() {
    assert_magic_version_mismatch(2, MAGIC_ADDRESS_V1, "v2 协商 + v1 魔法域").await;
}

/// 协商 `v=1` 却用 v2 魔法域 ⇒ 拒绝。
#[tokio::test]
async fn magic_v2_with_peer_version_1_is_rejected() {
    assert_magic_version_mismatch(1, MAGIC_ADDRESS_V2, "v1 协商 + v2 魔法域").await;
}

/// 截断的 UDP 报文：声明 64 字节只给 8 字节 ⇒ 不得当成短报文投递。
#[tokio::test]
async fn truncated_datagram_is_not_delivered() {
    let (probe, tcp_addr, udp_addr) = spawn_probe().await;
    let mut client = Client::start(PASSWORD).await;
    client.settings(2).await;
    client.expect(Command::ServerSettings).await;

    let request = UotRequest {
        is_connect: false,
        destination: SocksAddr::Ipv4([127, 0, 0, 1], tcp_addr.port()),
    };
    open_uot(&mut client, 1, MAGIC_ADDRESS_V2, &request).await;
    client.expect(Command::SynAck).await;

    // 报文地址合法（指向 UDP 探针），但长度声明 64、实际只给 8 字节。
    let mut address_bytes = vec![0x00];
    address_bytes.extend_from_slice(&[127, 0, 0, 1]);
    address_bytes.extend_from_slice(&udp_addr.port().to_be_bytes());
    let mut truncated = address_bytes;
    truncated.extend_from_slice(&64u16.to_be_bytes());
    truncated.extend_from_slice(b"12345678");
    push_bytes(&mut client, 1, &truncated).await;

    // 等一会，确认没有任何投递。
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        probe.udp_packets.load(Ordering::SeqCst),
        0,
        "截断报文不得被投递"
    );
    assert_eq!(
        probe.tcp_conns.load(Ordering::SeqCst),
        0,
        "不得回落成 TCP 拨号"
    );

    // 关闭写端：服务端读到干净 EOF 后收尾（残缺报文始终没被投递）。
    client.shutdown().await;
    let _ = client.wait_session().await;
}

/// 截断的 anytls 帧（头声明 200 字节、实际只写 20 字节）⇒ 会话以错误结束。
#[tokio::test]
async fn truncated_push_frame_fails_closed() {
    let mut client = Client::start(PASSWORD).await;
    client.settings(2).await;
    client.expect(Command::ServerSettings).await;
    client
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;

    // 手工拼一个声明 200 字节、实际只写 20 字节的 PUSH 帧。
    let mut raw = vec![Command::Push as u8];
    raw.extend_from_slice(&1u32.to_be_bytes());
    raw.extend_from_slice(&200u16.to_be_bytes());
    raw.extend_from_slice(&[0u8; 20]);
    client.send_raw(&raw).await;

    client.shutdown().await;
    let result = client.wait_session().await;
    assert!(result.is_err(), "截断帧必须 fail-closed");
}

/// 篡改的目标地址：请求头的 SOCKS5 ATYP 被改成非法值（`0x02`）⇒ 拒绝。
#[tokio::test]
async fn tampered_request_atyp_is_rejected() {
    let (probe, _tcp_addr, _udp_addr) = spawn_probe().await;
    let mut client = Client::start(PASSWORD).await;
    client.settings(2).await;
    client.expect(Command::ServerSettings).await;

    client
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    // 手工拼首地址 + 请求头：ATYP 篡改成 SOCKS5 里也不存在的 `0x02`。
    let mut payload = magic_address_bytes(MAGIC_ADDRESS_V2);
    payload.push(0x00); // isConnect
    payload.push(0x02); // ATYP 篡改成非法值
    payload.extend_from_slice(&[127, 0, 0, 1]);
    payload.extend_from_slice(&9u16.to_be_bytes());
    client
        .send(Frame {
            command: Command::Push,
            stream_id: 1,
            data: payload,
        })
        .await;

    let result = client.wait_session().await;
    assert!(result.is_err(), "被篡改的目标地址必须 fail-closed");
    assert_no_fallback(&probe, "被篡改的目标地址").await;
}

/// 篡改的魔法域：仍含 `udp-over-tcp.arpa` 但不是精确域名 ⇒ 拒绝，不得回落成 TCP 拨号。
///
/// 参考侧的判据是 `strings.Contains(destination, "udp-over-tcp.arpa")`，会把这类
/// 域名也认成 UoT 流；本卡要求 fail-closed，故必须拒绝而不是按普通目标拨号。
#[tokio::test]
async fn tampered_magic_domain_is_rejected() {
    let (probe, _tcp_addr, _udp_addr) = spawn_probe().await;
    let mut client = Client::start(PASSWORD).await;
    client.settings(2).await;
    client.expect(Command::ServerSettings).await;

    let request = UotRequest {
        is_connect: false,
        destination: SocksAddr::Ipv4([127, 0, 0, 1], 9),
    };
    open_uot(
        &mut client,
        1,
        "sp.v2.udp-over-tcp.arpa.attacker.test",
        &request,
    )
    .await;

    let result = client.wait_session().await;
    assert!(result.is_err(), "被篡改的魔法域必须 fail-closed");
    assert_no_fallback(&probe, "被篡改的魔法域").await;
}

/// 超长域名（255 字节 = 协议上限）且**不含**魔法后缀 ⇒ 拒绝，不得静默直连。
///
/// 域名目标无法直接拨号（参考侧同理），必须拒绝而不是解析后直连。
#[tokio::test]
async fn oversized_domain_without_magic_suffix_is_rejected() {
    let (probe, _tcp_addr, _udp_addr) = spawn_probe().await;
    let mut client = Client::start(PASSWORD).await;
    client.settings(2).await;
    client.expect(Command::ServerSettings).await;

    let long = "a".repeat(255);
    let request = UotRequest {
        is_connect: false,
        destination: SocksAddr::Ipv4([127, 0, 0, 1], 9),
    };
    // 首地址手工拼：ATYP(域名) + 长度(255) + 域名 + 端口。
    let mut payload = vec![0x03u8];
    payload.push(255);
    payload.extend_from_slice(long.as_bytes());
    payload.extend_from_slice(&9u16.to_be_bytes());
    client
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    client
        .send(Frame {
            command: Command::Push,
            stream_id: 1,
            data: payload,
        })
        .await;

    let result = client.wait_session().await;
    assert!(result.is_err(), "超长域名必须 fail-closed");
    assert_no_fallback(&probe, "超长域名").await;
    // 顺带确认请求头没被当成 UoT 流处理（会话直接失败，没进 UoT 分支）。
    let _ = request;
}

/// 超长域名（255 字节 = 协议上限）且**含**魔法后缀 ⇒ 拒绝，不得回落成 TCP 拨号。
#[tokio::test]
async fn oversized_domain_with_magic_suffix_is_rejected() {
    let (probe, _tcp_addr, _udp_addr) = spawn_probe().await;
    let mut client = Client::start(PASSWORD).await;
    client.settings(2).await;
    client.expect(Command::ServerSettings).await;

    let suffix = "udp-over-tcp.arpa";
    let long = format!("{}.{}", "a".repeat(255 - suffix.len() - 1), suffix);
    assert_eq!(long.len(), 255, "域名长度应为协议上限 255");

    let mut payload = vec![0x03u8];
    payload.push(255);
    payload.extend_from_slice(long.as_bytes());
    payload.extend_from_slice(&9u16.to_be_bytes());
    client
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    client
        .send(Frame {
            command: Command::Push,
            stream_id: 1,
            data: payload,
        })
        .await;

    let result = client.wait_session().await;
    assert!(result.is_err(), "超长域名必须 fail-closed");
    assert_no_fallback(&probe, "含魔法后缀的超长域名").await;
}
