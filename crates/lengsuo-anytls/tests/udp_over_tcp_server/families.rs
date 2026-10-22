// 地址族三态（IPv4 `0x00` / IPv6 `0x01` / FQDN `0x02`）与 connect 模式往返。
//
// 本文件由 `tests/udp_over_tcp_server.rs` 用 `include!` 文本并入同一模块；`use` 与
// 共享助手（`Client` / `open_uot` / `push_bytes` / `collect_replies` / `spawn_udp_echo`）
// 都在入口文件与 harness，本文件只放用例。
//
// ⚠️ 家族字节走 **`uot.AddrParser`**（`0x00`/`0x01`/`0x02`），**不是** SOCKS5 ATYP；
// 流首地址与请求头目的地址才走 SOCKS5 ATYP。混用即整体错位。

/// 走一条 UoT 会话：请求地址按指定家族字节编码，回程载荷逐字节一致。
///
/// 返回回程报文（调用方据此断言回程的地址家族）。
async fn family_roundtrip(request_address: Address, echo: SocketAddr) -> Datagram {
    let mut client = Client::start(PASSWORD).await;
    client.settings(2).await;
    // 服务端回 ServerSettings（v2）。
    client.expect(Command::ServerSettings).await;

    let request = UotRequest {
        is_connect: false,
        destination: SocksAddr::Ipv4([127, 0, 0, 1], echo.port()),
    };
    open_uot(&mut client, 1, MAGIC_ADDRESS_V2, &request).await;
    // SYNACK（v2 才汇报，参考 `Stream.HandshakeSuccess`）。
    let ack = client.expect(Command::SynAck).await;
    assert!(ack.data.is_empty(), "SYNACK 不带错误文本");

    let payload = b"uot-family-payload";
    push_bytes(&mut client, 1, &uot_datagram(&request_address, payload)).await;

    let association = Association::new(UdpVersion::V2, request);
    let replies = collect_replies(&mut client, 1, &association, 1).await;
    assert_eq!(replies.len(), 1, "应收到一个回程报文");
    assert_eq!(replies[0].payload, payload, "回程载荷应逐字节一致");

    client.shutdown().await;
    replies.into_iter().next().expect("回程报文")
}

/// IPv4 家族（`0x00`）：报文地址写成 `0x00 | 4 字节 | 端口`。
#[tokio::test]
async fn address_family_ipv4_uses_uot_byte_0x00() {
    let echo = spawn_udp_echo("127.0.0.1:0").await;
    let reply = family_roundtrip(Address::Ipv4([127, 0, 0, 1], echo.port()), echo).await;
    assert_eq!(
        reply.address,
        Some(Address::Ipv4([127, 0, 0, 1], echo.port())),
        "回程源地址应还原成 IPv4（家族字节 0x00）"
    );
}

/// IPv6 家族（`0x01`）：报文地址写成 `0x01 | 16 字节 | 端口`。
#[tokio::test]
async fn address_family_ipv6_uses_uot_byte_0x01() {
    let echo = spawn_udp_echo("[::1]:0").await;
    let reply = family_roundtrip(
        Address::Ipv6(
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            echo.port(),
        ),
        echo,
    )
    .await;
    assert_eq!(
        reply.address,
        Some(Address::Ipv6(
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            echo.port()
        )),
        "回程源地址应是 IPv6（家族字节 0x01）"
    );
}

/// FQDN 家族（`0x02`）：报文地址写成 `0x02 | 长度(1B) | 域名 | 端口`。
///
/// 域名 `localhost` 在本机解析到 `127.0.0.1`（服务端优先 IPv4），因此回程源是 IPv4。
#[tokio::test]
async fn address_family_fqdn_uses_uot_byte_0x02() {
    let echo = spawn_udp_echo("127.0.0.1:0").await;
    let reply = family_roundtrip(Address::Fqdn("localhost".into(), echo.port()), echo).await;
    assert_eq!(
        reply.address,
        Some(Address::Ipv4([127, 0, 0, 1], echo.port())),
        "FQDN 解析到 IPv4 后回程源应是 IPv4"
    );
}

/// connect 模式（`isConnect=1`）：报文**不带**地址，目标固定为请求头里的目的地址。
///
/// 这是 UoT 的第二种形态（参考 `uot.Request{IsConnect}`），与上面的非 connect
/// 模式（报文自带地址）互为对照。
#[tokio::test]
async fn connect_mode_carries_no_address_and_targets_request_destination() {
    let echo = spawn_udp_echo("127.0.0.1:0").await;
    let mut client = Client::start(PASSWORD).await;
    client.settings(2).await;
    client.expect(Command::ServerSettings).await;

    let request = UotRequest {
        is_connect: true,
        destination: SocksAddr::Ipv4([127, 0, 0, 1], echo.port()),
    };
    open_uot(&mut client, 1, MAGIC_ADDRESS_V2, &request).await;
    client.expect(Command::SynAck).await;

    let payload = b"uot-connect-payload";
    // connect 模式的报文只有 `长度(2B) | 载荷`。
    push_bytes(
        &mut client,
        1,
        &Datagram {
            address: None,
            payload: payload.to_vec(),
        }
        .encode(true)
        .expect("报文可编码"),
    )
    .await;

    let association = Association::new(UdpVersion::V2, request);
    let replies = collect_replies(&mut client, 1, &association, 1).await;
    assert_eq!(replies.len(), 1, "应收到一个回程报文");
    assert_eq!(replies[0].payload, payload, "回程载荷应逐字节一致");
    assert_eq!(replies[0].address, None, "connect 模式的回程不带地址");

    client.shutdown().await;
}
