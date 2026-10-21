// 协商推导（对齐 hub.go / dialer.go 的 switch）：客户端与服务端两侧的速率推导。
/// 客户端：`min(local up, server down)`，缺参回落 BBR（None）。
#[test]
fn negotiate_client_brutal_branch() {
    let local = CongestionConfig::new(CongestionMode::Brutal, BW(0), BW(10_000_000)).unwrap();

    // 正常 min。
    assert_eq!(
        negotiate_client_rate(&local, CcHeader::Bps(BW(4_000_000))),
        Some(4_000_000)
    );
    // 服务端更高 → 取本地 up。
    assert_eq!(
        negotiate_client_rate(&local, CcHeader::Bps(BW(99_000_000))),
        Some(10_000_000)
    );
    // 服务端 "auto" → 回落 BBR（None）。
    assert_eq!(negotiate_client_rate(&local, CcHeader::Auto), None);
    // 服务端 down=0 → 回落 BBR。
    assert_eq!(negotiate_client_rate(&local, CcHeader::Bps(BW(0))), None);

    // 本地 up=0 → 回落 BBR（即使服务端给了值）。
    let local_no_up = CongestionConfig::new(CongestionMode::Brutal, BW(0), BW(0)).unwrap();
    assert_eq!(
        negotiate_client_rate(&local_no_up, CcHeader::Bps(BW(4_000_000))),
        None
    );
}

/// 客户端 `force-brutal` 不做 min，直接用本地 up。
#[test]
fn negotiate_client_force_brutal_ignores_server() {
    let local = CongestionConfig::new(CongestionMode::ForceBrutal, BW(0), BW(10_000_000)).unwrap();
    assert_eq!(
        negotiate_client_rate(&local, CcHeader::Bps(BW(1))),
        Some(10_000_000)
    );
    assert_eq!(
        negotiate_client_rate(&local, CcHeader::Auto),
        Some(10_000_000)
    );
}

/// `reno` / `bbr` 均不改 Brutal 速率（None）。
#[test]
fn negotiate_client_reno_bbr_are_none() {
    let reno = CongestionConfig::new(CongestionMode::Reno, BW(0), BW(10_000_000)).unwrap();
    let bbr = CongestionConfig::new(CongestionMode::Bbr, BW(0), BW(10_000_000)).unwrap();
    assert_eq!(
        negotiate_client_rate(&reno, CcHeader::Bps(BW(4_000_000))),
        None
    );
    assert_eq!(
        negotiate_client_rate(&bbr, CcHeader::Bps(BW(4_000_000))),
        None
    );
}

/// 回归：配置层的 CC-RX 取值 → 线上头值 → 解析回来，全链路一致。
///
/// 说明：`h3_auth` 的线上常量 `COMMON_HEADER_CC_RX` 用小写
/// `"hysteria-cc-rx"`（HTTP/2·3 头名大小写不敏感，与参考 Go 的规范形
/// `"Hysteria-CC-RX"` 线上等价）；本模块导出的 `HEADER_CC_RX` 用参考原形。
/// 此处断言二者仅大小写之差，避免将来漂移成不同的头名。
#[test]
fn config_cc_rx_round_trips_via_wire_header_value() {
    use lengsuo_hysteria::congestion::header::{encode, HEADER_CC_RX};
    use lengsuo_hysteria::h3_auth::COMMON_HEADER_CC_RX;

    assert_eq!(
        HEADER_CC_RX.to_ascii_lowercase(),
        COMMON_HEADER_CC_RX,
        "配置层头名与线上头名不一致"
    );

    let cfg = CongestionConfig::new(CongestionMode::Brutal, BW(4_000_000), BW(10_000_000)).unwrap();
    let wire = encode(cfg.cc_rx_value());
    assert_eq!(wire, "4000000");
    assert_eq!(
        CcHeader::decode(&wire).unwrap(),
        CcHeader::Bps(BW(4_000_000))
    );
    // 服务端读到该值后，协商结果 = min(服务端 up, 客户端 down)。
    let srv = CongestionConfig::new(CongestionMode::Brutal, BW(0), BW(10_000_000)).unwrap();
    assert_eq!(
        negotiate_server_rate(&srv, CcHeader::decode(&wire).unwrap()),
        Some(4_000_000)
    );
}

/// 服务端：`min(BrutalUp, clientDown)`；**无 "auto" 分支**
/// （参考对客户端头用 `ParseUint` 忽略错误 → "auto" 退化为 0 → BBR）。
#[test]
fn negotiate_server_branch() {
    let srv = CongestionConfig::new(CongestionMode::Brutal, BW(0), BW(10_000_000)).unwrap();
    assert_eq!(
        negotiate_server_rate(&srv, CcHeader::Bps(BW(4_000_000))),
        Some(4_000_000)
    );
    assert_eq!(
        negotiate_server_rate(&srv, CcHeader::Bps(BW(99_000_000))),
        Some(10_000_000)
    );
    // clientDown = 0 → BBR。
    assert_eq!(negotiate_server_rate(&srv, CcHeader::Bps(BW(0))), None);
    // "auto" → 服务端不认 → BBR。
    assert_eq!(negotiate_server_rate(&srv, CcHeader::Auto), None);

    // 服务端 force-brutal 直接用自己的 up。
    let forced = CongestionConfig::new(CongestionMode::ForceBrutal, BW(0), BW(10_000_000)).unwrap();
    assert_eq!(
        negotiate_server_rate(&forced, CcHeader::Bps(BW(1))),
        Some(10_000_000)
    );
}
