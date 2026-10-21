// 用例 A1/A2（正向，传统关联）：IPv4 目标与域名目标形态。
// 本文件由 `tests/xray_udp.rs` 用 `include!` 文本并入同一模块（用例名不带
// 模块前缀，与拆分前逐字一致）；`use`、常量与共享助手都在入口文件。

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
