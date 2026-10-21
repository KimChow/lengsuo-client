// 用例 B（多目标并行，传统关联）：两条独立关联同时发往两个回显端口。
// 本文件由 `tests/xray_udp.rs` 用 `include!` 文本并入同一模块（用例名不带
// 模块前缀，与拆分前逐字一致）；`use`、常量与共享助手都在入口文件。

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
