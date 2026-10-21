//! `lengsuo_vless::vision_wire`（新出的站原语）↔ 固定版本 Xray **真实互通**。
//!
//! 方向：**本仓客户端**（`vision_wire::VisionSession`，VLESS 头 + Vision 流量层）→
//! **Xray 入站**（`flow=xtls-rprx-vision`）→ 回环 echo → 回程由 Xray 下行发回，
//! 本仓用**新 API** 解包。
//!
//! 与既有 `tests/xray_vision.rs` 的区别：后者直接调既有原语
//! （`VisionClient::encode_first_uplink` / `encode_uplink`，且**自己**剥响应头）；
//! **本文件走的是本卡新增的 `vision_wire::VisionSession`**——它按参考分层
//! （`DecodeResponseHeader` → `NewVisionReader`）**自己**解响应头，是「新 API 的线上
//! 字节真的被参考实现接受、且新 API 能自己收对下行」的硬证据，而不是自回路自证。
//!
//! 用例默认 `#[ignore]`，必须显式 `--ignored` 运行；未设置 `LENGSUO_XRAY` 时打印
//! 跳过原因后返回（跳过**不是**互通通过）。
//!
//! 覆盖：
//! 1. 空首包 → 参考走「0 内容长 padding 块」路径；
//! 2. 大首包 → 参考走短 padding 直发路径；
//! 3. 256 KiB 跨多条 padding 块，往返逐字节比对。
//!
//! 与 `tests/vision_wire.rs` 的 `interop_case` **互补**：那边验「响应头在参考侧的
//! 确切线上字节」，这边验「首包 / padding 规则」。
//!
//! 本文件不含 `unsafe`；只用回环地址、临时端口与假凭据；日志不含密钥/明文。

mod support;

#[path = "vision_wire/interop.rs"]
mod interop;

use interop::{first_block_lengths, run_wire_echo, skip_without_binary, UPLINK_CHUNK};

/// 情况 A：新 API 空首包 ⇒ 参考走「0 内容长 padding 块」路径。
///
/// padding 参考规则（独立复算）：`contentLen < 900 && long` → `900 + rand(0,500)`，
/// 落在 `[900, 1400)`。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn wire_small_first_packet_uses_long_padding() {
    if skip_without_binary() {
        return;
    }
    let payload = b"vision wire small first packet".to_vec();
    let (first_block, got, _inbound) = tokio::time::timeout(
        interop::LIMIT * 2,
        run_wire_echo(&payload, None, UPLINK_CHUNK),
    )
    .await
    .expect("互通超时");
    let (command, content_len, padding_len) = first_block_lengths(&first_block);
    assert_eq!(command, 0, "空首块命令应是 PADDING_CONTINUE");
    assert_eq!(content_len, 0, "空首块无内容");
    assert!(
        (900..1400).contains(&padding_len),
        "独立复算：p = 900 + rand(0,500) - 0 ∈ [900,1400)，实得 {padding_len}"
    );
    assert_eq!(got, payload, "下行解包必须逐字节一致");
}

/// 情况 B：新 API 大首包 ⇒ 参考走短 padding 直发路径。
///
/// padding 参考规则（独立复算）：`contentLen >= testseed[0]` 且非 long → `rand(0,256)`。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn wire_large_first_packet_uses_short_padding() {
    if skip_without_binary() {
        return;
    }
    let payload = (0..900u32).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let (first_block, got, _inbound) = tokio::time::timeout(
        interop::LIMIT * 2,
        run_wire_echo(&payload, Some(&payload), 900),
    )
    .await
    .expect("互通超时");
    let (command, content_len, padding_len) = first_block_lengths(&first_block);
    assert_eq!(command, 0, "首包命令应是 PADDING_CONTINUE");
    assert_eq!(content_len, 900, "首块内容应原样携带");
    assert!(
        padding_len < 256,
        "独立复算：p = rand(0,256) ∈ [0,256)，实得 {padding_len}"
    );
    assert_eq!(got, payload, "下行解包必须逐字节一致");
}

/// 情况 C：新 API 走 256 KiB 跨多条 padding 块，往返逐字节比对。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn wire_256kib_roundtrip_byte_compared() {
    if skip_without_binary() {
        return;
    }
    let payload = (0..256 * 1024u32)
        .map(|i| (i % 253) as u8)
        .collect::<Vec<_>>();
    let (first_block, got, _inbound) = tokio::time::timeout(
        interop::LIMIT * 2,
        run_wire_echo(&payload, Some(&payload), UPLINK_CHUNK),
    )
    .await
    .expect("互通超时");
    let (_command, content_len, padding_len) = first_block_lengths(&first_block);
    assert_eq!(content_len, UPLINK_CHUNK, "首块携带第一个分块");
    assert!(padding_len < 256, "首块短 padding：p = rand(0,256)");
    assert_eq!(got.len(), payload.len(), "下行明文长度应与回程一致");
    assert_eq!(got, payload, "256 KiB 回程必须逐字节一致");
}
