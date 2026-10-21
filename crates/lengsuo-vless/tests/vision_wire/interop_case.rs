//! `vision_wire` ↔ 固定版本 Xray 的**响应头线上字节**互通用例。
//!
//! 这是与 `tests/vision_wire_xray.rs` **互补**的一条：那边验「首包 / padding
//! 规则」，这条验「**下行响应头在参考侧的确切线上字节**」以及
//! **本仓新 API 的响应头剥离没有多读/少读**。
//!
//! 关键判据（参考 `proxy/vless/encoding`）：
//! - 参考入站下行先写响应头 `[version(1)][addonsLen(1)]`；响应的 addons 恒为空
//!   （`responseAddons := &encoding.Addons{}`）⇒ 线上头 = `00 00`；
//! - 紧接着才是 vision 下行块，参考 `XtlsPadding` 在**首个**被 padding 的块前写
//!   一次 16 字节 UUID ⇒ 下行块以 UUID 开头。
//!
//! ⇒ 若本仓 `ResponseHeaderStream` 多读或少读响应头，vision 块头就会错位，
//! 解出的明文必然是垃圾；本用例同时断言「线上头恰为 2 字节」与「解出的明文
//! 逐字节一致」，两者合起来就是「剥离边界正确」的硬证据。

use super::interop::{run_wire_echo, skip_without_binary, UPLINK_CHUNK};

/// 参考的 VLESS 响应头长度（`version(1) + addonsLen(1)`）。
const RESPONSE_HEADER_LEN: usize = 2;

/// 完整互通 + **响应头线上字节**断言。
///
/// 断言：
/// 1. 参考下行线上字节以 `00 00` 开头（版本 0 + addons 长度 0）；
/// 2. 第 3..19 字节是 UUID（参考下行首个 padding 块携带 UUID）⇒ 证明本仓只剥了
///    **恰好 2 字节**响应头，没有把 vision 块头一起吃掉；
/// 3. 本仓新 API 解出的下行明文与上行载荷**逐字节一致**。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn wire_response_header_on_the_wire_is_exactly_two_bytes() {
    if skip_without_binary() {
        return;
    }
    let payload = b"vision wire response header wire-level check".to_vec();
    let (_first_block, got, inbound) = tokio::time::timeout(
        super::interop::LIMIT * 2,
        run_wire_echo(&payload, None, UPLINK_CHUNK),
    )
    .await
    .expect("互通超时");

    assert!(
        inbound.len() > RESPONSE_HEADER_LEN + 16,
        "参考下行线上字节不足以切出响应头 + 首块（实际 {} 字节）",
        inbound.len()
    );
    assert_eq!(
        &inbound[..RESPONSE_HEADER_LEN],
        &[0x00, 0x00],
        "参考下行响应头必须是 [version=0, addonsLen=0]"
    );
    assert_eq!(
        &inbound[RESPONSE_HEADER_LEN..RESPONSE_HEADER_LEN + 16],
        &crate::support::KEY[..],
        "响应头之后必须是参考下行首个 padding 块的 UUID（证明只剥了 2 字节）"
    );
    assert_eq!(got, payload, "下行解包必须逐字节一致");
}
