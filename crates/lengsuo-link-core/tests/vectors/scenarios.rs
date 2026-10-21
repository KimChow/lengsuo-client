//! 错误场景的**重算**（含「会话是否失效」这一位）。
//!
//! 单独成文件的原因：`error_vectors.rs`（数据 + 标签映射）与本文件
//! （场景重算）合起来会顶破 400 行软目标 ⇒ 按「数据 / 重算」拆开。

use lengsuo_link_core::frame::{decode_exact, seal_frame, FrameType};
use lengsuo_wireguard::transport::{Sender, TransportKey};

use super::error_vectors::{
    ErrorVector, INITIATOR_PUBLIC, INITIATOR_STATIC, OTHER_INITIATOR_PUBLIC,
    OTHER_INITIATOR_STATIC, RESPONDER_PUBLIC, RESPONDER_STATIC, WRONG_KEY,
};
use super::{frame_error_label, from_hex, session_error_label};

/// 跑一次错误场景，返回**实际**的稳定标签。
pub fn run_scenario(vector: &ErrorVector) -> String {
    match vector.operation.as_str() {
        "decode_frame" => {
            let bytes = from_hex(&vector.input_hex);
            let error = decode_exact(&bytes).expect_err("坏帧必须被拒绝");
            frame_error_label(&error).to_string()
        }
        "seal_frame_oversize" => {
            let plain_len: usize = vector
                .parameter("plain_len")
                .unwrap_or("0")
                .parse()
                .expect("plain_len 是数字");
            let key = TransportKey::new(&WRONG_KEY).expect("测试密钥长度固定为 32 字节");
            let mut sender = Sender::new(key, 0x1122_3344, 0);
            let plain = vec![0x41u8; plain_len];
            let error = seal_frame(&mut sender, FrameType::Data, 0, &plain)
                .expect_err("超长明文必须被拒绝");
            frame_error_label(&error).to_string()
        }
        "session_open_frame" => cross_link_open(vector).0,
        _ => panic!("未知操作 {}", vector.operation),
    }
}

/// 重算一个错误场景，返回**稳定标签**与**会话是否已失效**。
///
/// 与 [`run_scenario`] 同源；额外返回「会话失效」这一位，供向量里的
/// `expect_session_invalidated` 声明被真正核对。
pub fn run_scenario_with_state(vector: &ErrorVector) -> (String, bool) {
    match vector.operation.as_str() {
        "session_open_frame" => {
            let (_label, invalidated) = cross_link_open(vector);
            (run_scenario(vector), invalidated)
        }
        _ => (run_scenario(vector), false),
    }
}

/// 跨链路解封：拿「另一条链路」的密钥封一帧，在本链路解封。
///
/// 返回**稳定标签**与**会话是否已失效**。
///
/// ⚠️ 跨链路那一对必须**自洽**：响应方要认识「另一条链路」发起方的静态公钥，
/// 否则剥壳阶段就报「未知对端」，到不了 AEAD 认证失败那一步。
fn cross_link_open(vector: &ErrorVector) -> (String, bool) {
    let (mut wrong_initiator, _wrong_responder) = super::session_pair(
        OTHER_INITIATOR_STATIC,
        RESPONDER_PUBLIC,
        RESPONDER_STATIC,
        OTHER_INITIATOR_PUBLIC,
    );
    let (_initiator, mut responder) = super::session_pair(
        INITIATOR_STATIC,
        RESPONDER_PUBLIC,
        RESPONDER_STATIC,
        INITIATOR_PUBLIC,
    );
    let plain = from_hex(&vector.input_hex);
    let wire = wrong_initiator
        .seal_frame(FrameType::Data, 1, &plain)
        .expect("跨链路封帧成功");
    let error = responder.open_frame(&wire).expect_err("跨链路帧必须被拒绝");
    (
        session_error_label(&error).to_string(),
        responder.is_invalidated(),
    )
}
