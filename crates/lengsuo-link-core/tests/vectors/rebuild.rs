//! L2 会话向量的**重算引擎**：把向量里的输入重新跑一遍，
//! 得到「按当前实现应得的期望字节」。
//!
//! 单独成文件的原因：`session_vectors.rs`（解析 + 数据结构）与本文件
//! （重算）合起来会顶破 400 行软目标 ⇒ 按「解析 / 重算」拆开。
//!
//! ⚠️ 重算**不读旧常量** ⇒ 输出的就是「按当前实现应得的期望字节」；
//! 仓内常量必须与重算结果**逐字节相同**（由一致性测试守住）。

use std::time::Instant;

use lengsuo_link_core::session::{Session, SessionConfig, SessionRole};
use lengsuo_wireguard::handshake::{mac1, Handshake, Responder, INITIATION_LEN, RESPONSE_LEN};

use super::session_vectors::{LinkMaterial, LinkVector, RoundVector, TransportKeys};
use super::{advance_round, DIR_I2R};

// ---------------------------------------------------------------- 重算引擎

/// 一轮重算的产物。
#[derive(Debug, Clone)]
pub struct RebuiltRound {
    /// initiation 报文**原始**字节（含墙钟区段）。
    pub initiation: Vec<u8>,
    /// response 报文**原始**字节（含墙钟区段）。
    pub response: Vec<u8>,
    /// 封出的帧（与向量顺序一致）。
    pub frames: Vec<Vec<u8>>,
    /// 会话层读到的世代号。
    pub generation: u64,
}

/// 在**传输层**重算一轮握手（initiation / response 原始字节 + 传输密钥）。
///
/// 走 `lengsuo-wireguard` 的握手状态机（**只读复用**）：这里不经过
/// `Session`，因为 `Session` 不导出传输密钥。
pub fn rebuild_handshake(
    material: &LinkMaterial,
    round: &RoundVector,
) -> (Vec<u8>, Vec<u8>, TransportKeys) {
    let mut handshake = Handshake::new(
        &material.initiator_static_private,
        &material.responder_static_public,
        None,
        round.initiator_index,
    )
    .expect("发起方握手上下文可构造");
    let initiation = handshake
        .create_initiation(round.initiator_seed)
        .expect("initiation 可生成");
    let mut responder = Responder::new(
        &material.responder_static_private,
        &material.initiator_static_public,
        None,
        0,
    )
    .expect("响应方握手上下文可构造");
    responder
        .consume_initiation(&initiation)
        .expect("initiation 可剥壳");
    let mut response = responder
        .create_response(round.responder_seed, round.responder_index)
        .expect("response 可生成");
    responder.add_macs(&mut response);
    let responder_keys = responder.begin_symmetric_session().expect("对称会话可派生");
    let initiator_keys = handshake
        .consume_response(&response)
        .expect("response 可消费");
    let keys = TransportKeys {
        initiator_send: initiator_keys.send,
        initiator_receive: initiator_keys.receive,
        responder_send: responder_keys.send,
        responder_receive: responder_keys.receive,
    };
    (initiation.to_vec(), response.to_vec(), keys)
}

/// 在**会话层**重算一条链路的全部轮次（世代号 + 封出的帧）。
pub fn rebuild_link(link: &LinkVector) -> Vec<RebuiltRound> {
    let mut initiator = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        link.material.initiator_static_private,
        link.material.responder_static_public,
    ))
    .expect("发起方会话可构造");
    let mut responder = Session::new(SessionConfig::new(
        SessionRole::Responder,
        link.material.responder_static_private,
        link.material.initiator_static_public,
    ))
    .expect("响应方会话可构造");
    let mut now = Instant::now();
    let mut rebuilt = Vec::new();
    for (index, round) in link.rounds.iter().enumerate() {
        if index > 0 {
            now = advance_round(now);
        }
        let initiation = initiator
            .create_initiation(round.initiator_seed, round.initiator_index, now)
            .expect("initiation 可生成");
        responder
            .consume_initiation(&initiation, now)
            .expect("initiation 可剥壳");
        let response = responder
            .create_response(round.responder_seed, round.responder_index, now)
            .expect("response 可生成");
        initiator
            .consume_response(&response, now)
            .expect("response 可消费");
        let mut frames = Vec::new();
        for frame in &round.frames {
            let session = if frame.direction == DIR_I2R {
                &mut initiator
            } else {
                &mut responder
            };
            frames.push(
                session
                    .seal_frame(frame.frame_type, frame.seq, &frame.plaintext)
                    .expect("封帧成功"),
            );
        }
        rebuilt.push(RebuiltRound {
            initiation,
            response,
            frames,
            generation: initiator.generation().value(),
        });
    }
    rebuilt
}

/// initiation 的 MAC1 校验规则：`mac1(对端静态公钥, 报文[:116]) == 报文[116..132]`。
///
/// 参考语义：MAC1 = `BLAKE2s-128(BLAKE2s-256("mac1----" || 对端静态公钥), 报文去掉
/// mac1/mac2 的前缀)`。initiation 的对端 = **响应方的静态公钥**。
pub fn initiation_mac1_ok(initiation: &[u8], responder_static_public: &[u8; 32]) -> bool {
    if initiation.len() != INITIATION_LEN {
        return false;
    }
    let expected = mac1(responder_static_public, &initiation[..INITIATION_LEN - 32]);
    expected == initiation[INITIATION_LEN - 32..INITIATION_LEN - 16]
}

/// response 的 MAC1 校验规则：`mac1(对端静态公钥, 报文[:60]) == 报文[60..76]`。
///
/// response 的对端 = **发起方的静态公钥**（响应方出站时按对端公钥加 MAC，
/// 发起方入站时按自己的公钥校验——两侧是同一把钥匙）。
pub fn response_mac1_ok(response: &[u8], initiator_static_public: &[u8; 32]) -> bool {
    if response.len() != RESPONSE_LEN {
        return false;
    }
    let expected = mac1(initiator_static_public, &response[..RESPONSE_LEN - 32]);
    expected == response[RESPONSE_LEN - 32..RESPONSE_LEN - 16]
}
