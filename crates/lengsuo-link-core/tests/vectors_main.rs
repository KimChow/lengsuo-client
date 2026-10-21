//! 跨端测试向量的**入口测试文件**。
//!
//! `tests/vectors/` 是子目录模块（cargo 只把 `tests/*.rs` 当测试目标），
//! 所以本文件负责把子目录挂进来并**重导出**用例。
//!
//! - [`vectors::session_vectors`]：L2 会话字节级向量。
//! - [`vectors::error_vectors`]：错误路径的稳定标签向量。
//! - [`vectors::consistency`]：一致性测试。
//!
//! ⚠️ 子目录里**不**再包一层 `mod tests {}`（clippy `module_inception` 会拦）。

use lengsuo_link_core::session::SessionRole;

mod vectors;

use vectors::error_vectors;
use vectors::rebuild;
use vectors::session_vectors;

// ---------------------------------------------------------------- 用例
//
// 全部用例写在子模块里并标了 `#[test]` ⇒ **cargo 会自动收集**
// （子模块由 `mod vectors;` 引入到本测试目标即可）。
// 这里只 `use` 那些**本文件里的用例直接调用**的助手。

use error_vectors::{
    generation_mismatch, initiator_consumes_initiation, known_frame_labels, known_session_labels,
    payload_limits, responder_creates_initiation, role_name, session_oversize_plaintext,
    session_send_before_handshake, session_wrong_key_open_frame,
};
use rebuild::{rebuild_handshake, rebuild_link};
use session_vectors::parse_session_vectors;

/// 错误向量：每个场景重算出的**稳定标签**必须与向量里写的一致。
#[test]
fn every_error_vector_yields_its_stable_label() {
    let vectors = error_vectors::parse_error_vectors();
    assert!(!vectors.is_empty(), "错误向量不能为空");
    for vector in &vectors {
        // 场景说明不能为空（它是移动端排查失败原因时给人看的）。
        assert!(
            !vector.scenario.is_empty(),
            "错误向量 {} 缺场景说明",
            vector.name
        );
        match vector.operation.as_str() {
            "decode_frame" | "seal_frame_oversize" | "session_open_frame" => {
                let actual = error_vectors::run_scenario(vector);
                assert_eq!(
                    actual, vector.expected_label,
                    "错误向量 {}（{}）的稳定标签不符：期望 {}，实际 {actual}",
                    vector.name, vector.scenario, vector.expected_label
                );
            }
            other => panic!("错误向量 {} 的操作 {other} 未接入重算", vector.name),
        }
    }
}

/// 错误向量：每条都要声明「不回退明文」；会话失效的还要声明会话确实失效。
#[test]
fn every_error_vector_declares_no_plaintext_fallback() {
    for vector in error_vectors::parse_error_vectors() {
        assert!(
            vector.expect_no_plaintext,
            "错误向量 {}（{}）必须声明「不回退明文」",
            vector.name, vector.scenario
        );
        // 声明了「会话失效」的场景，重算时确实要看到会话失效。
        if vector.expect_session_invalidated {
            let (label, invalidated) = error_vectors::run_scenario_with_state(&vector);
            assert_eq!(
                label, vector.expected_label,
                "错误向量 {}（{}）的稳定标签不符",
                vector.name, vector.scenario
            );
            assert!(
                invalidated,
                "错误向量 {}（{}）声明了会话失效，但重算时会话并未失效",
                vector.name, vector.scenario
            );
        }
    }
}

/// 错误向量：认证失败 ⇒ `session.auth_failed`、**不回退明文**、会话失效。
#[test]
fn wrong_key_open_fails_closed_with_auth_failed_label() {
    let frame = error_vectors::valid_frame();
    let (label, invalidated) = session_wrong_key_open_frame(&frame);
    assert_eq!(label, "session.auth_failed", "认证失败标签不符");
    assert!(invalidated, "认证失败后会话必须失效");
}

/// 错误向量：角色不符 ⇒ `session.role_mismatch`。
#[test]
fn role_mismatch_yields_stable_label() {
    let (label, invalidated) = initiator_consumes_initiation();
    assert_eq!(label, "session.role_mismatch", "角色不符标签不符");
    assert!(!invalidated, "角色不符**不**作废会话（只是拒绝这次操作）");

    let (label, invalidated) = responder_creates_initiation();
    assert_eq!(label, "session.role_mismatch", "角色不符标签不符");
    assert!(!invalidated, "角色不符**不**作废会话");
}

/// 错误向量：世代号不匹配 ⇒ 显式的 `session.generation_mismatch`。
#[test]
fn generation_mismatch_yields_stable_label() {
    assert_eq!(
        generation_mismatch(0, 1).as_deref(),
        Some("session.generation_mismatch"),
        "世代号不等必须报不匹配"
    );
    assert_eq!(generation_mismatch(1, 1), None, "世代号相等不应报不匹配");
}

/// 错误向量：未握手就收发 ⇒ `session.invalid_state`。
#[test]
fn unhandshaked_session_yields_invalid_state_label() {
    let (label, invalidated) = session_send_before_handshake();
    assert_eq!(label, "session.invalid_state", "未握手标签不符");
    assert!(!invalidated, "未握手**不**作废会话");
}

/// 错误向量：明文超上限 ⇒ 明确错误、**不截断**、会话仍有效。
#[test]
fn oversize_plaintext_is_rejected_without_truncation() {
    let (label, invalidated) = session_oversize_plaintext();
    assert_eq!(label, "session.frame", "超长明文标签不符");
    assert!(!invalidated, "超长明文**不**作废会话（只是拒绝这一帧）");
}

/// 错误向量：载荷上限常量自洽（明文上限 = 载荷上限 − 32）。
#[test]
fn payload_limits_are_consistent() {
    let (payload_limit, plain_limit) = payload_limits();
    assert_eq!(payload_limit, 1400, "载荷上限必须是 1400 字节");
    assert_eq!(
        plain_limit,
        payload_limit - 32,
        "明文上限必须比载荷上限少 32 字节"
    );
}

/// 稳定标签表自检：不得有重复标签。
#[test]
fn stable_label_tables_have_no_duplicates() {
    let mut frame = known_frame_labels();
    frame.sort_unstable();
    let before = frame.len();
    frame.dedup();
    assert_eq!(before, frame.len(), "帧层稳定标签表有重复");

    let mut session = known_session_labels();
    session.sort_unstable();
    let before = session.len();
    session.dedup();
    assert_eq!(before, session.len(), "会话层稳定标签表有重复");
}

/// 会话向量解析自检（移动端按同一份 schema 读）。
#[test]
fn session_vectors_parse_and_cover_both_directions() {
    let links = parse_session_vectors();
    assert!(!links.is_empty(), "会话向量不能为空");
    let mut has_i2r = false;
    let mut has_r2i = false;
    for link in &links {
        for round in &link.rounds {
            for frame in &round.frames {
                if frame.direction == vectors::DIR_I2R {
                    has_i2r = true;
                }
                if frame.direction == vectors::DIR_R2I {
                    has_r2i = true;
                }
            }
        }
    }
    assert!(has_i2r, "必须覆盖发起方 → 响应方方向");
    assert!(has_r2i, "必须覆盖响应方 → 发起方方向");
}

/// 重算引擎自检：重算出的帧字节与向量一致（与一致性测试同源，供报告取证）。
#[test]
fn rebuild_reproduces_the_first_frame_of_each_link() {
    for link in parse_session_vectors() {
        let rebuilt = rebuild_link(&link);
        let (initiation, response, _keys) = rebuild_handshake(&link.material, &link.rounds[0]);
        assert_eq!(initiation.len(), 148);
        assert_eq!(response.len(), 92);
        for (round, outcome) in link.rounds.iter().zip(&rebuilt) {
            for (frame, actual) in round.frames.iter().zip(&outcome.frames) {
                assert_eq!(
                    vectors::to_hex(actual),
                    vectors::to_hex(&frame.frame),
                    "链路 {} 的帧 {} 重算不符",
                    link.name,
                    frame.name
                );
            }
        }
    }
}

/// 角色名是**跨端契约**：移动端按同一套名字显示（`initiator` / `responder`）。
#[test]
fn role_names_are_stable() {
    assert_eq!(role_name(SessionRole::Initiator), "initiator");
    assert_eq!(role_name(SessionRole::Responder), "responder");
}
