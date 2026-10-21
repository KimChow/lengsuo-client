//! L1 传输接线层的 **fail-closed** 用例。
//!
//! 覆盖任务书 §五 第 2 条的后四项：认证失败 ⇒ fail-closed 不返回明文；
//! 会话未建立 ⇒ 收发被拒（`InvalidState`）；会话已失效 ⇒ 收发被拒
//! （`Invalidated`）；超长字节 ⇒ 明确报错（不截断、不当合法帧）。
//!
//! 另加四条本卡自己的边界纪律：传输层错误**原样透出**；明文超长 ⇒ 拒绝
//! **且一个字节都没发出去**；暂时没数据 ⇒ `WouldBlock`（**不是**失败）；
//! 稳定错误码 / 标签是**跨端契约**。
//!
//! ⛔ 本文件**不**证明与任何真实端互通：只证明「同一进程内」的拒绝语义。

use std::collections::VecDeque;
use std::time::Instant;

use lengsuo_link_core::frame::{FrameType, MAX_FRAME_LEN, MAX_PLAIN_LEN};
use lengsuo_link_core::session::{Session, SessionConfig, SessionError, SessionRole};
use lengsuo_link_core::transport::{ErrorCode, Link, Transport, TransportError};

// ---------------------------------------------------------------- 假密钥材料

/// 发起方静态私钥（测试专用）。
const INITIATOR_STATIC: [u8; 32] = [0x11; 32];
/// 响应方静态私钥（测试专用）。
const RESPONDER_STATIC: [u8; 32] = [0x22; 32];
/// 发起方静态公钥（仓外 Python `cryptography` 的 X25519 独立算出）。
const INITIATOR_PUBLIC: [u8; 32] = [
    0x7b, 0x4e, 0x90, 0x9b, 0xbe, 0x7f, 0xfe, 0x44, 0xc4, 0x65, 0xa2, 0x20, 0x03, 0x7d, 0x60, 0x8e,
    0xe3, 0x58, 0x97, 0xd3, 0x1e, 0xf9, 0x72, 0xf0, 0x7f, 0x74, 0x89, 0x2c, 0xb0, 0xf7, 0x3f, 0x13,
];
/// 响应方静态公钥（仓外 Python `cryptography` 的 X25519 独立算出）。
const RESPONDER_PUBLIC: [u8; 32] = [
    0x0f, 0xaa, 0x68, 0x4e, 0xd2, 0x88, 0x67, 0xb9, 0x7f, 0x4a, 0x6a, 0x2d, 0xee, 0x5d, 0xf8, 0xce,
    0x97, 0x4e, 0x76, 0xb7, 0x01, 0x8e, 0x3f, 0x22, 0xa1, 0xc4, 0xcf, 0x26, 0x78, 0x57, 0x0f, 0x20,
];

// ---------------------------------------------------------------- 测试用传输

/// 记录发出去字节、并可按剧本吐出字节的传输（测试专用）。
#[derive(Debug, Default)]
struct RecordingTransport {
    sent: Vec<Vec<u8>>,
    fail_send: bool,
    to_serve: VecDeque<Vec<u8>>,
}

impl RecordingTransport {
    /// 正常搬运：只记录发出去的字节。
    fn new() -> Self {
        Self::default()
    }

    /// 发送必失败的变体（模拟链路已关闭）。
    fn failing() -> Self {
        Self {
            fail_send: true,
            ..Self::default()
        }
    }

    /// 按剧本吐出字节的变体（模拟「对端发来的任意字节」）。
    fn scripted(bytes: impl Into<Vec<u8>>) -> Self {
        let mut to_serve = VecDeque::new();
        to_serve.push_back(bytes.into());
        Self {
            to_serve,
            ..Self::default()
        }
    }

    /// 已经发出去的字节（按发送顺序）。
    fn sent_bytes(&self) -> &[Vec<u8>] {
        &self.sent
    }
}

impl Transport for RecordingTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.sent.push(bytes.to_vec());
        if self.fail_send {
            return Err(TransportError::Closed {
                reason: "对端已关闭",
            });
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        self.to_serve.pop_front().ok_or(TransportError::WouldBlock)
    }
}

// ---------------------------------------------------------------- 夹具

/// 构造（发起方, 响应方)一对**未握手**的会话。
fn session_pair() -> (Session, Session) {
    let initiator = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        INITIATOR_STATIC,
        RESPONDER_PUBLIC,
    ))
    .expect("发起方会话可构造");
    let responder = Session::new(SessionConfig::new(
        SessionRole::Responder,
        RESPONDER_STATIC,
        INITIATOR_PUBLIC,
    ))
    .expect("响应方会话可构造");
    (initiator, responder)
}

/// 在同一对会话对象上跑完一轮握手（L2 已交付，本卡只调用不修改）。
fn handshake_round(
    initiator: &mut Session,
    responder: &mut Session,
    index_base: u32,
    seed_base: u8,
    now: Instant,
) {
    let initiation = initiator
        .create_initiation([seed_base; 32], index_base, now)
        .expect("initiation 可生成");
    responder
        .consume_initiation(&initiation, now)
        .expect("initiation 可剥壳");
    let response = responder
        .create_response([seed_base.wrapping_add(1); 32], index_base + 1, now)
        .expect("response 可生成");
    initiator
        .consume_response(&response, now)
        .expect("response 可消费");
}

/// 一对**已握手**的会话。
fn established_pair() -> (Session, Session) {
    let (mut initiator, mut responder) = session_pair();
    handshake_round(&mut initiator, &mut responder, 100, 0xB1, Instant::now());
    (initiator, responder)
}

// ---------------------------------------------------------------- 认证失败 ⇒ fail-closed

#[test]
fn tampered_ciphertext_fails_closed_and_yields_no_plaintext() {
    let (initiator, responder) = established_pair();
    let mut a = Link::new(initiator, RecordingTransport::new());
    let plaintext = b"secret-payload-must-never-leak".to_vec();

    a.send_frame(FrameType::Data, 1, &plaintext)
        .expect("发帧成功");
    let wire = a.transport().sent_bytes()[0].clone();
    assert!(wire.len() > 1);

    // 篡改**密文**（动最后一字节 = 认证标签）：帧头完好，AEAD 认证必然失败。
    let mut tampered = wire.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    let mut b = Link::new(responder, RecordingTransport::scripted(tampered));
    let error = b.recv_frame().expect_err("被篡改的密文必须被拒绝");
    assert!(
        matches!(error, TransportError::Session(SessionError::AuthFailed)),
        "期望认证失败，实际 {error:?}"
    );
    // 错误里**不得**出现明文。
    assert!(
        !error.to_string().contains("secret-payload"),
        "错误文本不得泄漏明文：{error}"
    );
    // 认证失败 ⇒ 会话立即失效。
    assert!(b.session().is_invalidated());
}

#[test]
fn failed_authentication_keeps_the_session_closed() {
    let (initiator, responder) = established_pair();
    let mut a = Link::new(initiator, RecordingTransport::new());
    a.send_frame(FrameType::Data, 1, b"payload")
        .expect("发帧成功");
    let mut wire = a.transport().sent_bytes()[0].clone();
    let last = wire.len() - 1;
    wire[last] ^= 0x80;

    let mut b = Link::new(responder, RecordingTransport::scripted(wire));
    assert!(b.recv_frame().is_err(), "被篡改的密文必须被拒绝");

    // 失效之后：再收也是**拒绝**，不是「空明文」。
    let error = b.recv_frame().expect_err("失效后必须继续拒绝");
    assert!(
        matches!(
            error,
            TransportError::Session(SessionError::Invalidated)
                | TransportError::Session(SessionError::AuthFailed)
        ),
        "期望失效/认证失败，实际 {error:?}"
    );
    assert!(b.session().is_invalidated());
}

// ---------------------------------------------------------------- 会话未建立 ⇒ InvalidState

#[test]
fn unestablished_session_rejects_send_and_receive() {
    let (initiator, responder) = session_pair();
    assert!(!initiator.is_established());

    let mut a = Link::new(initiator, RecordingTransport::new());
    let error = a
        .send_frame(FrameType::Data, 1, b"nope")
        .expect_err("未建立的会话不得发送");
    assert!(
        matches!(
            error,
            TransportError::Session(SessionError::InvalidState { .. })
        ),
        "期望 InvalidState，实际 {error:?}"
    );

    let mut b = Link::new(responder, RecordingTransport::new());
    let error = b.recv_frame().expect_err("未建立的会话不得接收");
    assert!(
        matches!(
            error,
            TransportError::Session(SessionError::InvalidState { .. })
        ),
        "期望 InvalidState，实际 {error:?}"
    );
}

// ---------------------------------------------------------------- 会话已失效 ⇒ Invalidated

#[test]
fn invalidated_session_rejects_send_and_receive() {
    let (mut initiator, mut responder) = established_pair();
    initiator.invalidate();
    responder.invalidate();

    let mut a = Link::new(initiator, RecordingTransport::new());
    let error = a
        .send_frame(FrameType::Data, 1, b"nope")
        .expect_err("已失效的会话不得发送");
    assert!(
        matches!(error, TransportError::Session(SessionError::Invalidated)),
        "期望 Invalidated，实际 {error:?}"
    );

    let mut b = Link::new(responder, RecordingTransport::new());
    let error = b.recv_frame().expect_err("已失效的会话不得接收");
    assert!(
        matches!(error, TransportError::Session(SessionError::Invalidated)),
        "期望 Invalidated，实际 {error:?}"
    );
}

// ---------------------------------------------------------------- 超长字节 ⇒ 明确报错

#[test]
fn oversized_bytes_are_rejected_without_truncation() {
    let (_initiator, responder) = established_pair();
    let oversize = vec![0x5Au8; MAX_FRAME_LEN + 1];

    let mut b = Link::new(responder, RecordingTransport::scripted(oversize));
    let error = b.recv_frame().expect_err("超长字节必须被明确拒绝");
    match error {
        TransportError::TooLong { actual, limit } => {
            assert_eq!(actual, MAX_FRAME_LEN + 1);
            assert_eq!(limit, MAX_FRAME_LEN);
        }
        other => panic!("期望 TooLong，实际 {other:?}"),
    }
    // 超长是**搬运层**的错误，不是会话层的：会话不应因此失效。
    assert!(!b.session().is_invalidated(), "超长字节不应让会话失效");
    assert!(b.session().is_established());
}

#[test]
fn exactly_maximum_length_bytes_are_not_rejected_by_the_length_check() {
    // 上限**恰好**等于 MAX_FRAME_LEN 的字节不该被长度检查拦下
    // （它会继续走到会话层，由会话层判定「这不是一帧」）。
    let (_initiator, responder) = established_pair();
    let exact = vec![0x5Au8; MAX_FRAME_LEN];
    let mut b = Link::new(responder, RecordingTransport::scripted(exact));
    let error = b.recv_frame().expect_err("不是合法帧，必须报错");
    assert!(
        !matches!(error, TransportError::TooLong { .. }),
        "恰好等于上限的字节不该被判超长，实际 {error:?}"
    );
}

// ---------------------------------------------------------------- 明文超长 ⇒ 一个字节都不发

#[test]
fn oversized_plaintext_is_rejected_and_nothing_is_sent() {
    let (initiator, _responder) = established_pair();
    let mut a = Link::new(initiator, RecordingTransport::new());

    let too_long = vec![0xA5u8; MAX_PLAIN_LEN + 1];
    let error = a
        .send_frame(FrameType::Data, 1, &too_long)
        .expect_err("超长明文必须被拒绝");
    assert!(
        matches!(error, TransportError::Session(SessionError::Frame(_))),
        "期望帧层错误，实际 {error:?}"
    );
    assert!(
        a.transport().sent_bytes().is_empty(),
        "超长明文必须一个字节都不发出去"
    );
}

// ---------------------------------------------------------------- 传输层错误原样透出

#[test]
fn transport_errors_are_passed_through_verbatim() {
    let (initiator, _responder) = established_pair();
    let mut a = Link::new(initiator, RecordingTransport::failing());
    let error = a
        .send_frame(FrameType::Data, 1, b"payload")
        .expect_err("传输层失败必须报错");
    assert!(
        matches!(error, TransportError::Closed { .. }),
        "期望 Closed，实际 {error:?}"
    );
    // 传输层失败**不得**被改写成「成功」或「会话失效」。
    assert!(a.session().is_established());
}

#[test]
fn would_block_is_surfaced_without_breaking_the_session() {
    let (initiator, _responder) = established_pair();
    let mut a = Link::new(initiator, RecordingTransport::new());
    let error = a.recv_frame().expect_err("没有数据时必须报错");
    assert!(
        matches!(error, TransportError::WouldBlock),
        "期望 WouldBlock，实际 {error:?}"
    );
    assert!(a.session().is_established());
}

// ---------------------------------------------------------------- 稳定错误码

#[test]
fn error_codes_are_stable_across_the_wire_contract() {
    // 数字码 + 标签都是**跨端契约**：移动端按码分支，不解析错误文本。
    assert_eq!(ErrorCode::WouldBlock.code(), 0x0103);
    assert_eq!(ErrorCode::WouldBlock.as_str(), "WOULD_BLOCK");
    assert_eq!(ErrorCode::Closed.code(), 0x0104);
    assert_eq!(ErrorCode::Closed.as_str(), "CLOSED");
    assert_eq!(ErrorCode::TooLong.code(), 0x0105);
    assert_eq!(ErrorCode::TooLong.as_str(), "TOO_LONG");
    assert_eq!(ErrorCode::SessionInvalidState.code(), 0x0106);
    assert_eq!(
        ErrorCode::SessionInvalidState.as_str(),
        "SESSION_INVALID_STATE"
    );
    assert_eq!(ErrorCode::SessionInvalidated.code(), 0x0107);
    assert_eq!(
        ErrorCode::SessionInvalidated.as_str(),
        "SESSION_INVALIDATED"
    );
    assert_eq!(ErrorCode::SessionAuthFailed.code(), 0x0108);
    assert_eq!(ErrorCode::SessionAuthFailed.as_str(), "SESSION_AUTH_FAILED");

    // 错误 → 码的映射必须稳定。
    assert_eq!(
        TransportError::WouldBlock.error_code(),
        ErrorCode::WouldBlock
    );
    assert_eq!(
        TransportError::TooLong {
            actual: 1,
            limit: 2
        }
        .error_code(),
        ErrorCode::TooLong
    );
    assert_eq!(
        TransportError::Session(SessionError::Invalidated).error_code(),
        ErrorCode::SessionInvalidated
    );
    assert_eq!(
        TransportError::Session(SessionError::AuthFailed).error_code(),
        ErrorCode::SessionAuthFailed
    );
    assert_eq!(
        TransportError::Session(SessionError::InvalidState {
            state: "unhandshaked",
            role: "initiator"
        })
        .error_code(),
        ErrorCode::SessionInvalidState
    );

    // 会话错误**原样透出**：调用方能拿回完整的 `SessionError`。
    let error = TransportError::Session(SessionError::Invalidated);
    assert_eq!(error.session_error(), Some(&SessionError::Invalidated));
    assert_eq!(TransportError::WouldBlock.session_error(), None);
}
