//! **0-RTT 既有判据回归**：审计 §3 的「重放 △」格原本只有
//! `accepted_early_data_is_not_replayed`（在 `tests/zero_rtt.rs`）。
//!
//! ⛔ **不改** `tests/zero_rtt.rs`；本模块**独立复刻**同一语义，
//! 保证补「常规会话重放」这一格时没有把 0-RTT 的判据弄丢。
//!
//! # 语义基线
//!
//! `src/quic/early.rs:228` `run_early`：
//! - `OperationKind::NonIdempotent` ⇒ **fail-closed**，既不发早数据、
//!   也不静默改走 1-RTT；
//! - 早数据被**接受**（`accepted == true`）⇒ 只交付早数据的结果，
//!   **不得**再跑 1-RTT（否则就是重复交付）；
//! - 早数据被**拒绝**（`accepted == false`）⇒ 早数据被传输层丢弃，
//!   调用方显式重放一次 1-RTT（不构成重复交付，因为早数据从未到达对端）。
//!
//! 参考实现（固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//! **结构性不可达 0-RTT 早数据**，有两条**独立**的原因：
//!
//! 1. **服务端**：`transport/internet/hysteria/hub.go:426` 用
//!    `quic.Listen(...)`（**不是** `quic.ListenEarly`）⇒ quic-go 的
//!    `Transport.Listen` 走 `createServer(..., allow0RTT=false)`
//!    （`transport.go:173`）⇒ 服务端 `acceptEarlyConns == false` ⇒
//!    0-RTT 数据报在**传输层**被直接丢弃（`server.go:468-486`：
//!    `if wire.Is0RTTPacket(p.data) { if !s.acceptEarlyConns { ...;
//!    return false } }`）。
//! 2. **客户端**：`transport/internet/hysteria/dialer.go:257` 虽用
//!    `quic.DialEarly` 发起连接，但 `:266` 把认证请求写成
//!    `http.MethodPost` ⇒ quic-go 的 http3 客户端 `roundTrip`
//!    （`http3/client.go:283-292`）对**非** `GET_0RTT`/`HEAD_0RTT`
//!    的方法**等待握手完成**才发送 ⇒ **认证请求从来不会**作为早数据
//!    发出。
//!
//! ⇒ 参考侧**永远**收不到 0-RTT 早数据 ⇒ 0-RTT 只能做 **Rust↔Rust**
//! 闭环（判据钉在本仓 `run_early` 状态机上），不与参考互跑。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use lengsuo_hysteria::quic::{
    run_early, EarlyError, OperationKind, ZeroRttOutcome, ZeroRttRejected,
};

/// 计数器（记录早数据 / 1-RTT 各被调用了几次）。
#[derive(Default)]
struct FakeConn {
    early_sends: AtomicUsize,
    one_rtt_sends: AtomicUsize,
}

/// 0-RTT 既有判据回归：早数据被接受 ⇒ **只交付一次**，不得重复。
///
/// 语义等价于 `tests/zero_rtt.rs::accepted_early_data_is_not_replayed`
/// （本卡不改那个文件，此处独立复刻以防回归）。
#[test]
fn accepted_early_data_is_not_replayed_regression() {
    let fake = FakeConn::default();
    let (value, outcome) = run_early(
        OperationKind::Idempotent,
        Some(|| {
            fake.early_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("early")
        }),
        || {
            fake.one_rtt_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("1-rtt")
        },
        true,
    )
    .expect("幂等操作");
    assert_eq!(value, "early", "被接受的早数据结果必须交付");
    assert_eq!(outcome, ZeroRttOutcome::Accepted);
    assert_eq!(fake.early_sends.load(Ordering::SeqCst), 1, "早数据只发一次");
    assert_eq!(
        fake.one_rtt_sends.load(Ordering::SeqCst),
        0,
        "早数据被接受后**不得**再走 1-RTT（否则是重复交付）"
    );
}

/// 0-RTT 既有判据回归：非幂等操作 fail-closed（不发早数据、不静默回落）。
#[test]
fn non_idempotent_early_data_still_fails_closed() {
    let fake = FakeConn::default();
    let result: Result<((), ZeroRttOutcome), EarlyError<&'static str>> = run_early(
        OperationKind::NonIdempotent,
        Some(|| {
            fake.early_sends.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
        || {
            fake.one_rtt_sends.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        true,
    );
    assert_eq!(result, Err(EarlyError::NonIdempotent));
    assert_eq!(fake.early_sends.load(Ordering::SeqCst), 0, "早数据不得发送");
    assert_eq!(
        fake.one_rtt_sends.load(Ordering::SeqCst),
        0,
        "不得静默改走 1-RTT"
    );
}

/// 0-RTT 既有判据回归：早数据被拒绝 ⇒ 显式重放**恰好一次** 1-RTT。
#[test]
fn rejected_early_data_replays_exactly_once() {
    let fake = FakeConn::default();
    let (value, outcome) = run_early(
        OperationKind::Idempotent,
        Some(|| {
            fake.early_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("early")
        }),
        || {
            fake.one_rtt_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("1-rtt")
        },
        false,
    )
    .expect("幂等操作");
    assert_eq!(value, "1-rtt", "被拒后使用 1-RTT 结果");
    assert_eq!(outcome, ZeroRttOutcome::Rejected(ZeroRttRejected));
    assert_eq!(
        fake.early_sends.load(Ordering::SeqCst),
        1,
        "早数据路径被调用一次（其结果被丢弃）"
    );
    assert_eq!(
        fake.one_rtt_sends.load(Ordering::SeqCst),
        1,
        "1-RTT 重放恰好一次（早数据从未到达对端 ⇒ 不构成重复交付）"
    );
}

/// 0-RTT 既有判据回归：未尝试 0-RTT ⇒ 结果必须是 `NotAttempted`
/// （不得宣称 0-RTT）。
#[test]
fn not_attempted_outcome_is_reported_honestly() {
    let fake = FakeConn::default();
    let (value, outcome) = run_early(
        OperationKind::Idempotent,
        None::<fn() -> Result<&'static str, &'static str>>,
        || {
            fake.one_rtt_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("1-rtt")
        },
        false,
    )
    .expect("幂等操作");
    assert_eq!(value, "1-rtt");
    assert_eq!(outcome, ZeroRttOutcome::NotAttempted);
    assert_eq!(fake.early_sends.load(Ordering::SeqCst), 0);
    assert_eq!(fake.one_rtt_sends.load(Ordering::SeqCst), 1);
}

/// 0-RTT 与「常规会话重放」的关系：0-RTT 的早数据**可被攻击者重放**
/// （TLS 层无法阻止），所以只有幂等操作能走早数据；常规会话的帧级
/// 重放则被当成新请求（见 `frame_level.rs`）。
///
/// 这条把两层的结论钉在一起：0-RTT 的判据（不重复交付）不因新增
/// 「常规会话重放」用例而放宽。
#[test]
fn zero_rtt_semantics_and_regular_session_replay_are_distinct() {
    // 0-RTT 层：早数据被接受 ⇒ 只交付一次。
    let fake = FakeConn::default();
    let (_, outcome) = run_early(
        OperationKind::Idempotent,
        Some(|| {
            fake.early_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("early")
        }),
        || {
            fake.one_rtt_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("1-rtt")
        },
        true,
    )
    .expect("幂等操作");
    assert_eq!(outcome, ZeroRttOutcome::Accepted);
    assert_eq!(fake.one_rtt_sends.load(Ordering::SeqCst), 0);

    // 常规会话层：帧里没有序号 ⇒ 协议层**无法**识别重放（参考同样不防）。
    // 这里用 `lengsuo_hysteria::tcp::TcpRequest` 的公开 API 验证帧格式
    // 不含任何防重放字段（编码结果逐字节可复现 ⇒ 无 nonce）。
    let frame = lengsuo_hysteria::tcp::TcpRequest {
        address: "127.0.0.1:9".to_string(),
        padding: b"lengsuo-replay-fixed-padding-0123456789".to_vec(),
    }
    .encode()
    .expect("编码 TCPRequest");
    let frame2 = lengsuo_hysteria::tcp::TcpRequest {
        address: "127.0.0.1:9".to_string(),
        padding: b"lengsuo-replay-fixed-padding-0123456789".to_vec(),
    }
    .encode()
    .expect("编码 TCPRequest");
    assert_eq!(
        frame, frame2,
        "TCPRequest 编码必须确定性（无随机 nonce ⇒ 协议层不可识别重放）"
    );
    // 帧里除地址与 padding 外只有长度前缀 ⇒ 没有任何序号/时间戳/随机数。
    let addr_len = "127.0.0.1:9".len();
    assert_eq!(
        frame.len(),
        2 + 1 + addr_len + 1 + b"lengsuo-replay-fixed-padding-0123456789".len(),
        "帧结构 = varint(0x401) + varint(addr_len) + addr + varint(pad_len) + padding"
    );
}

/// 0-RTT 的**传输层**重放与「常规会话的帧级重放」互不覆盖：
/// 0-RTT 早数据被拒时，传输层**已经**丢弃了它（本仓的
/// `src/quic/client.rs:255` 显式在同连接上重放认证请求）。
#[test]
fn rejected_early_data_is_dropped_by_transport_layer() {
    // 语义等价于 `src/quic/early.rs` 的 `run_early(accepted=false)`：
    // 早数据路径被调用（字节已发出），但**结果不交付**；只有 fallback
    // 的 1-RTT 结果被交付 ⇒ 应用层只看到一次效果。
    let fake = FakeConn::default();
    let delivered = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&delivered);
    let (value, outcome) = run_early(
        OperationKind::Idempotent,
        Some(|| {
            fake.early_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("early")
        }),
        || {
            counter.fetch_add(1, Ordering::SeqCst);
            fake.one_rtt_sends.fetch_add(1, Ordering::SeqCst);
            Ok::<_, &'static str>("1-rtt")
        },
        false,
    )
    .expect("幂等操作");
    assert_eq!(value, "1-rtt");
    assert!(outcome.is_rejected());
    assert_eq!(delivered.load(Ordering::SeqCst), 1, "应用层只交付一次");
}
