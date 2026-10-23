//! 凭据灌注管线（W8 · 环境侧）的验收用例。
//!
//! 全部走**注入式假实现**：不建套接字、不发真实 HTTP、不与参考二进制互通
//! （本卡不含传输 ⇒ 没有可互通的面）。期望值一律用**独立写死的字面量**，
//! 不从被测实现反推（⛔ 不用自家 roundtrip 冒充验收）。
//!
//! # 编译期约束（无 trybuild，用代码评审兜底）
//!
//! `Plaintext` **不实现** `Clone`（编译期不允许复制明文）、**不实现**
//! `Serialize`/`Deserialize`（防明文被误序列化进 JSON/事件流）。
//! 本文件的假 sink 以**所有权移交**方式接收明文（`Vec<(String, Plaintext)>`），
//! 明文只能经 `as_str()` 只读回看；`credential.rs` 上另有一条 `compile_fail`
//! 文档测试机器化守住「不 Clone」（`cargo test` 会跑它）。
//! 任何人若给 `Plaintext` 加 `Clone`，必须同时回答「为什么允许再复制一份明文」
//! ——本卡不允许，且**不得用 `#[allow]` 掩盖**。

use lengsuo_environment::credential::{
    inject_credentials, CredRefId, CredentialSink, InjectError, InjectReport, InvalidRefReason,
    Plaintext, SecretUnlock, SinkError, UnlockError, MAX_REFS, MAX_REF_ID_LEN,
};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

/// 测试夹具里**写死**的明文（只在本文件与假实现之间流转，不进实现代码）。
const LITERALS: [&str; 3] = ["pw-2f9c1a", "cookie=z8q4", "tok-vt7m3"];
/// 同上，给需要 4 条的用例。
const LITERALS4: [&str; 4] = ["pw-2f9c1a", "cookie=z8q4", "tok-vt7m3", "proxy-9wq1"];

fn refs_of(ids: &[&str]) -> Vec<CredRefId> {
    ids.iter()
        .map(|id| CredRefId::parse(*id).expect("夹具引用 id 必须形态合法"))
        .collect()
}

/// 假解锁：记录调用顺序、进入/退出事件与在途计数，并可指定第 N 次调用失败。
struct FakeUnlock {
    table: BTreeMap<String, String>,
    calls: RefCell<Vec<String>>,
    events: RefCell<Vec<String>>,
    in_flight: Cell<usize>,
    overlapped: Cell<bool>,
    fail_at: Cell<Option<usize>>,
    fail_with: Cell<UnlockError>,
}

impl FakeUnlock {
    fn new(ids: &[&str], plaintexts: &[&str]) -> Self {
        assert_eq!(ids.len(), plaintexts.len(), "夹具：引用 id 与明文一一对应");
        Self {
            table: ids
                .iter()
                .zip(plaintexts)
                .map(|(id, plain)| ((*id).to_owned(), (*plain).to_owned()))
                .collect(),
            calls: RefCell::new(Vec::new()),
            events: RefCell::new(Vec::new()),
            in_flight: Cell::new(0),
            overlapped: Cell::new(false),
            fail_at: Cell::new(None),
            fail_with: Cell::new(UnlockError::Transport),
        }
    }

    fn failing_at(self, call_index: usize, err: UnlockError) -> Self {
        self.fail_at.set(Some(call_index));
        self.fail_with.set(err);
        self
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn call_count(&self) -> usize {
        self.calls.borrow().len()
    }

    fn events(&self) -> Vec<String> {
        self.events.borrow().clone()
    }

    fn overlapped(&self) -> bool {
        self.overlapped.get()
    }
}

impl SecretUnlock for FakeUnlock {
    async fn unlock(&self, r: &CredRefId) -> Result<Plaintext, UnlockError> {
        let in_flight = self.in_flight.get() + 1;
        self.in_flight.set(in_flight);
        if in_flight > 1 {
            self.overlapped.set(true);
        }
        let id = r.as_str().to_owned();
        self.events.borrow_mut().push(format!("enter:{id}"));
        self.calls.borrow_mut().push(id.clone());
        let call_index = self.calls.borrow().len() - 1;

        let outcome = if self.fail_at.get() == Some(call_index) {
            Err(self.fail_with.get())
        } else {
            match self.table.get(&id) {
                Some(plain) => Ok(Plaintext::new(plain.clone())),
                None => panic!("夹具缺少引用 {id} 的明文"),
            }
        };

        // 让出调度：管线若并发，`in_flight` 会同时 > 1，串行性用例即变红。
        tokio::task::yield_now().await;

        self.events.borrow_mut().push(format!("exit:{id}"));
        self.in_flight.set(self.in_flight.get() - 1);
        outcome
    }

    async fn probe(&self) -> Result<(), UnlockError> {
        Ok(())
    }
}

/// 假 sink：按顺序收下明文（接管所有权），并可指定第 N 次接收失败。
struct FakeSink {
    accepted: Vec<(String, Plaintext)>,
    fail_at: Option<usize>,
    fail_with: SinkError,
}

impl FakeSink {
    fn new() -> Self {
        Self {
            accepted: Vec::new(),
            fail_at: None,
            fail_with: SinkError::Rejected,
        }
    }

    fn failing_at(mut self, accept_index: usize, err: SinkError) -> Self {
        self.fail_at = Some(accept_index);
        self.fail_with = err;
        self
    }

    fn ids(&self) -> Vec<String> {
        self.accepted.iter().map(|(id, _)| id.clone()).collect()
    }
}

impl CredentialSink for FakeSink {
    fn accept(&mut self, r: &CredRefId, plaintext: Plaintext) -> Result<(), SinkError> {
        if self.fail_at == Some(self.accepted.len()) {
            // 明文随参数一起被丢弃（⇐ 所有权已移交）。
            return Err(self.fail_with);
        }
        self.accepted.push((r.as_str().to_owned(), plaintext));
        Ok(())
    }
}

// ── 用例 1：正常 3 条 ───────────────────────────────────────────────────────

#[tokio::test]
async fn three_refs_are_injected_in_input_order_with_exact_plaintext() {
    let ids = ["ref-0", "ref-1", "ref-2"];
    let refs = refs_of(&ids);
    let unlock = FakeUnlock::new(&ids, &LITERALS);
    let mut sink = FakeSink::new();

    let report = inject_credentials(&unlock, &refs, &mut sink)
        .await
        .expect("3 条合法且互异的引用必须灌注成功");

    assert_eq!(report.len(), 3);
    assert_eq!(report.refs(), refs.as_slice());
    assert_eq!(sink.ids(), vec!["ref-0", "ref-1", "ref-2"]);
    assert_eq!(sink.accepted.len(), 3);
    // 逐字符相等：期望值是夹具里写死的字面量。
    assert_eq!(sink.accepted[0].1.as_str(), "pw-2f9c1a");
    assert_eq!(sink.accepted[1].1.as_str(), "cookie=z8q4");
    assert_eq!(sink.accepted[2].1.as_str(), "tok-vt7m3");
    assert_eq!(unlock.call_count(), 3);
}

// ── 用例 2：形态非法（预检拒绝，unlock 调用次数 = 0）────────────────────────

/// 把非法 id 放在**下标 1**，两侧都是合法引用 ⇒ 同时验证 `index` 的正确性。
async fn expect_invalid_ref(bad: &str, reason: InvalidRefReason) {
    // fail-closed 构造入口也必须拒绝（形态校验的另一处出口）。
    assert!(
        CredRefId::parse(bad).is_err(),
        "形态非法的引用 id 不得通过构造"
    );

    let refs = vec![
        CredRefId::parse("ref-0").expect("合法夹具"),
        CredRefId::from_external(bad),
        CredRefId::parse("ref-2").expect("合法夹具"),
    ];
    let unlock = FakeUnlock::new(&["ref-0", "ref-2"], &["a", "b"]);
    let mut sink = FakeSink::new();

    let err = inject_credentials(&unlock, &refs, &mut sink)
        .await
        .expect_err("形态非法必须在预检被拒");

    assert!(
        matches!(err, InjectError::InvalidRef { index: 1, reason: r } if r == reason),
        "期望下标 1 的形态非法，实得 {err:?}"
    );
    assert_eq!(err.index(), Some(1));
    assert_eq!(err.injected(), 0);
    assert_eq!(unlock.call_count(), 0, "预检失败时一条 unlock 都不许发起");
    assert_eq!(sink.accepted.len(), 0);
}

#[tokio::test]
async fn empty_ref_id_is_rejected_before_any_unlock() {
    expect_invalid_ref("", InvalidRefReason::Empty).await;
}

#[tokio::test]
async fn overlong_ref_id_is_rejected_before_any_unlock() {
    // 上界两侧都探：恰好 MAX 合法，MAX+1 拒绝。
    let at_limit = "x".repeat(MAX_REF_ID_LEN);
    assert!(CredRefId::parse(&at_limit).is_ok(), "恰好到上限必须合法");
    let over = "x".repeat(MAX_REF_ID_LEN + 1);
    expect_invalid_ref(
        &over,
        InvalidRefReason::TooLong {
            len: MAX_REF_ID_LEN + 1,
        },
    )
    .await;
}

#[tokio::test]
async fn control_byte_ref_id_is_rejected_before_any_unlock() {
    expect_invalid_ref("ref\u{0}0", InvalidRefReason::ControlByte).await;
    expect_invalid_ref("ref\u{7}0", InvalidRefReason::ControlByte).await;
}

#[tokio::test]
async fn whitespace_ref_id_is_rejected_before_any_unlock() {
    expect_invalid_ref("ref 0", InvalidRefReason::Whitespace).await;
    expect_invalid_ref("ref\t0", InvalidRefReason::Whitespace).await;
    expect_invalid_ref("ref\u{a0}0", InvalidRefReason::Whitespace).await;
}

// ── 用例 3：重复引用 ────────────────────────────────────────────────────────

#[tokio::test]
async fn duplicate_ref_is_rejected_before_any_unlock() {
    let refs = refs_of(&["ref-0", "ref-1", "ref-0"]);
    let unlock = FakeUnlock::new(&["ref-0", "ref-1"], &["a", "b"]);
    let mut sink = FakeSink::new();

    let err = inject_credentials(&unlock, &refs, &mut sink)
        .await
        .expect_err("同一引用不得解两次");

    assert!(
        matches!(err, InjectError::DuplicateRef { index: 2, first: 0 }),
        "期望报下标 2 与首次位置 0，实得 {err:?}"
    );
    assert_eq!(err.injected(), 0);
    assert_eq!(unlock.call_count(), 0, "预检失败时一条 unlock 都不许发起");
}

// ── 用例 4：条数超上限 ──────────────────────────────────────────────────────

#[tokio::test]
async fn too_many_refs_is_rejected_before_any_unlock() {
    let ids: Vec<String> = (0..=MAX_REFS).map(|i| format!("ref-{i}")).collect();
    let refs: Vec<CredRefId> = ids
        .iter()
        .map(|id| CredRefId::parse(id).expect("合法夹具"))
        .collect();
    assert_eq!(refs.len(), MAX_REFS + 1);
    let unlock = FakeUnlock::new(&[], &[]);
    let mut sink = FakeSink::new();

    let err = inject_credentials(&unlock, &refs, &mut sink)
        .await
        .expect_err("超上限必须整批拒绝");

    assert!(
        matches!(err, InjectError::TooManyRefs { count, max } if count == MAX_REFS + 1 && max == MAX_REFS),
        "期望报条数与上限，实得 {err:?}"
    );
    assert_eq!(err.injected(), 0);
    assert_eq!(unlock.call_count(), 0, "预检失败时一条 unlock 都不许发起");
}

#[tokio::test]
async fn exactly_max_refs_is_accepted() {
    let owned: Vec<String> = (0..MAX_REFS).map(|i| format!("ref-{i}")).collect();
    let ids: Vec<&str> = owned.iter().map(String::as_str).collect();
    let refs = refs_of(&ids);
    let plaintexts: Vec<String> = (0..MAX_REFS).map(|i| format!("pw-{i}")).collect();
    let borrowed: Vec<&str> = plaintexts.iter().map(String::as_str).collect();
    let unlock = FakeUnlock::new(&ids, &borrowed);
    let mut sink = FakeSink::new();

    let report = inject_credentials(&unlock, &refs, &mut sink)
        .await
        .expect("恰好到上限必须整批成功");

    assert_eq!(report.len(), MAX_REFS);
    assert_eq!(sink.ids(), ids);
    assert_eq!(unlock.call_count(), MAX_REFS);
}

// ── 用例 5：第 2 条 unlock 失败 ─────────────────────────────────────────────

#[tokio::test]
async fn unlock_failure_stops_pipeline_and_reports_progress() {
    let ids = ["ref-0", "ref-1", "ref-2", "ref-3"];
    let refs = refs_of(&ids);
    let unlock = FakeUnlock::new(&ids, &LITERALS4).failing_at(1, UnlockError::AuditDenied);
    let mut sink = FakeSink::new();

    let err = inject_credentials(&unlock, &refs, &mut sink)
        .await
        .expect_err("第 2 条被审计拦截必须中止整批");

    assert!(
        matches!(
            err,
            InjectError::Unlock {
                index: 1,
                reason: UnlockError::AuditDenied,
                injected: 1
            }
        ),
        "期望第 2 条失败且已注入 1 条，实得 {err:?}"
    );
    assert_eq!(err.index(), Some(1));
    assert_eq!(err.injected(), 1);
    // 第 3、4 条绝不发起：调用序列恰为 [0, 1]。
    assert_eq!(unlock.calls(), vec!["ref-0", "ref-1"]);
    assert_eq!(sink.accepted.len(), 1);
    assert_eq!(sink.accepted[0].1.as_str(), "pw-2f9c1a");
}

#[test]
fn unlock_error_kinds_are_distinguishable_and_carry_stable_codes() {
    // 60006（引用失效）与 60007（审计拦截）必须可区分；错误里不得有明文。
    assert_eq!(UnlockError::RefInvalid.code(), "unlock.ref_invalid");
    assert_eq!(UnlockError::AuditDenied.code(), "unlock.audit_denied");
    assert_eq!(UnlockError::Transport.code(), "unlock.transport");
    assert_ne!(
        UnlockError::RefInvalid.code(),
        UnlockError::AuditDenied.code()
    );
    assert!(!format!("{:?}", UnlockError::RefInvalid).contains("pw-2f9c1a"));
}

// ── 用例 6：第 2 条 sink 失败 ───────────────────────────────────────────────

#[tokio::test]
async fn sink_failure_stops_pipeline_and_reports_progress() {
    let ids = ["ref-0", "ref-1", "ref-2", "ref-3"];
    let refs = refs_of(&ids);
    let unlock = FakeUnlock::new(&ids, &LITERALS4);
    let mut sink = FakeSink::new().failing_at(1, SinkError::Rejected);

    let err = inject_credentials(&unlock, &refs, &mut sink)
        .await
        .expect_err("第 2 条移交失败必须中止整批");

    assert!(
        matches!(
            err,
            InjectError::Sink {
                index: 1,
                reason: SinkError::Rejected,
                injected: 1
            }
        ),
        "期望第 2 条移交失败且已注入 1 条，实得 {err:?}"
    );
    assert_eq!(err.injected(), 1);
    // 第 3、4 条绝不发起。
    assert_eq!(unlock.calls(), vec!["ref-0", "ref-1"]);
    assert_eq!(sink.accepted.len(), 1);
}

// ── 用例 7：串行性（不存在并发在途）────────────────────────────────────────

#[tokio::test]
async fn pipeline_never_has_two_unlocks_in_flight() {
    let ids = ["ref-0", "ref-1", "ref-2"];
    let refs = refs_of(&ids);
    let unlock = FakeUnlock::new(&ids, &LITERALS);
    let mut sink = FakeSink::new();

    inject_credentials(&unlock, &refs, &mut sink)
        .await
        .expect("正常灌注");

    assert!(!unlock.overlapped(), "假 unlock 观测到并发在途");
    assert_eq!(
        unlock.events(),
        vec![
            "enter:ref-0",
            "exit:ref-0",
            "enter:ref-1",
            "exit:ref-1",
            "enter:ref-2",
            "exit:ref-2",
        ]
    );
}

// ── 用例 8：空入参 ──────────────────────────────────────────────────────────

#[tokio::test]
async fn empty_input_succeeds_without_any_unlock() {
    let unlock = FakeUnlock::new(&[], &[]);
    let mut sink = FakeSink::new();

    let report = inject_credentials(&unlock, &[], &mut sink)
        .await
        .expect("空入参必须成功");

    assert!(report.is_empty());
    assert_eq!(report.len(), 0);
    assert_eq!(report.refs(), <[CredRefId]>::default());
    assert_eq!(unlock.call_count(), 0);
    assert_eq!(sink.accepted.len(), 0);
}

// ── 用例 9：明文不泄漏 ──────────────────────────────────────────────────────

#[tokio::test]
async fn plaintext_never_appears_in_errors_or_report() {
    let ids = ["ref-0", "ref-1", "ref-2"];
    let refs = refs_of(&ids);

    // 成功路径：报告（及其 Debug）不得含明文。
    let unlock = FakeUnlock::new(&ids, &LITERALS);
    let mut sink = FakeSink::new();
    let report = inject_credentials(&unlock, &refs, &mut sink)
        .await
        .expect("正常灌注");
    let report_debug = format!("{report:?}");

    // 失败路径：第 2 条失败 ⇒ 第 1 条的明文已在内存里待过，错误面仍不得含它。
    let unlock = FakeUnlock::new(&ids, &LITERALS).failing_at(1, UnlockError::RefInvalid);
    let mut sink = FakeSink::new();
    let err = inject_credentials(&unlock, &refs, &mut sink)
        .await
        .expect_err("第 2 条引用失效必须中止");

    let surfaces = [
        report_debug,
        format!("{err:?}"),
        format!("{err}"),
        err.to_string(),
        format!("{:?}", err.index()),
        format!("{:?}", UnlockError::RefInvalid),
        format!("{}", UnlockError::RefInvalid),
        format!("{:?}", SinkError::Rejected),
        format!("{}", SinkError::Rejected),
        format!("{:?}", InvalidRefReason::Empty),
        format!("{}", InvalidRefReason::Empty),
        format!("{:?}", Plaintext::new(LITERALS[0])),
        format!("{}", Plaintext::new(LITERALS[0])),
    ];
    for surface in &surfaces {
        for literal in LITERALS {
            assert!(
                !surface.contains(literal),
                "明文不得出现在任何输出面：{surface}"
            );
        }
    }
}

// ── 用例 10：无状态（可重复调用，无跨调用残留）────────────────────────────

#[tokio::test]
async fn pipeline_is_stateless_across_calls() {
    let ids = ["ref-0", "ref-1", "ref-2"];
    let refs = refs_of(&ids);
    let unlock = FakeUnlock::new(&ids, &LITERALS);

    let mut sink_a = FakeSink::new();
    let first = inject_credentials(&unlock, &refs, &mut sink_a)
        .await
        .expect("首次灌注");
    let mut sink_b = FakeSink::new();
    let second = inject_credentials(&unlock, &refs, &mut sink_b)
        .await
        .expect("再次灌注");

    assert_eq!(first, second, "同一管线两次同参数调用结果必须一致");
    assert_eq!(sink_a.ids(), sink_b.ids());
    assert_eq!(
        unlock.call_count(),
        2 * refs.len(),
        "本模块不得持有跨调用缓存"
    );
}

// ── 用例 11：编译期约束（代码评审 + 文档测试兜底）──────────────────────────

#[test]
fn plaintext_is_move_only_and_only_readable_by_reference() {
    // `Plaintext` 不 Clone/不 Serialize（见文件头注释与 `credential.rs` 上的
    // `compile_fail` 文档测试）⇒ 明文只能**移交所有权**，回看只能经只读视图。
    let id = CredRefId::parse("ref-0").expect("合法夹具");
    let mut sink = FakeSink::new();
    sink.accept(&id, Plaintext::new(LITERALS[0]))
        .expect("正常接收");
    sink.accept(&id, Plaintext::new(LITERALS[1]))
        .expect("正常接收");

    // 两次移交的是两份**独立**的明文（不可能是同一份被复制）：
    assert_eq!(sink.accepted.len(), 2);
    assert_eq!(sink.accepted[0].1.as_str(), "pw-2f9c1a");
    assert_eq!(sink.accepted[1].1.as_str(), "cookie=z8q4");
    // 长度视图不暴露内容：
    assert_eq!(sink.accepted[0].1.len(), LITERALS[0].len());
    assert!(sink.accepted[0].1.as_str().contains("pw"));
    assert!(!format!("{:?}", sink.accepted[0].1).contains(LITERALS[0]));
}