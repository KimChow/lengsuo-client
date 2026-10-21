// 数据段流生命周期：EOF 帧 / 半帧截断 / 跨连接状态不外泄。
//
// 本文件由 `tests/security_matrix.rs` 用 `include!` 文本并入同一模块；
// 共享常量与助手在 `security_matrix/common.rs`，`use` 写在入口文件。

/// 半关闭（数据段）：写端发出 EOF 帧后关闭 ⇒ 读端必须解出 `None`（流结束）。
#[tokio::test]
async fn body_half_close_reads_eof_frame_for_every_tier() {
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
            let mut seal =
                BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0)
                    .expect("可建");
            let mut wire = Vec::new();
            seal.seal(&mut wire, b"partial").expect("可写");
            seal.seal(&mut wire, b"").expect("EOF 可写");

            let mut open =
                BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0)
                    .expect("可建");
            let mut cursor = &wire[..];
            let first = open.open_from(&mut cursor).expect("可解");
            let eof = open.open_from(&mut cursor).expect("可解");
            (first, eof, cursor.len())
        })
        .await
        .expect("数据段半关闭用例不得超时");

        assert_eq!(
            outcome.0.as_deref(),
            Some(&b"partial"[..]),
            "security={security:?}"
        );
        assert!(
            outcome.1.is_none(),
            "security={security:?} EOF 帧必须读到 None"
        );
        assert_eq!(outcome.2, 0, "security={security:?} 不得有残留字节");
    }
}

/// 超时：数据段读到一半（长度段已到、载荷段缺失）必须报截断，不得挂起。
#[tokio::test]
async fn partial_body_frame_reports_truncation_for_every_tier() {
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
            let mut seal =
                BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0)
                    .expect("可建");
            let mut wire = Vec::new();
            seal.seal(&mut wire, b"0123456789").expect("可写");
            // 砍掉载荷段的一半。
            wire.truncate(2 + 5);

            let mut open =
                BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0)
                    .expect("可建");
            let mut cursor = &wire[..];
            open.open_from(&mut cursor)
        })
        .await
        .expect("半帧用例不得超时");

        assert!(
            matches!(
                outcome,
                Err(lengsuo_vmess::Error::Truncated { .. })
                    | Err(lengsuo_vmess::Error::BadLength { .. })
            ),
            "security={security:?} 半帧必须报截断，实际 {outcome:?}"
        );
    }
}

// ---- 7) 清理 ----

/// 清理：连接结束后帧上下文无残留状态（nonce 计数不外泄、可重复使用）。
///
/// 判据：新建的帧上下文与用过的帧上下文在**同样输入**下必须产出同样字节——
/// 证明上一条连接的计数/掩码状态没有泄漏到下一条连接。
#[test]
fn no_state_leaks_between_connections_for_every_tier() {
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let build = |option: u8| {
            BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, option)
                .expect("可建")
        };
        // 第一条连接：写两帧。
        let mut first = build(0x04);
        let mut wire_a = Vec::new();
        first.seal(&mut wire_a, b"one").expect("可写");
        first.seal(&mut wire_a, b"two").expect("可写");

        // 第二条连接：全新上下文，必须产出与第一条**完全相同**的字节。
        let mut second = build(0x04);
        let mut wire_b = Vec::new();
        second.seal(&mut wire_b, b"one").expect("可写");
        second.seal(&mut wire_b, b"two").expect("可写");

        assert_eq!(
            wire_a, wire_b,
            "security={security:?} 帧状态不得跨连接泄漏（掩码流/nonce 计数必须从头开始）"
        );
    }
}

/// 清理：帧上下文在被完整消费后，读到 EOF 且没有半开的残留。
#[test]
fn eof_frame_leaves_no_residual_state_for_every_tier() {
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let mut seal =
            BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0x04)
                .expect("可建");
        let mut wire = Vec::new();
        seal.seal(&mut wire, b"payload").expect("可写");
        seal.seal(&mut wire, b"").expect("EOF 可写");

        let mut open =
            BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0x04)
                .expect("可建");
        let mut cursor = &wire[..];
        assert!(open.open_from(&mut cursor).expect("可解").is_some());
        assert!(open.open_from(&mut cursor).expect("可解").is_none());
        assert!(cursor.is_empty(), "security={security:?} EOF 后不得有残留");
        // 再读一次必须报截断（流已结束），而不是凭空造出数据。
        let result = open.open_from(&mut cursor);
        assert!(
            matches!(result, Err(lengsuo_vmess::Error::Truncated { .. })),
            "security={security:?} EOF 后再读必须报截断，实际 {result:?}"
        );
    }
}
