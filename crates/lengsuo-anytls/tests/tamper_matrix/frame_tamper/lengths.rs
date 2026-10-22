// 长度字段篡改 3 条：改大 / 改小 / 超过读取上限。
//
// 本文件由 `tests/tamper_matrix/frame_tamper.rs` 用 `include!` 文本并入同一模块；
// `use` 与共享助手（`healthy_session`）都在入口文件。

/// 长度字段篡改（改大）：声明长度大于实际字节数 ⇒ 必须被拒绝，**不是**越界读、
/// 也不是截断后继续。
///
/// 判据位置：`src/frame.rs:124-128`——`Frame::read` 先按声明长度读满
/// `length` 字节，字节不足时读操作超时 ⇒ `Error::Timeout`（`src/frame.rs:139`）。
#[tokio::test]
async fn inflated_length_field_is_rejected_not_truncated() {
    timeout(TOTAL, async {
        let target = spawn_target().await;
        let mut harness = healthy_session().await;
        let payload = push_with_target(target.addr, b"inflated-length-probe");
        let mut bytes = Frame {
            command: Command::Push,
            stream_id: 1,
            data: payload,
        }
        .encode()
        .expect("编码 PUSH");
        // 声明长度比实际载荷大 64 字节：服务端永远等不到那么多字节。
        let inflated = declared_length(&bytes) + 64;
        set_length(&mut bytes, inflated);
        harness.send_raw(&bytes).await;

        // 不关闭客户端半：让服务端自己的读超时先触发（否则 EOF 会掩盖判据）。
        let outcome = harness.settle().await;
        assert!(
            matches!(outcome, Err(Error::Timeout) | Err(Error::Io(_))),
            "长度改大必须失败（等不到那么多字节），实际：{outcome:?}"
        );
        assert_eq!(
            target.accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "长度改大的帧不得触发拨号"
        );
        assert!(
            target.received().is_empty(),
            "长度改大的帧不得把载荷交给上层"
        );
    })
    .await
    .expect("用例超时");
}

/// 长度字段篡改（改小）：声明长度小于实际字节数 ⇒ 多出的字节会错位成新的帧头，
/// 必须被拒绝（**不是**截断后继续正常跑）。
///
/// 本用例把多出的字节设计成**未定义命令字节**，使判据确定：读满 7 字节头后
/// `Command::try_from` 立刻 `Err(Error::Invalid)`（`src/frame.rs:45`、`src/frame.rs:123`）。
/// 同时被截短的地址前缀不足以解析出目标 ⇒ 目标从未被拨号。
#[tokio::test]
async fn deflated_length_field_is_rejected_not_truncated() {
    timeout(TOTAL, async {
        let target = spawn_target().await;
        let mut harness = healthy_session().await;
        // 地址字节的第 4 位取 0x0B（未定义命令）：多出的字节以它开头即非法。
        let mut payload = vec![0x01, 127, 0, 0x0B, 0, 0, 0];
        payload.extend_from_slice(b"deflated");
        let mut bytes = Frame {
            command: Command::Push,
            stream_id: 1,
            data: payload,
        }
        .encode()
        .expect("编码 PUSH");
        // 声明长度砍到 3 字节：地址前缀不完整，多出的 4 字节成为下一帧的头。
        set_length(&mut bytes, 3);
        harness.send_raw(&bytes).await;

        let outcome = harness.finish().await;
        assert!(
            matches!(outcome, Err(Error::Invalid)),
            "长度改小必须因帧流错位而失败，实际：{outcome:?}"
        );
        assert_eq!(
            target.accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "长度改小的帧不得触发拨号（地址前缀不完整）"
        );
        assert!(
            target.received().is_empty(),
            "长度改小的帧不得把载荷交给上层"
        );
    })
    .await
    .expect("用例超时");
}

/// 长度字段篡改：超过读取上限时必须显式拒绝（`Error::TooLarge`），不越界读。
///
/// 判据位置：`src/frame.rs:125-127`——`length > limit` 即 `Error::TooLarge`。
/// 注：服务端会话固定用 `u16::MAX` 作上限（`src/server/session.rs:101`），
/// 故该判据在会话路径上不可达；本用例直接在帧原语层断言它确实存在。
#[tokio::test]
async fn length_field_above_read_limit_is_rejected() {
    timeout(TOTAL, async {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let bytes = Frame {
            command: Command::Push,
            stream_id: 1,
            data: vec![0xAA; 100],
        }
        .encode()
        .expect("编码 PUSH");
        assert_eq!(declared_length(&bytes), 100);
        server.write_all(&bytes).await.expect("写帧");
        let outcome = Frame::read(&mut client, 64, WAIT).await;
        assert!(
            matches!(outcome, Err(Error::TooLarge)),
            "长度超过读取上限必须显式拒绝"
        );
    })
    .await
    .expect("用例超时");
}
