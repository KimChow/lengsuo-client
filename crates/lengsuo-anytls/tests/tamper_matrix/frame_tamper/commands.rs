// 命令字节篡改 3 条：未知命令 / 改成已知命令 / 改成 Waste。
//
// 本文件由 `tests/tamper_matrix/frame_tamper.rs` 用 `include!` 文本并入同一模块；
// `use` 与共享助手（`healthy_session`）都在入口文件。

/// 帧头命令字节篡改：**未知命令**必须被拒绝，不是当作已知命令处理。
///
/// 判据位置：`src/frame.rs:45`（`Command::try_from` 的 `_ => Err(Error::Invalid)`）
/// 与 `src/frame.rs:123`（`Frame::read` 读头后立刻解析命令）。
/// 参考 anytls-go `proxy/session/session.go:358-360` 的 `default:` 分支
/// **静默忽略**未知命令 ⇒ 本仓比参考更严，见 `docs/anytls-tamper.md` 偏离清单。
#[tokio::test]
async fn unknown_command_byte_is_rejected_and_session_fails_closed() {
    timeout(TOTAL, async {
        let target = spawn_target().await;
        let mut harness = healthy_session().await;

        // 构造一条合法的 PUSH（目标地址 + 载荷），再把命令字节改成未定义值。
        let payload = push_with_target(target.addr, b"unknown-command-probe");
        let mut bytes = Frame {
            command: Command::Push,
            stream_id: 1,
            data: payload,
        }
        .encode()
        .expect("编码 PUSH");
        bytes[0] = 0xFF; // 参考里没有的命令字节
        harness.send_raw(&bytes).await;

        // 会话必须以失败结束（fail-closed），不得当作已知命令继续。
        let outcome = harness.finish().await;
        assert!(
            matches!(outcome, Err(Error::Invalid)),
            "未知命令必须使会话以 Error::Invalid 失败，实际：{outcome:?}"
        );
        // 篡改帧的载荷绝不能交给上层（目标既没被拨号，也没收到字节）。
        assert_eq!(
            target.accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "未知命令帧不得触发拨号"
        );
        assert!(target.received().is_empty(), "未知命令帧的载荷不得交给上层");
    })
    .await
    .expect("用例超时");
}

/// 帧头命令字节篡改：改成**另一个已知命令**同样必须被拒绝（不得按新命令语义放行）。
///
/// 判据位置：`src/server_state.rs:95-155`（各命令的结构约束）与
/// `src/server_state.rs:151-153`（客户端方向帧一律 `ServerToClient` 违规）。
#[tokio::test]
async fn known_command_byte_swap_is_never_accepted_as_original() {
    timeout(TOTAL, async {
        // 目标命令：把 PUSH 改成这些命令，逐一断言会话 fail-closed。
        let swaps = [
            Command::Syn,
            Command::Fin,
            Command::Settings,
            Command::ServerSettings,
            Command::SynAck,
            Command::Alert,
            Command::UpdatePadding,
            Command::HeartRequest,
            Command::HeartResponse,
        ];
        for command in swaps {
            let target = spawn_target().await;
            let mut harness = healthy_session().await;
            let payload = push_with_target(target.addr, b"known-command-swap");
            let mut bytes = Frame {
                command: Command::Push,
                stream_id: 1,
                data: payload,
            }
            .encode()
            .expect("编码 PUSH");
            bytes[0] = command as u8;
            harness.send_raw(&bytes).await;

            let outcome = harness.finish().await;
            assert!(
                matches!(outcome, Err(Error::Invalid)),
                "把 PUSH 改成 {command:?} 必须使会话失败，实际：{outcome:?}"
            );
            assert_eq!(
                target.accepted.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "改成 {command:?} 的帧不得触发拨号"
            );
            assert!(
                target.received().is_empty(),
                "改成 {command:?} 的帧不得把载荷交给上层"
            );
        }
    })
    .await
    .expect("用例超时");
}

/// 帧头命令字节篡改：改成 `Waste`（填充命令）时载荷被丢弃、目标从未被拨号。
///
/// 这一格**不是**硬拒绝，而是「静默丢弃」：`src/server_state.rs:97-98` 对
/// Waste 不做任何结构校验（参考 anytls-go `proxy/session/session.go:260-268`
/// 同样只丢弃），所以帧层无法区分「本来是填充」与「被改成填充」——
/// 参考实现根本**不校验帧头**（见 `docs/anytls-tamper.md` 偏离清单）。
/// 断言口径因此是**载荷不得交给上层**（fail-closed 的可观测后果），
/// 而不是「必须报某个错误」。
#[tokio::test]
async fn command_byte_turned_into_waste_never_delivers_payload() {
    timeout(TOTAL, async {
        let target = spawn_target().await;
        let mut harness = healthy_session().await;
        let payload = push_with_target(target.addr, b"waste-swap-probe");
        let mut bytes = Frame {
            command: Command::Push,
            stream_id: 1,
            data: payload,
        }
        .encode()
        .expect("编码 PUSH");
        bytes[0] = Command::Waste as u8;
        harness.send_raw(&bytes).await;

        // 会话可以继续（Waste 是合法帧），但载荷绝不能被转发。
        let outcome = harness.finish().await;
        assert!(
            outcome.is_ok(),
            "改成 Waste 的帧本身是合法帧，会话应可继续，实际：{outcome:?}"
        );
        assert_eq!(
            target.accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "改成 Waste 的帧不得触发拨号"
        );
        assert!(
            target.received().is_empty(),
            "改成 Waste 的帧不得把载荷交给上层"
        );
    })
    .await
    .expect("用例超时");
}
