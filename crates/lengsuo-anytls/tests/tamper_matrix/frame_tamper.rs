//! 帧层篡改用例：命令字节、长度字段、认证块。
//!
//! 口径：AnyTLS 的帧头只有 `cmd(1) | sid(4) | len(2)`
//! （参考 anytls-go `proxy/session/frame.go:37-49`），**没有帧级 MAC**。
//! 因此帧层能判定的篡改是**结构性**的：未知命令、长度与实际字节不符、
//! 命令与载荷不自洽、认证摘要不匹配。本模块逐条钉住这些判据。
//!
//! 载荷内容本身的完整性**不在帧层**——参考同样没有；那部分由 TLS 提供，
//! 见 `tls_tamper`。
#![allow(dead_code)]

use crate::harness::{
    declared_length, flip_bit, push_with_target, set_length, settings, spawn_target, Harness,
    PASSWORD, TOTAL, WAIT,
};
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    Error,
};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

/// 认证块：`SHA256(口令)` 32 字节 + BE16 padding 长度 + padding。
/// 用**生产代码路径**（`Credential::send`）生成，避免自造摘要实现。
async fn auth_block(password: &[u8]) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    Credential::new(password)
        .send(&mut buffer, b"", WAIT)
        .await
        .expect("生成认证块");
    buffer
}

/// 建会话、认证、发送 Settings 并读到 ServerSettings（证明会话健康）。
/// 返回已就绪的夹具。
async fn healthy_session() -> Harness {
    let mut harness = Harness::start(PASSWORD).await;
    harness.send(settings()).await;
    let frame = harness.expect(Command::ServerSettings).await;
    assert_eq!(frame.data, b"v=2", "ServerSettings 载荷");
    harness
}

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

/// 认证块篡改：口令摘要改 1 bit ⇒ 必须认证失败，且**不得**进入帧循环。
///
/// 判据位置：`src/auth.rs:67-69`——常量时间比对（`subtle::ConstantTimeEq`）
/// 不等即 `Error::Authentication`。
/// 参考 anytls-go `cmd/server/inbound_tcp.go:40-45`：32 字节摘要不等即走
/// `fallback`（未实现 = 直接断连）⇒ 与本仓一致。
#[tokio::test]
async fn authentication_block_tampering_is_rejected() {
    timeout(TOTAL, async {
        let target = spawn_target().await;
        let (client, server_side) = tokio::io::duplex(64 * 1024);
        let config = lengsuo_anytls::server::ServerConfig::new(PASSWORD, WAIT);
        let task = tokio::spawn(lengsuo_anytls::server::serve(server_side, config));
        let mut client = client;

        // 用生产代码路径生成认证块，再改摘要的第 1 个字节。
        let mut block = auth_block(PASSWORD).await;
        flip_bit(&mut block, 0);
        client.write_all(&block).await.expect("写篡改认证块");
        client.flush().await.expect("刷新");

        // 服务端不得回应任何帧（认证失败发生在帧循环之前）。
        // 注意：`timeout(...)` 成功时返回 `Ok(inner)`，故要判**内层**结果。
        let read = timeout(WAIT, Frame::read(&mut client, u16::MAX, WAIT)).await;
        match read {
            Err(_elapsed) => {}
            Ok(Err(err)) => assert!(
                matches!(err, Error::Io(_)),
                "认证失败后服务端只能断开，不得回语义帧，实际错误：{err}"
            ),
            Ok(Ok(_frame)) => panic!("认证失败后服务端不得发送任何帧"),
        }

        drop(client);
        let outcome = timeout(TOTAL, task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic");
        assert!(
            matches!(outcome, Err(Error::Authentication)),
            "认证块篡改必须以 Error::Authentication 失败，实际：{outcome:?}"
        );
        assert_eq!(
            target.accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "认证失败不得触发任何拨号"
        );
    })
    .await
    .expect("用例超时");
}

/// 认证块篡改：padding 长度字段改大到超上限 ⇒ 必须被拒绝（`Error::TooLarge`）。
///
/// 判据位置：`src/auth.rs:57-59`——`length > max_padding` 即 `Error::TooLarge`。
/// 上限来自 `src/server/mod.rs:21`（`PADDING_LIMIT = 4096`）。
#[tokio::test]
async fn authentication_padding_length_above_limit_is_rejected() {
    timeout(TOTAL, async {
        let (client, server_side) = tokio::io::duplex(64 * 1024);
        let config = lengsuo_anytls::server::ServerConfig::new(PASSWORD, WAIT);
        let task = tokio::spawn(lengsuo_anytls::server::serve(server_side, config));
        let mut client = client;

        let mut block = auth_block(PASSWORD).await;
        // 摘要正确；把 padding 长度改成 0xFFFF（远超 4096 上限）。
        block[32..34].copy_from_slice(&u16::MAX.to_be_bytes());
        client.write_all(&block).await.expect("写篡改认证块");
        client.flush().await.expect("刷新");

        drop(client);
        let outcome = timeout(TOTAL, task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic");
        assert!(
            matches!(outcome, Err(Error::TooLarge)),
            "认证块 padding 长度超上限必须以 Error::TooLarge 失败，实际：{outcome:?}"
        );
    })
    .await
    .expect("用例超时");
}

/// 认证块篡改：摘要整段替换成等长垃圾 ⇒ 同样必须认证失败。
///
/// 与 `authentication_block_tampering_is_rejected` 互补：证明判据是
/// **摘要比对**而不是「碰巧有一位不同」。
#[tokio::test]
async fn authentication_block_fully_replaced_is_rejected() {
    timeout(TOTAL, async {
        let (client, server_side) = tokio::io::duplex(64 * 1024);
        let config = lengsuo_anytls::server::ServerConfig::new(PASSWORD, WAIT);
        let task = tokio::spawn(lengsuo_anytls::server::serve(server_side, config));
        let mut client = client;

        let mut block = auth_block(PASSWORD).await;
        for byte in block.iter_mut().take(32) {
            *byte = 0x00;
        }
        client.write_all(&block).await.expect("写替换认证块");
        client.flush().await.expect("刷新");

        drop(client);
        let outcome = timeout(TOTAL, task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic");
        assert!(
            matches!(outcome, Err(Error::Authentication)),
            "整段替换的摘要必须以 Error::Authentication 失败，实际：{outcome:?}"
        );
    })
    .await
    .expect("用例超时");
}
