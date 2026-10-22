//! **官方 anytls-go v0.0.13 服务端**对截断帧的实际反应（参考侧取证，`#[ignore]`）。
//!
//! 这两条是**参考对端**证据（不是本仓 roundtrip）：起官方 `anytls-server`，
//! 完成真实 TLS 握手与认证，然后发截断帧并断开，观察官方 server 的反应。
//!
//! 与源码取证一致（`proxy/session/session.go:190` 的 `io.ReadFull`）：
//! 1. 官方 server **不会**把截断帧的半截载荷交给目标（`session.go:196-208`：
//!    `io.ReadFull` 失败即 `return err`，`stream.pipeW.Write` 根本不执行）；
//! 2. 官方 server 对截断的响应是**断开连接**（会话随 `recvLoop` 返回而结束），
//!    而不是像本仓旧实现那样把截断当「正常收尾」并静默接受。
//!
//! ⚠️ **Windows 差异**：官方 anytls-go v0.0.13 服务端在 Windows 上**自身崩溃**
//! （上游缺陷，见 `tests/interop_udp.rs:310-325` 的注释：`cmd/server/outbound_tcp.go:39`
//! 的 `net.ListenPacket("udp", "")` 在 Windows 上非法，随后空指针解引用）。
//! 故本模块的用例加 `#[cfg(not(windows))]` 门控——**用 `cfg` 排除而不是「跑完再跳过」**：
//! 这样 Windows 上的实际通过数更少，门禁的 `expected_passed` 按平台如实登记，
//! **不冒充通过**。
#![allow(dead_code)]

use super::harness::{push_with_target, spawn_target, WAIT};
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// 参考侧 Settings 载荷（与官方 server 夹具协商到 v2）。
const SETTINGS: &[u8] = b"v=2\nclient=lengsuo-anytls\npadding-md5=75cff2ad89aadf5e257059ee571ebe11";

/// 与官方 server 完成认证 + Settings(v=2) 协商，返回 TLS 流与夹具。
///
/// 口令必须与官方 server 夹具一致（`interop/support.rs` 的 `PASSWORD`，
/// 由 `Process::server` 的 `-p` 传入）。
#[cfg(not(windows))]
async fn official_socket(
    label: &str,
) -> Option<(crate::interop_harness::Fixture, crate::tls::TlsStream)> {
    let fixture = crate::interop_harness::Fixture::start(label).await?;
    let connector = fixture.connector().expect("TLS 客户端配置");
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", fixture.port()))
        .await
        .expect("连接官方 server 端口");
    let mut stream = crate::tls::client_handshake(&connector, crate::tls::EXPECTED_NAME, tcp, WAIT)
        .await
        .expect("TLS 握手（含证书链与名称校验）");

    Credential::new(super::support::PASSWORD.as_bytes())
        .send(&mut stream, b"", WAIT)
        .await
        .expect("认证发送");
    Frame {
        command: Command::Settings,
        stream_id: 0,
        data: SETTINGS.to_vec(),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("写 Settings");
    Some((fixture, stream))
}

/// **官方 anytls-go v0.0.13 服务端**对截断帧的实际反应（参考侧取证）。
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl"]
async fn official_server_closes_connection_on_truncated_frame() {
    let Some((mut fixture, mut stream)) = official_socket("trunc-official").await else {
        return;
    };

    // 收 ServerSettings（确认协商到 v2，且连接此刻是活的）。
    let mut negotiated = false;
    while !negotiated {
        let frame = Frame::read(&mut stream, u16::MAX, WAIT)
            .await
            .expect("读服务端帧");
        if frame.command == Command::ServerSettings {
            negotiated = true;
        }
    }

    // 发**半截帧头**（7 字节只写 3 字节）后断开。
    stream
        .write_all(&[Command::Push as u8, 0x00, 0x00])
        .await
        .expect("写半截帧头");
    stream.flush().await.expect("刷新");
    stream.shutdown().await.expect("半关闭写端");

    // 判据：官方 server 必须**断开**（读端拿到 EOF / 断连），
    // 而不是在截断后继续把会话当「正常收尾」并保持连接。
    let mut sink = Vec::new();
    let read = timeout(WAIT, stream.read_to_end(&mut sink)).await;
    assert!(
        read.is_ok(),
        "官方 server 必须在截断后断开连接，不得保持会话存活"
    );

    let (code, log) = fixture.finish();
    println!("anytls-server exit code={code:?}");
    assert!(
        !log.contains(super::support::PASSWORD),
        "server 日志不得出现口令"
    );
}

/// **官方 anytls-go v0.0.13 服务端**对「完整头 + 截断载荷」的反应（参考侧取证）。
///
/// 这是上面那条的**可观测副作用**版本：参考的 `session.go:196-208` 在
/// `io.ReadFull` 读不满载荷时**直接 `return err`**，根本不会执行
/// `stream.pipeW.Write(buffer)` ⇒ **目标从未被拨号**。
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 LENGSUO_ANYTLS_SERVER 与 openssl"]
async fn official_server_never_dials_target_for_truncated_payload() {
    let Some((mut fixture, mut stream)) = official_socket("trunc-payload-official").await else {
        return;
    };

    // 目标：记录被拨号的次数（**不**回显，只观察「有没有连上来」）。
    let target = spawn_target().await;
    let payload = b"official-truncated-payload-probe";

    // 完整帧头（长度字段 = 100）+ 只有 10 字节载荷 ⇒ 载荷被截断。
    let mut bytes = Frame {
        command: Command::Push,
        stream_id: 1,
        data: push_with_target(target.addr, payload),
    }
    .encode()
    .expect("编码 PUSH");
    bytes[5..7].copy_from_slice(&100u16.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 10]);
    stream.write_all(&bytes).await.expect("写截断帧");
    stream.flush().await.expect("刷新");
    stream.shutdown().await.expect("半关闭写端");

    // 判据 1：官方 server 断开连接。
    let mut sink = Vec::new();
    let read = timeout(WAIT, stream.read_to_end(&mut sink)).await;
    assert!(
        read.is_ok(),
        "官方 server 必须在截断后断开连接，不得保持会话存活"
    );

    // 判据 2：**目标从未被拨号** ⇒ 截断的载荷没有被当成有效帧交付。
    // 留一点余量给官方 server 的异步收尾。
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        target.accepted.load(Ordering::SeqCst),
        0,
        "官方 server 不得为截断的帧拨号目标（半截载荷不得交付）"
    );
    assert!(
        target.received().is_empty(),
        "官方 server 不得把半截载荷交给目标"
    );

    let (code, log) = fixture.finish();
    println!("anytls-server exit code={code:?}");
    assert!(
        !log.contains(super::support::PASSWORD),
        "server 日志不得出现口令"
    );
}
