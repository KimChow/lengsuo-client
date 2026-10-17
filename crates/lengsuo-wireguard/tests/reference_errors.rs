//! 错误路径的官方参考验收：与固定 commit 的 wireguard-go 测试适配器在回环 UDP
//! 上交换**错 PSK / 篡改 / 截断 / 重放**报文，断言两端都 fail-closed。
//!
//! 证据范围（刻意收窄，不夸大为完整 WireGuard 运行时互通）：
//! - 参考端是 `device` 包内的**测试适配器**：真实 Noise 握手状态机
//!   （`ConsumeMessageInitiation` / `CreateMessageResponse`）、真实 cookie
//!   MAC1 校验、真实 keypair AEAD 解封与真实 replayFilter，绑定
//!   `tuntest.NewChannelTUN()` 用户态假 TUN；**没有内核 TUN、没有设备转发、
//!   没有内层 IP 解析**。
//! - 参考二进制由负责人预先构建（`LENGSUO_WG_REFERENCE_BIN`），本测试不构建、
//!   不修改参考仓。
//! - 全部密钥为测试专用假凭据；断言不超过上述语义。
//!
//! 脚手架见 `tests/support/reference.rs`；超时链条有限（socket 6s、Go 8s
//! deadline、`-test.timeout 12s`），子进程由 `Reference` 的 Drop 回收。

mod support;

use lengsuo_wireguard::handshake::Handshake;
use lengsuo_wireguard::transport::{Error as WgError, Receiver, Sender};
use lengsuo_wireguard::ReplayError;
use support::reference::{
    establish, loopback_socket, name_of, no_response, output_text, recv_reply, server_public,
    Reference, CLIENT_STATIC, EPHEMERAL_SEED, LOCAL_INDEX, PSK_ON, PSK_WRONG, RUST_PAYLOAD,
};

/// 1. 错 PSK：Rust 侧认证失败并 poison；真实 Go 端等不到合法 transport 而失败。
#[test]
#[ignore = "需要固定 wireguard-go 参考二进制 LENGSUO_WG_REFERENCE_BIN"]
fn wrong_psk_fails_closed_on_both_sides() {
    let socket = loopback_socket();
    let addr = socket.local_addr().unwrap().to_string();
    let reference = Reference::spawn(Some(&PSK_ON), &addr);
    let mut buffer = [0u8; 2048];
    let (n, peer) = socket.recv_from(&mut buffer).expect("ready 报文");
    assert_eq!(&buffer[..n], b"wireguard-reference-ready");
    socket.connect(peer).expect("connect");
    let mut handshake = Handshake::new(
        &CLIENT_STATIC,
        &server_public(),
        Some(PSK_WRONG),
        LOCAL_INDEX,
    )
    .expect("构造");
    socket
        .send(
            &handshake
                .create_initiation(EPHEMERAL_SEED)
                .expect("initiation"),
        )
        .expect("发 initiation");
    let n = socket.recv(&mut buffer).expect("参考端仍应发 response");
    let outcome = handshake.consume_response(&buffer[..n]);
    assert!(
        matches!(outcome, Err(WgError::AuthFailed)),
        "错 PSK 必须认证失败且不得派生密钥：{}",
        name_of(outcome.as_ref().err())
    );
    let again = handshake.consume_response(&buffer[..n]);
    assert!(
        matches!(again, Err(WgError::Poisoned)),
        "认证失败后必须永久 poison，不得再产出密钥：{}",
        name_of(again.as_ref().err())
    );
    let output = reference.finish();
    let text = output_text(&output);
    assert!(
        !output.status.success(),
        "错 PSK 下参考端不得完成会话：{text}"
    );
    assert!(
        text.contains("i/o timeout"),
        "参考端应因等不到合法 transport 而超时失败：{text}"
    );
}

/// 已封装 transport 的破坏方式。
#[derive(Clone, Copy, Debug)]
enum Tamper {
    /// 翻转标签末字节 → 参考端 AEAD Open 失败。
    TagByte,
    /// 截断到 20 字节（低于 32 最小长度）→ 参考端结构检查失败。
    Truncated,
    /// 改写接收者标识 → 参考端 index 比对失败。
    Receiver,
}

fn apply_tamper(packet: &mut Vec<u8>, tamper: Tamper) {
    match tamper {
        Tamper::TagByte => {
            let last = packet.len() - 1;
            packet[last] ^= 0x01;
        }
        Tamper::Truncated => packet.truncate(20),
        Tamper::Receiver => packet[4] ^= 0xff,
    }
}

/// 2-4. 真实 Go 核心必须拒收被篡改 / 截断 / 错接收者的 transport 报文。
///
/// 握手用正确的无 PSK 分支完成（与现有 happy-path 同一真实 Go 代码路径），
/// 随后 Rust 发出被破坏的 transport；适配器必须在其真实解密与 index 检查处
/// `t.Fatal` 并非零退出，且输出含对应的官方拒绝理由。
fn reference_rejects_broken_transport(tamper: Tamper) {
    let session = establish(None);
    let mut sender = Sender::new(session.send.clone(), session.remote_index, 0);
    let mut packet = sender.seal(RUST_PAYLOAD).expect("封装合法报文");
    apply_tamper(&mut packet, tamper);
    session
        .socket
        .send(&packet)
        .expect("发送被破坏报文（回环）");
    let output = session.reference.finish();
    let text = output_text(&output);
    assert!(
        !output.status.success(),
        "参考端必须拒绝 {tamper:?} transport：{text}"
    );
    let marker = match tamper {
        Tamper::TagByte => "Rust transport authentication failed",
        Tamper::Truncated => "bad transport",
        Tamper::Receiver => "receiver index mismatch",
    };
    assert!(
        text.contains(marker),
        "参考端拒绝理由应含 {marker}，实际：{text}"
    );
}

#[test]
#[ignore = "需要固定 wireguard-go 参考二进制 LENGSUO_WG_REFERENCE_BIN"]
fn go_reference_rejects_tampered_transport_tag() {
    reference_rejects_broken_transport(Tamper::TagByte);
}

#[test]
#[ignore = "需要固定 wireguard-go 参考二进制 LENGSUO_WG_REFERENCE_BIN"]
fn go_reference_rejects_truncated_transport() {
    reference_rejects_broken_transport(Tamper::Truncated);
}

#[test]
#[ignore = "需要固定 wireguard-go 参考二进制 LENGSUO_WG_REFERENCE_BIN"]
fn go_reference_rejects_wrong_receiver_transport() {
    reference_rejects_broken_transport(Tamper::Receiver);
}

/// initiation 的破坏方式。
#[derive(Clone, Copy, Debug)]
enum InitBreak {
    /// 截断 1 字节（147B）：参考 `MessageInitiation.unmarshal` 长度检查失败。
    Truncated,
    /// 翻转 MAC1 首字节：参考 `CookieChecker.CheckMAC1` 失败。
    Mac1,
}

/// 8-9. 真实 Go 核心必须拒收被截断 / MAC1 被篡改的 initiation，
/// 因此 Rust 在有限超时内收不到任何 response。方向与第 2-4 项相反：
/// 这里由 Rust 发包、参考端 `device` 包的官方检查器判定。
fn go_rejects_broken_initiation(kind: InitBreak) {
    let socket = loopback_socket();
    let addr = socket.local_addr().unwrap().to_string();
    let reference = Reference::spawn(None, &addr);
    let mut buffer = [0u8; 2048];
    let (n, peer) = socket.recv_from(&mut buffer).expect("ready 报文");
    assert_eq!(&buffer[..n], b"wireguard-reference-ready");
    socket.connect(peer).expect("connect");
    let mut handshake =
        Handshake::new(&CLIENT_STATIC, &server_public(), None, LOCAL_INDEX).expect("构造");
    let mut wire = handshake
        .create_initiation(EPHEMERAL_SEED)
        .expect("initiation")
        .to_vec();
    assert_eq!(wire.len(), 148);
    match kind {
        InitBreak::Truncated => wire.truncate(147),
        InitBreak::Mac1 => wire[116] ^= 0x01, // initiation 的 mac1 起点为 116
    }
    socket.send(&wire).expect("发送被破坏的 initiation（回环）");
    let outcome = socket.recv(&mut buffer);
    assert!(
        outcome.as_ref().err().is_some_and(no_response),
        "参考端拒绝后不得返回 response：{outcome:?}"
    );
    let output = reference.finish();
    let text = output_text(&output);
    assert!(
        !output.status.success(),
        "参考端必须拒绝 {kind:?} initiation：{text}"
    );
    let marker = match kind {
        InitBreak::Truncated => "message length mismatch",
        InitBreak::Mac1 => "initiation MAC1 rejected",
    };
    assert!(
        text.contains(marker),
        "参考端拒绝理由应含 {marker}，实际：{text}"
    );
}

#[test]
#[ignore = "需要固定 wireguard-go 参考二进制 LENGSUO_WG_REFERENCE_BIN"]
fn go_reference_rejects_truncated_initiation() {
    go_rejects_broken_initiation(InitBreak::Truncated);
}

#[test]
#[ignore = "需要固定 wireguard-go 参考二进制 LENGSUO_WG_REFERENCE_BIN"]
fn go_reference_rejects_tampered_initiation_mac1() {
    go_rejects_broken_initiation(InitBreak::Mac1);
}

/// 5. 参考端真实 response 的 MAC1 被改动后，Rust 必须认证失败并 poison。
#[test]
#[ignore = "需要固定 wireguard-go 参考二进制 LENGSUO_WG_REFERENCE_BIN"]
fn rust_rejects_tampered_mac1_of_reference_response() {
    let socket = loopback_socket();
    let addr = socket.local_addr().unwrap().to_string();
    let reference = Reference::spawn(None, &addr);
    let mut buffer = [0u8; 2048];
    let (n, peer) = socket.recv_from(&mut buffer).expect("ready 报文");
    assert_eq!(&buffer[..n], b"wireguard-reference-ready");
    socket.connect(peer).expect("connect");
    let mut handshake =
        Handshake::new(&CLIENT_STATIC, &server_public(), None, LOCAL_INDEX).expect("构造");
    socket
        .send(
            &handshake
                .create_initiation(EPHEMERAL_SEED)
                .expect("initiation"),
        )
        .expect("发 initiation");
    let n = socket.recv(&mut buffer).expect("response 报文");
    assert_eq!(n, 92, "参考 response 应为 92 字节");
    let mut forged = buffer[..n].to_vec();
    forged[60] ^= 0x01; // 92B 布局中 mac1 起点为 60
    let outcome = handshake.consume_response(&forged);
    assert!(
        matches!(outcome, Err(WgError::AuthFailed)),
        "篡改 MAC1 的参考 response 必须被拒绝：{}",
        name_of(outcome.as_ref().err())
    );
    let again = handshake.consume_response(&forged);
    assert!(
        matches!(again, Err(WgError::Poisoned)),
        "MAC1 失败后必须永久 poison：{}",
        name_of(again.as_ref().err())
    );
    let output = reference.finish();
    assert!(
        !output.status.success(),
        "被拒后参考端不得完成会话：{}",
        output_text(&output)
    );
}

/// 用例 6：参考端真实 reply 的重复投递被重放窗口拒绝且不 poison；
/// 同一流改第一个字节的 reply 报认证失败并 poison——两类失败语义可区分。
#[test]
#[ignore = "需要固定 wireguard-go 参考二进制 LENGSUO_WG_REFERENCE_BIN"]
fn rust_replays_reference_reply_without_poison() {
    let session = establish(None);
    let mut sender = Sender::new(session.send.clone(), session.remote_index, 0);
    let wire = sender.seal(RUST_PAYLOAD).expect("封装");
    session.socket.send(&wire).expect("发 transport");
    let mut buffer = [0u8; 2048];
    let n = recv_reply(&session.socket, &mut buffer);
    let reply = buffer[..n].to_vec();
    let mut receiver = Receiver::new(session.receive.clone(), session.local_index, u64::MAX);
    let opened = receiver.open(&reply).expect("参考端 reply 必须可解封");
    assert_eq!(opened.plaintext.as_slice(), b"go-rust-payload!");
    let highest_before = receiver.highest();
    let replay = receiver.open(&reply);
    assert!(
        matches!(replay, Err(WgError::Replay(ReplayError::Duplicate { .. }))),
        "重放参考 reply 必须报 Duplicate：{replay:?}"
    );
    assert!(!receiver.is_poisoned(), "重放拒绝不应 poison 接收端");
    assert_eq!(
        receiver.highest(),
        highest_before,
        "重放拒绝不应改变窗口状态"
    );
    let mut tampered = reply.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let mut strict = Receiver::new(session.receive.clone(), session.local_index, u64::MAX);
    let outcome = strict.open(&tampered);
    assert!(
        matches!(outcome, Err(WgError::AuthFailed)),
        "篡改 reply 标签应报认证失败：{outcome:?}"
    );
    assert!(strict.is_poisoned(), "AEAD 失败必须永久 poison");
    let output = session.reference.finish();
    assert!(
        output.status.success(),
        "本用例的合法双向部分应通过：{}",
        output_text(&output)
    );
}

/// 用例 7：对参考端真实 reply 做截断。
///
/// 短于 32 字节属头部结构拒绝（不 poison）；头部合法但密文尾部被截掉属
/// AEAD 认证失败（永久 poison，不回退明文）。
///
/// 素材来自真实 Go 封装的 transport 报文，不是自家 roundtrip 构造。
#[test]
#[ignore = "需要固定 wireguard-go 参考二进制 LENGSUO_WG_REFERENCE_BIN"]
fn truncated_reference_reply_is_structural_or_auth_rejection() {
    let session = establish(None);
    let mut sender = Sender::new(session.send.clone(), session.remote_index, 0);
    let wire = sender.seal(RUST_PAYLOAD).expect("封装");
    session.socket.send(&wire).expect("发 transport");
    let mut buffer = [0u8; 2048];
    let n = recv_reply(&session.socket, &mut buffer);
    let reply = buffer[..n].to_vec();
    assert!(reply.len() > 32, "参考 reply 应含密文正文");
    let output = session.reference.finish();
    assert!(
        output.status.success(),
        "参考端应正常完成本次合法双向：{}",
        output_text(&output)
    );
    for len in [0usize, 4, 16, 31] {
        let mut receiver = Receiver::new(session.receive.clone(), session.local_index, u64::MAX);
        let truncated = &reply[..len.min(reply.len())];
        let outcome = receiver.open(truncated);
        assert!(
            outcome.is_err(),
            "长度 {len} 的截断 reply 必须被拒绝：{outcome:?}"
        );
        assert!(
            matches!(outcome, Err(WgError::Wire(_))),
            "长度 {len} 应是头部结构拒绝：{outcome:?}"
        );
        assert!(
            !receiver.is_poisoned(),
            "长度 {len} 属结构拒绝，不得 poison"
        );
    }
    let mut receiver = Receiver::new(session.receive.clone(), session.local_index, u64::MAX);
    let short_of_tag = reply[..reply.len() - 8].to_vec();
    let outcome = receiver.open(&short_of_tag);
    assert!(
        matches!(outcome, Err(WgError::AuthFailed)),
        "截掉密文尾部应报认证失败：{outcome:?}"
    );
    assert!(receiver.is_poisoned(), "AEAD 失败必须 poison");
}
