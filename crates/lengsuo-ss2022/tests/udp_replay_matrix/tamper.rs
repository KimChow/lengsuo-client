//! ④ 伪造 / 篡改 / 截断 EIH 必须 **fail-closed**，且**不得污染**会话窗口。
//!
//! 参考对应路径：`shadowaead_2022/service_multi.go` 的服务端 UDP 收包
//! （`:274-280` 身份指纹计算、`:288` 指纹失配、`:330-334` AEAD 解密失败）。
//!
//! 归属：`tests/udp_replay_matrix.rs` 的 ④ 组用例。

use super::{
    clock, expect_error, key, make_server, now_secs, one_layer_psks, one_layer_users, peer, target,
};
use lengsuo_ss2022::{
    crypto::Method,
    eih_udp::{EihUdpChain, EihUdpSender},
    Error,
};

/// ④ 伪造 / 篡改 EIH 一律 fail-closed，且**不得污染**会话窗口。
///
/// 关键性质（与参考 `service_multi.go:330-338` 一致：AEAD 成功之后才 `Add`）：
/// 被拒的报文**不占**窗口位 ⇒ 随后同一 packet id 的合法报文仍应被接受。
#[test]
fn tampered_or_forged_eih_is_rejected_fail_closed() {
    let psks = one_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("身份链应可构造");
    let mut sender = EihUdpSender::new(chain).expect("发送端应可构造");
    let packet = sender
        .seal(&target(), b"authentic", now_secs(), 0)
        .expect("封包应成功");
    let mut server = make_server(psks[0].clone(), one_layer_users(Method::Aes256), 1);

    // 线上布局：separate header 16 + 身份头 16 + AEAD 密文。
    let mut tampered_identity = packet.clone();
    tampered_identity[16] ^= 0x01;
    let error = expect_error(server.receive(&tampered_identity, peer(1), clock()));
    assert!(
        matches!(error, Error::IdentityUnknown),
        "篡改身份头必须拒绝，实际 {error:?}"
    );

    // 篡改 separate header 的会话 id 段 ⇒ 身份指纹失配 ⇒ 拒绝。
    let mut tampered_session = packet.clone();
    tampered_session[0] ^= 0x01;
    let error = expect_error(server.receive(&tampered_session, peer(1), clock()));
    assert!(
        matches!(error, Error::IdentityUnknown),
        "篡改会话 id 必须拒绝，实际 {error:?}"
    );

    // 篡改 separate header 的 packet id 段 ⇒ **同样**是身份指纹失配。
    //
    // 原因：separate header 是**单个 AES-ECB 块**（参考
    // `shadowaead_2022/service_multi.go:274-275` 对 `aes.BlockSize` 整体解密），
    // 改动块内任一字节都会破坏整个块的解密结果；而身份指纹是
    // `decrypt(身份头) XOR decrypt(separate header)`
    // （参考 `service_multi.go:280-281` 的 `xorWords`）⇒ 指纹必然失配，
    // 在 AEAD 之前就被拒。参考侧报 `invalid request`
    // （`service_multi.go:288`），本仓报 `Error::IdentityUnknown`。
    let mut tampered_id = packet.clone();
    tampered_id[8] ^= 0x01;
    let error = expect_error(server.receive(&tampered_id, peer(1), clock()));
    assert!(
        matches!(error, Error::IdentityUnknown),
        "篡改 packet id 必须被拒（指纹先于 AEAD 失配），实际 {error:?}"
    );

    // 篡改 AEAD 密文 ⇒ 认证失败（参考 `service_multi.go:330-334` 同构）。
    let mut tampered_body = packet.clone();
    let last = tampered_body.len() - 1;
    tampered_body[last] ^= 0x01;
    let error = expect_error(server.receive(&tampered_body, peer(1), clock()));
    assert!(
        matches!(error, Error::Authentication),
        "篡改密文必须认证失败，实际 {error:?}"
    );

    // 截断到身份头中间 ⇒ 形状非法 ⇒ 拒绝。
    let truncated = &packet[..20];
    let error = expect_error(server.receive(truncated, peer(1), clock()));
    assert!(
        matches!(error, Error::EihTruncated),
        "截断包必须拒绝，实际 {error:?}"
    );

    // 陌生 PSK 伪造的整包（指纹不在用户表）⇒ 拒绝。
    let stranger = key(Method::Aes256, 0x99);
    let forged_chain = EihUdpChain::new(vec![psks[0].clone(), stranger]).expect("陌生链应可构造");
    let mut forged_sender = EihUdpSender::new(forged_chain).expect("发送端");
    let forged = forged_sender
        .seal(&target(), b"forged", now_secs(), 0)
        .expect("封包");
    let error = expect_error(server.receive(&forged, peer(1), clock()));
    assert!(
        matches!(error, Error::IdentityUnknown),
        "陌生指纹必须拒绝，实际 {error:?}"
    );

    // 错误与日志不得泄露 PSK / 载荷。
    let rendered = format!("{error} {error:?}");
    assert!(
        !rendered.contains("authentic"),
        "错误不得含载荷：{rendered}"
    );
    assert!(!rendered.contains("forged"), "错误不得含载荷：{rendered}");

    // 关键：被拒的报文**没有**占掉合法包 id 0 的窗口位 ⇒ 合法包仍被接受。
    let decoded = server
        .receive(&packet, peer(1), clock())
        .expect("被拒报文不得污染窗口，合法包应被接受");
    assert_eq!(decoded.payload, b"authentic".as_slice());
}
