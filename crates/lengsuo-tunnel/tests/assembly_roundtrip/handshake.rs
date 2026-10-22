// 握手主题：握手成功落地密钥、握手失败显式报错（不回退明文）。
//
// 本文件由入口 `assembly_roundtrip.rs` 用 `include!` **文本并入**同一模块，
// 故不写 `use`（入口已全部引入），用例名也不带模块前缀。

// ------------------------------------------------------- 1. 握手成功并落地

#[tokio::test]
async fn initiator_responder_handshake_completes() {
    let (initiator, responder, initiator_keys, responder_keys) = handshake_over_udp().await;

    assert!(initiator.is_established(), "发起方会话必须已建立");
    assert!(responder.is_established(), "响应方会话必须已建立");

    // 发起方的 keypair **真的**落进了 Device 的 current 槽位
    // （对照参考 `BeginSymmetricSession` 的 initiator 分支：新 keypair 直接上位）。
    let initiator_key = initiator
        .device()
        .keypairs()
        .current()
        .expect("发起方的 current keypair 必须存在（密钥已落地）");
    assert_eq!(initiator_key.local_index, initiator_keys.local_index);
    assert_eq!(initiator_key.remote_index, initiator_keys.remote_index);

    // 响应方的 keypair 落在 **next** 槽位（对照参考的 responder 分支：新 keypair
    // 先进 next，等第一个用它的数据报文确认后才晋升）⇒ 此刻 current 仍为空。
    // ⛔ 这不是「没落地」：它等的是**对端的第一个数据报文**来确认。
    assert!(
        responder.device().keypairs().current().is_none(),
        "响应方在收到首个数据报文前，current 槽位应当仍为空（keypair 在 next）"
    );

    // 两侧的 index 必须**互为镜像**（发起方 send 的 receiver == 响应方的 local）。
    assert_eq!(
        initiator_keys.remote_index, responder_keys.local_index,
        "发起方写入的对端 index 必须等于响应方的本端 index"
    );
    assert_eq!(
        responder_keys.remote_index, initiator_keys.local_index,
        "响应方写入的对端 index 必须等于发起方的本端 index"
    );
    // 收发密钥必须**互为镜像**（发起方 send == 响应方 receive，反之亦然）。
    assert_eq!(
        initiator_keys.send, responder_keys.receive,
        "发起方发送密钥必须等于响应方接收密钥"
    );
    assert_eq!(
        initiator_keys.receive, responder_keys.send,
        "发起方接收密钥必须等于响应方发送密钥"
    );
}

// ------------------------------------------- 2. 握手失败显式报错（不回退明文）

#[tokio::test]
async fn handshake_failure_is_reported() {
    // ⛔ 用一个**从未握手成功**的装配层：失败之后它必须**仍然**未就绪。
    let mut initiator = Assembly::new(initiator_config()).expect("发起方装配层可建");
    let mut handshake = InitiatorHandshake::new(&initiator, SEED).expect("发起方握手上下文可建");
    handshake
        .create_initiation(SEED)
        .expect("initiation 可构造");

    // 一个**长度合法但 MAC1 全零**的 response ⇒ 认证必然失败。
    let mut broken = [0u8; 92];
    broken[..4].copy_from_slice(&2u32.to_le_bytes());
    broken[4..8].copy_from_slice(&RESPONDER_INDEX.to_le_bytes());
    broken[8..12].copy_from_slice(&handshake.local_index().to_le_bytes());

    let err = handshake
        .consume_response(&broken)
        .expect_err("被篡改的 response 必须被拒绝");
    match err {
        AssemblyError::HandshakeRejected { reason } => {
            assert!(
                !reason.is_empty(),
                "失败原因必须给出固定短语（不含报文内容）"
            );
            assert_eq!(reason, "响应报文认证失败", "失败原因必须可判定");
        }
        other => panic!("期望 HandshakeRejected，实际 {other:?}"),
    }

    // ⛔ **不回退明文**：会话**不得**因失败而变成「已建立」。
    assert!(
        !initiator.is_established(),
        "握手失败后不得把会话标成已建立（不回退明文）"
    );
    // 数据面必须**拒绝**收发（而不是放行明文）。
    let err = initiator
        .seal_frame(FrameType::Data, 1, b"plaintext-must-not-escape")
        .expect_err("会话未建立时必须拒绝封装");
    assert!(
        matches!(err, AssemblyError::SessionNotEstablished),
        "期望 SessionNotEstablished，实际 {err:?}"
    );
    let err = initiator
        .receive_frame(
            "203.0.113.5:1234".parse().expect("测试地址可解析"),
            Frame::new(FrameType::Data, 1, vec![0u8; 32]),
        )
        .expect_err("会话未建立时必须拒绝收包");
    assert!(
        matches!(err, AssemblyError::SessionNotEstablished),
        "期望 SessionNotEstablished，实际 {err:?}"
    );
}
