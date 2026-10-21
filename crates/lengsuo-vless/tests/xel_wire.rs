//! XEL 记录层出站原语（`lengsuo_vless::xel_wire`）的具名用例。
//!
//! 本文件验证的是**接线正确、没改语义**，三条主线：
//!
//! 1. **正常往返**：既有原语 → 新 API → 还原 ⇒ 载荷逐字节一致。
//! 2. **错误输入 fail-closed**：非法参数/截断输入 ⇒ 显式报错，不静默产出垃圾。
//! 3. **与既有实现的等价性**：新 API 的输出与既有原语的输出**逐字节相同**。
//!
//! 关键证据是第 3 条：新 API 只是**编排**（分块、方向分离、掩蔽层顺序），
//! 加密/分帧全部委托给 `crate::xel` 的既有原语。等价性用例直接拿
//! `crate::xel::record::RecordWriter` / `RecordReader` / `crate::xel::xor::XorMask`
//! 的输出与新 API 的输出对拍——任何「复制了第二份实现」的行为都会让对拍失败。
//!
//! **不声称与 Xray 进程级互通**：Xray v26.3.27（`d2758a0`）的 XEL 只能作为
//! `mlkem768x25519plus.*` 握手的一部分上线，记录层密钥由握手派生，配置里没有
//! 「注入会话密钥 / 只开记录层」的入口。既有 `tests/xel_golden.rs` 已用参考端
//! 实跑产出的黄金字节证明**记录层本身**与参考逐字节一致；本文件在此之上证明
//! **新 API 与既有原语**逐字节一致。两者串起来即：本 API 未改变记录层语义。
//!
//! **组合形态（AEAD ⊕ XOR 同时开启）的金标对齐**见子模块
//! [`reference_golden`]：既有金标只分别锁定两层，没有锁定「两层同时开启」时
//! 参考产出的线上字节——而那正是生产配置（参考 `XorMode == 2`）的形态。

/// 组合形态（AEAD 记录层 ⊕ XOR 头部掩蔽）的参考金标字节对拍。
#[path = "xel_wire/reference_golden.rs"]
mod reference_golden;

/// 参考二进制侧的互通边界取证（`#[ignore]`，须显式 `--ignored` 实跑）。
#[path = "xel_wire/reference_binary.rs"]
mod reference_binary;

use std::time::Duration;

use lengsuo_vless::xel::{
    aead::XelCipher,
    record::{RecordReader, RecordWriter},
    xor::XorMask,
    Error as XelError, XelKey,
};
use lengsuo_vless::xel_wire::{
    Error as WireError, XelReceiver, XelSender, XelStream, XelWireConfig, XorLayer,
    MAX_PLAINTEXT_PER_RECORD, XOR_IV_LEN,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

/// 上行 AEAD 记录密钥（假密钥）。
fn uplink_key() -> XelKey {
    XelKey::new(&[0xA1; 32]).unwrap()
}

/// 下行 AEAD 记录密钥（假密钥）。
fn downlink_key() -> XelKey {
    XelKey::new(&[0xB2; 32]).unwrap()
}

/// 错钥（假密钥，用于 fail-closed 用例）。
fn wrong_key() -> XelKey {
    XelKey::new(&[0x99; 32]).unwrap()
}

/// XOR 掩蔽层的上下行 IV。
const IV_UP: [u8; XOR_IV_LEN] = [0x11; XOR_IV_LEN];
const IV_DOWN: [u8; XOR_IV_LEN] = [0x22; XOR_IV_LEN];

/// 载荷序列：覆盖空、单字节、跨记录边界与多记录。
fn payloads() -> Vec<Vec<u8>> {
    vec![
        b"first xel wire payload".to_vec(),
        vec![0x00],
        vec![0xEE; 400],
        b"tail record \xff\x00\x80".to_vec(),
    ]
}

/// 构造一对方向（发送端 / 接收端）。
///
/// **同进程回环**：发送端用 `uplink_key`，接收端必须用**同一把** `uplink_key`
/// 解密（对端发来的就是上行方向的记录）。XOR 掩蔽层同理：接收端的 `recv_key`/
/// `recv_iv` 必须与发送端的 `send_key`/`send_iv` **完全一致**（参考 `xor.go` 的
/// `NewXorConn(conn, ctr, peerCTR, ...)`：对端的发送流就是本端的接收流，
/// 掩蔽与去掩蔽必须用同一条密钥流）。
fn pair(cipher: XelCipher, xor: bool) -> (XelSender, XelReceiver) {
    let xor_layer = if xor {
        Some(XorLayer::new(uplink_key(), &IV_UP, uplink_key(), &IV_UP).expect("IV 长度合法"))
    } else {
        None
    };
    let config = XelWireConfig {
        cipher,
        uplink_key: uplink_key(),
        downlink_key: uplink_key(),
        xor: xor_layer,
    };
    config.split().expect("配置合法")
}

// ---------------------------------------------------------------------------
// 一、正常往返
// ---------------------------------------------------------------------------

/// 正常往返：既有原语封出的线上字节 → 新 API 还原 ⇒ 载荷逐字节一致。
#[test]
fn roundtrip_via_new_api_restores_payload_byte_for_byte() {
    for cipher in [XelCipher::Aes256Gcm, XelCipher::ChaCha20Poly1305] {
        for xor in [false, true] {
            let (mut sender, mut receiver) = pair(cipher, xor);
            for payload in payloads() {
                let wire = sender.seal(&payload).expect("封包成功");
                let plain = receiver.open(&wire).expect("解包成功");
                assert_eq!(plain, payload, "{cipher:?} xor={xor}：载荷必须逐字节还原");
            }
            receiver.finish().expect("流必须恰好结束");
        }
    }
}

/// 正常往返（流式）：线上字节任意切分喂入 ⇒ 载荷逐字节一致、顺序不变。
#[test]
fn roundtrip_survives_arbitrary_wire_chunking() {
    for step in [1usize, 2, 3, 5, 7, 22, 64, 512] {
        // 分块与一次性各用独立实例：接收方向有状态（序号锁定步）。
        let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, true);
        let mut wire = Vec::new();
        for payload in payloads() {
            wire.extend_from_slice(&sender.seal(&payload).unwrap());
        }
        let mut got: Vec<u8> = Vec::new();
        for chunk in wire.chunks(step) {
            got.extend_from_slice(&receiver.open(chunk).expect("解包成功"));
        }
        receiver.finish().expect("流必须恰好结束");
        let want: Vec<u8> = payloads().concat();
        assert_eq!(got, want, "分块步长 {step}：载荷必须逐字节一致");
    }
}

/// 空载荷不产出线上字节（参考 `common.go:49` 的 `if len(b) == 0 { return 0, nil }`）。
#[test]
fn empty_payload_produces_no_wire_bytes() {
    let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, false);
    assert!(sender.seal(b"").unwrap().is_empty());
    assert!(receiver.open(b"").unwrap().is_empty());
    receiver.finish().expect("空流必须恰好结束");
}

// ---------------------------------------------------------------------------
// 三、与既有实现的等价性（硬证据：没有复制第二份实现）
// ---------------------------------------------------------------------------

/// 等价性：AEAD 模式下，新 API 的线上字节与既有 `RecordWriter` 逐字节相同。
#[test]
fn new_api_matches_existing_record_writer_byte_for_byte() {
    for cipher in [XelCipher::Aes256Gcm, XelCipher::ChaCha20Poly1305] {
        let (mut sender, _) = pair(cipher, false);
        // 既有原语：同一把密钥、同一套件，逐条封。
        let mut legacy = RecordWriter::new(cipher, uplink_key());
        for payload in payloads() {
            let ours = sender.seal(&payload).expect("封包成功");
            let theirs = legacy.seal(&payload).expect("既有原语封包成功");
            assert_eq!(
                ours, theirs,
                "{cipher:?}：新 API 的线上字节必须与既有原语逐字节相同"
            );
        }
    }
}

/// 等价性：AEAD 模式下，新 API 解出的明文与既有 `RecordReader` 逐字节相同。
#[test]
fn new_api_matches_existing_record_reader_byte_for_byte() {
    for cipher in [XelCipher::Aes256Gcm, XelCipher::ChaCha20Poly1305] {
        // 用既有原语封流。
        let mut legacy = RecordWriter::new(cipher, uplink_key());
        let mut wire = Vec::new();
        for payload in payloads() {
            wire.extend_from_slice(&legacy.seal(&payload).unwrap());
        }
        // 新 API 还原。
        let (_, mut receiver) = pair(cipher, false);
        assert_eq!(
            receiver.open(&wire).expect("解包成功"),
            payloads().concat(),
            "{cipher:?}：新 API 必须逐字节还原既有原语产出的流"
        );
        // 既有原语还原同一流 ⇒ 与新 API 结果逐字节相同。
        let mut legacy_reader = RecordReader::new(cipher, uplink_key());
        legacy_reader.push(&wire).unwrap();
        let mut legacy_plain = Vec::new();
        while let Some(chunk) = legacy_reader.next_plaintext().unwrap() {
            legacy_plain.extend_from_slice(&chunk);
        }
        legacy_reader.finish().unwrap();
        let (_, mut receiver2) = pair(cipher, false);
        assert_eq!(
            receiver2.open(&wire).unwrap(),
            legacy_plain,
            "{cipher:?}：新 API 与既有原语的还原结果必须逐字节相同"
        );
    }
}

/// 等价性：XOR 模式下，新 API 的线上字节与既有 `XorMask` + `RecordWriter` 逐字节相同。
#[test]
fn new_api_matches_existing_xor_mask_byte_for_byte() {
    let (mut sender, _) = pair(XelCipher::Aes256Gcm, true);
    // 既有原语：先 AEAD 封记录，再掩蔽 5 字节头（参考的层序）。
    let mut legacy_writer = RecordWriter::new(XelCipher::Aes256Gcm, uplink_key());
    let mut legacy_mask = XorMask::new(&uplink_key(), &IV_UP, &uplink_key(), &IV_UP).unwrap();
    for payload in payloads() {
        let mut theirs = legacy_writer.seal(&payload).unwrap();
        legacy_mask.mask_outgoing(&mut theirs).unwrap();
        let ours = sender.seal(&payload).expect("封包成功");
        assert_eq!(
            ours, theirs,
            "XOR 模式：新 API 的线上字节必须与既有原语逐字节相同"
        );
    }
}

/// 等价性：XOR 模式下，新 API 还原的明文与既有 `XorMask` + `RecordReader` 逐字节相同。
#[test]
fn new_api_matches_existing_xor_reader_byte_for_byte() {
    let mut legacy_writer = RecordWriter::new(XelCipher::Aes256Gcm, uplink_key());
    let mut legacy_mask = XorMask::new(&uplink_key(), &IV_UP, &uplink_key(), &IV_UP).unwrap();
    let mut wire = Vec::new();
    for payload in payloads() {
        let mut record = legacy_writer.seal(&payload).unwrap();
        legacy_mask.mask_outgoing(&mut record).unwrap();
        wire.extend_from_slice(&record);
    }
    // 既有原语还原。
    let mut legacy_reader = RecordReader::new(XelCipher::Aes256Gcm, uplink_key());
    let mut legacy_plain = Vec::new();
    for chunk in wire.chunks(7) {
        let mut unmasked = chunk.to_vec();
        legacy_mask.unmask_incoming(&mut unmasked).unwrap();
        legacy_reader.push(&unmasked).unwrap();
        while let Some(plain) = legacy_reader.next_plaintext().unwrap() {
            legacy_plain.extend_from_slice(&plain);
        }
    }
    legacy_reader.finish().unwrap();
    // 新 API 还原同一流。
    let (_, mut receiver) = pair(XelCipher::Aes256Gcm, true);
    assert_eq!(
        receiver.open(&wire).expect("解包成功"),
        legacy_plain,
        "XOR 模式：新 API 与既有原语的还原结果必须逐字节相同"
    );
}

/// 等价性：分块上限与参考一致——超长明文被切成 8192 字节的记录。
///
/// 参考 `common.go:53` `CommonConn.Write`：`if len(b) > 8192 { b = b[:8192] }`。
#[test]
fn long_payload_is_chunked_at_reference_8192_boundary() {
    let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, false);
    let payload = vec![0x5A; MAX_PLAINTEXT_PER_RECORD * 2 + 17];
    let wire = sender.seal(&payload).expect("封包成功");
    // 三条记录：8192 + 8192 + 17 字节明文，每条加 16 字节 tag。
    let expected = 3 * (5 + 16) + payload.len();
    assert_eq!(wire.len(), expected, "记录条数必须与参考分块一致");
    assert_eq!(receiver.open(&wire).unwrap(), payload, "载荷必须逐字节还原");
    receiver.finish().unwrap();
}

// ---------------------------------------------------------------------------
// 二、错误输入 fail-closed
// ---------------------------------------------------------------------------

/// 非法参数：IV 长度不对 ⇒ 显式报错，不静默降级。
#[test]
fn invalid_iv_length_is_rejected_explicitly() {
    for iv in [
        &[0u8; XOR_IV_LEN - 1][..],
        &[0u8; XOR_IV_LEN + 1][..],
        &[][..],
    ] {
        let outcome = XorLayer::new(uplink_key(), iv, downlink_key(), &IV_DOWN);
        assert!(
            matches!(
                outcome,
                Err(WireError::Record(XelError::InvalidIvLength { got, want }))
                    if got == iv.len() && want == XOR_IV_LEN
            ),
            "IV 长度 {} 必须被显式拒绝，实际 {:?}",
            iv.len(),
            outcome.err()
        );
    }
    // 下行 IV 同样受检。
    assert!(matches!(
        XorLayer::new(uplink_key(), &IV_UP, downlink_key(), &[0u8; 3]),
        Err(WireError::Record(XelError::InvalidIvLength { .. }))
    ));
}

/// 非法参数：AEAD 密钥长度不对 ⇒ 在构造 `XelKey` 时即被拒绝。
#[test]
fn invalid_key_length_is_rejected_explicitly() {
    for bytes in [&[0u8; 31][..], &[0u8; 33][..], &[][..]] {
        assert!(
            matches!(
                XelKey::new(bytes),
                Err(XelError::InvalidKeyLength { got, want })
                    if got == bytes.len() && want == 32
            ),
            "密钥长度 {} 必须被显式拒绝",
            bytes.len()
        );
    }
}

/// 错误密钥 ⇒ 显式认证失败，且方向被 poison（后续调用返回 `Poisoned`）。
#[test]
fn wrong_key_fails_closed_and_poisons() {
    let (mut sender, _) = pair(XelCipher::Aes256Gcm, false);
    let wire = sender.seal(b"secret xel wire payload").unwrap();
    // 用错钥构造接收端。
    let config = XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: wrong_key(),
        downlink_key: wrong_key(),
        xor: None,
    };
    let (_, mut receiver) = config.split().unwrap();
    assert!(
        matches!(
            receiver.open(&wire),
            Err(WireError::Record(XelError::AuthFailed))
        ),
        "错钥必须显式认证失败"
    );
    assert!(receiver.is_poisoned(), "认证失败后方向必须 poison");
    // 后续调用一律 `Poisoned`，绝不产出明文。
    assert!(matches!(
        receiver.open(&wire),
        Err(WireError::Record(XelError::Poisoned))
    ));
    // 帧器本身未被污染（污染的是 AEAD 方向），但方向已 poison ⇒ `finish`
    // 之后的任何读取都必须被拒绝。
    assert!(matches!(
        receiver.finish(),
        Ok(()) | Err(WireError::Record(XelError::Poisoned))
    ));
    assert!(matches!(
        receiver.open(&wire),
        Err(WireError::Record(XelError::Poisoned))
    ));
}

/// 截断输入：残字节 ⇒ 显式 `Truncated`，不静默丢弃。
#[test]
fn truncated_stream_is_reported_not_swallowed() {
    let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, false);
    let wire = sender
        .seal(b"a xel wire payload long enough to truncate")
        .unwrap();
    receiver
        .open(&wire[..wire.len() - 3])
        .expect("不足一帧属于正常等待");
    assert!(
        matches!(
            receiver.finish(),
            Err(WireError::Record(XelError::Truncated { .. }))
        ),
        "残字节必须显式报截断"
    );
    assert!(receiver.is_poisoned(), "截断后方向必须 poison");
}

/// 非法头部：魔数被改 ⇒ 显式 `InvalidHeader`，不静默产出垃圾。
#[test]
fn invalid_magic_is_rejected_explicitly() {
    let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, false);
    let mut wire = sender.seal(b"payload bytes here").unwrap();
    wire[0] ^= 0x01; // 破坏魔数
    assert!(
        matches!(
            receiver.open(&wire),
            Err(WireError::Record(XelError::InvalidHeader))
        ),
        "魔数不符必须显式报错"
    );
    assert!(receiver.is_poisoned(), "头部非法后方向必须 poison");
}

/// 长度越界：长度前缀不可信 ⇒ 显式 `InvalidRecordLength`，不静默攒字节。
#[test]
fn unsane_length_prefix_is_rejected_explicitly() {
    let (_, mut receiver) = pair(XelCipher::Aes256Gcm, false);
    // 魔数合法但 BE16 = 65535 > 16640（参考 `common.go:216` 的上界）。
    let outcome = receiver.open(&[23, 3, 3, 0xFF, 0xFF]);
    assert!(
        matches!(
            outcome,
            Err(WireError::Record(XelError::InvalidRecordLength { .. }))
        ),
        "长度前缀越界必须显式报错"
    );
    assert!(receiver.is_poisoned());
}

/// XOR 模式下头部被篡改 ⇒ 显式报错（掩蔽层 poison），不静默产出垃圾。
#[test]
fn xor_tampered_header_fails_closed() {
    let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, true);
    let mut wire = sender.seal(b"payload for xor tamper check").unwrap();
    wire[0] ^= 0x01; // 掩蔽后的头部被篡改
    let outcome = receiver.open(&wire);
    assert!(
        matches!(
            outcome,
            Err(WireError::Record(
                XelError::InvalidHeader | XelError::InvalidRecordLength { .. }
            ))
        ),
        "XOR 头部被篡改必须显式报错，实际 {:?}",
        outcome.err()
    );
    assert!(receiver.is_poisoned());
}

// ---------------------------------------------------------------------------
// 出站原语（`XelStream`）：真实回环 TCP
// ---------------------------------------------------------------------------

/// 出站原语：真实回环 TCP 上双向字节流逐字节还原。
#[tokio::test]
async fn xel_stream_roundtrips_over_loopback_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定回环");
    let address = listener.local_addr().expect("本端地址");
    let server = tokio::spawn(async move {
        let (transport, _) = listener.accept().await.expect("接受连接");
        // 服务端方向与客户端对调：服务端的发送 = 客户端的接收。
        let config = XelWireConfig {
            cipher: XelCipher::Aes256Gcm,
            uplink_key: downlink_key(),
            downlink_key: uplink_key(),
            xor: Some(
                XorLayer::new(downlink_key(), &IV_DOWN, uplink_key(), &IV_UP).expect("IV 合法"),
            ),
        };
        let mut stream = XelStream::new(transport, config).expect("构造出站原语");
        let mut buffer = vec![0u8; 4096];
        let read = stream.read(&mut buffer).await.expect("服务端读");
        // 回声：把读到的原样写回。
        stream.write_all(&buffer[..read]).await.expect("服务端写");
        stream.shutdown().await.expect("服务端关写");
        stream.close().await.expect("服务端收尾")
    });

    let transport = tokio::net::TcpStream::connect(address)
        .await
        .expect("连接回环");
    let config = XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: uplink_key(),
        downlink_key: downlink_key(),
        xor: Some(XorLayer::new(uplink_key(), &IV_UP, downlink_key(), &IV_DOWN).expect("IV 合法")),
    };
    let mut stream = XelStream::new(transport, config).expect("构造出站原语");
    let message = b"xel wire over real loopback tcp";
    stream.write_all(message).await.expect("客户端写");
    let mut buffer = vec![0u8; 4096];
    let read = timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("读不得超时")
        .expect("客户端读");
    assert_eq!(&buffer[..read], message, "回环载荷必须逐字节一致");
    stream.shutdown().await.expect("客户端关写");
    stream.close().await.expect("客户端收尾");
    server.await.expect("服务端任务不得 panic");
}

/// 出站原语：错钥时客户端读到的必须是失败，不是垃圾数据。
#[tokio::test]
async fn xel_stream_with_wrong_key_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定回环");
    let address = listener.local_addr().expect("本端地址");
    let server = tokio::spawn(async move {
        let (transport, _) = listener.accept().await.expect("接受连接");
        // 服务端用**错钥**发送 ⇒ 客户端的接收方向必然认证失败。
        let config = XelWireConfig {
            cipher: XelCipher::Aes256Gcm,
            uplink_key: wrong_key(),
            downlink_key: uplink_key(),
            xor: None,
        };
        let mut stream = XelStream::new(transport, config).expect("构造出站原语");
        // 不等客户端数据，直接发一条 ⇒ 客户端立刻撞上认证失败。
        let _ = stream
            .write_all(b"payload sealed under the wrong key")
            .await;
        let _ = stream.shutdown().await;
        let _ = stream.close().await;
    });

    let transport = tokio::net::TcpStream::connect(address)
        .await
        .expect("连接回环");
    let config = XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: uplink_key(),
        downlink_key: downlink_key(),
        xor: None,
    };
    let mut stream = XelStream::new(transport, config).expect("构造出站原语");
    let mut buffer = vec![0u8; 4096];
    let outcome = timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("错钥下读必须快速失败，而不是等到超时");
    // 读到的必须是「没有明文」：要么报错，要么 EOF，绝不产出垃圾。
    match outcome {
        Ok(0) => {}
        Ok(n) => panic!("错钥下不得产出明文，实际读出 {n} 字节"),
        Err(_) => {}
    }
    // 收尾必须报出读取方向的失败（fail-closed 的可见出口），且必须**快速**返回
    // （关掉写半后对端立刻看到 EOF，不靠超时兜底）。
    let closed = timeout(Duration::from_secs(5), stream.close())
        .await
        .expect("close 不得靠超时兜底");
    assert!(closed.is_err(), "错钥下 close 必须报出读取方向的失败");
    let _ = server.await;
}

/// 出站原语：`close()` 在对端关闭后必须成功返回（无残字节）。
#[tokio::test]
async fn xel_stream_close_succeeds_on_clean_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定回环");
    let address = listener.local_addr().expect("本端地址");
    let server = tokio::spawn(async move {
        let (mut transport, _) = listener.accept().await.expect("接受连接");
        // 服务端只封一条记录然后关闭（用客户端的下行密钥 ⇒ 客户端能解）。
        let mut writer = RecordWriter::new(XelCipher::Aes256Gcm, downlink_key());
        let record = writer.seal(b"goodbye").unwrap();
        transport.write_all(&record).await.expect("服务端写");
        transport.shutdown().await.expect("服务端关写");
    });

    let transport = tokio::net::TcpStream::connect(address)
        .await
        .expect("连接回环");
    let config = XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: uplink_key(),
        downlink_key: downlink_key(),
        xor: None,
    };
    let mut stream = XelStream::new(transport, config).expect("构造出站原语");
    let mut buffer = vec![0u8; 4096];
    let read = timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("读不得超时")
        .expect("客户端读");
    assert_eq!(&buffer[..read], b"goodbye", "载荷必须逐字节一致");
    // 对端已关写 ⇒ 再读一次必须得到 EOF，而不是挂死。
    let eof = timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("EOF 不得挂死")
        .expect("EOF 读取");
    assert_eq!(eof, 0, "对端关闭后必须读到 EOF");
    stream.shutdown().await.expect("客户端关写");
    stream.close().await.expect("干净 EOF 下 close 必须成功");
    server.await.expect("服务端任务不得 panic");
}

/// 出站原语：读方向的失败必须在**读操作本身**报出，不能只藏在 `close()` 里。
///
/// 回归用例（fail-open 缺陷）：读任务失败时会把失败原因放进失败槽并关闭管道
/// 写端。管道只能表达 EOF ⇒ 若读操作不把失败槽里的原因报出来，应用侧读到的是
/// 一个**干净的 EOF**，「认证失败的流」被误读成「对端正常结束」（静默降级）。
/// 只调用 `read()` 不调用 `close()` 的调用方（流式读取、只读一次载荷）根本不会
/// 发现异常。
///
/// 判据：错钥下 `read()` 必须返回**错误**（`Err`），不得返回 `Ok(0)`（干净 EOF）。
#[tokio::test]
async fn xel_stream_read_surfaces_read_direction_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定回环");
    let address = listener.local_addr().expect("本端地址");
    let server = tokio::spawn(async move {
        let (transport, _) = listener.accept().await.expect("接受连接");
        // 服务端用**错钥**发送 ⇒ 客户端的接收方向必然认证失败。
        let config = XelWireConfig {
            cipher: XelCipher::Aes256Gcm,
            uplink_key: wrong_key(),
            downlink_key: uplink_key(),
            xor: None,
        };
        let mut stream = XelStream::new(transport, config).expect("构造出站原语");
        let _ = stream
            .write_all(b"payload sealed under the wrong key")
            .await;
        let _ = stream.shutdown().await;
        let _ = stream.close().await;
    });

    let transport = tokio::net::TcpStream::connect(address)
        .await
        .expect("连接回环");
    let config = XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: uplink_key(),
        downlink_key: downlink_key(),
        xor: None,
    };
    let mut stream = XelStream::new(transport, config).expect("构造出站原语");
    let mut buffer = vec![0u8; 4096];
    // 只调 `read()`，**不**调 `close()`：失败必须在这里就可见。
    let outcome = timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("错钥下读必须快速失败，而不是等到超时");
    assert!(
        outcome.is_err(),
        "读方向的认证失败必须在 read() 里报出（不得返回干净的 EOF）"
    );
    // 显式丢弃客户端流：关掉传输，服务端的 `close()` 才能立刻收尾（不靠超时兜底）。
    drop(stream);
    let _ = server.await;
}
