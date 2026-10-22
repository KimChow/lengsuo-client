// ③ 保密性：密钥/明文不得出现在 Debug 或错误信息里；封解封在超时内收敛。
#[test]
fn key_and_plaintext_never_reach_debug_or_errors() {
    let secret = b"INNER-IP-PACKET-MUST-NOT-BE-LOGGED";
    let packet = sender().seal(secret).expect("seal");
    let mut wrong = Receiver::new(
        TransportKey::new(&KEY_B).expect("假密钥 B"),
        RECEIVER_ID,
        DEFAULT_MAX_COUNTER,
    );
    let open_error = wrong.open(&packet).expect_err("错误密钥");
    let mut long_sender = sender();
    long_sender.seal(&payload(MAX_PAYLOAD_LEN)).expect("ok");
    let too_long = long_sender
        .seal(&payload(MAX_PAYLOAD_LEN + 1))
        .expect_err("超限");
    let key_error = TransportKey::new(&[0xC3; 16]).expect_err("密钥长度不对");
    let wrap = {
        let mut exhausted = Sender::new(key_a(), RECEIVER_ID, u64::MAX);
        exhausted.seal(secret).expect("MAX 封包");
        exhausted.seal(secret).expect_err("用尽")
    };

    let mut rendered = Vec::new();
    // 所有错误路径的 Display 与 Debug。
    for error in [open_error, too_long, key_error, wrap] {
        rendered.push(format!("{error}"));
        rendered.push(format!("{error:?}"));
    }
    // 所有面向日志的结构体 Debug。
    let decrypted: Decrypted = Receiver::new(key_a(), RECEIVER_ID, DEFAULT_MAX_COUNTER)
        .open(&packet)
        .expect("解封");
    rendered.push(format!("{decrypted:?}"));
    rendered.push(format!("{:?}", key_a()));
    rendered.push(format!("{:?}", TransportKey::new(&KEY_B).expect("key b")));
    rendered.push(format!("{:?}", sender()));
    rendered.push(format!("{:?}", receiver()));
    rendered.push(format!(
        "{:?}",
        Decrypted {
            counter: 1,
            receiver: RECEIVER_ID,
            plaintext: secret.to_vec(),
        }
    ));

    let leaks = leak_forms(&KEY_A)
        .into_iter()
        .chain(leak_forms(&KEY_B))
        .chain(leak_forms(&[0xC3; 16]))
        .collect::<Vec<_>>();
    for text in &rendered {
        for leak in &leaks {
            assert!(!text.contains(leak.as_str()), "密钥泄漏到日志：{text}");
        }
        assert!(!text.contains("INNER-IP-PACKET"), "明文泄漏：{text}");
        assert!(
            !text.contains(&format!("{:?}", secret.as_slice())),
            "明文字节泄漏：{text}"
        );
    }
    // 明文长度可以出现，但不得带出内容。
    assert!(rendered
        .iter()
        .any(|text| text.contains("plaintext_len") || text.contains("Decrypted")));
    assert_eq!(key_len(), 32);
}
/// 同步测试用 `tokio::time::timeout` 兜住，防止未来接入异步 I/O 时挂死无人察觉。
#[tokio::test]
async fn seal_open_under_timeout_stays_bounded() {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(|| {
            let mut sender = sender();
            let mut open = receiver();
            let mut checked = 0usize;
            for index in 0..64u64 {
                let packet = sender.seal(&payload(8 + index as usize)).expect("seal");
                let decrypted = open.open(&packet).expect("open");
                assert_eq!(decrypted.counter, index);
                assert_eq!(decrypted.plaintext, payload(8 + index as usize));
                checked += 1;
            }
            checked
        }),
    )
    .await
    .expect("timeout 内完成");
    assert_eq!(result.expect("worker 未 panic"), 64);
}
