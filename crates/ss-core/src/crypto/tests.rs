//! `crypto` 模块的单元测试（自 `crypto.rs` 内联 `mod tests` 原样搬出）。
//!
//! 用例全限定名保持 `crypto::tests::*` 不变；正文逐字未改，仅去掉一层缩进。

use super::*;

#[test]
fn nonce_starts_at_zero_then_increments() {
    // Xray GenerateIncreasingNonce: c[i]++; if c[i]!=0 break —— FF+1=00 继续进位
    // 全 FF 起始 → 首次调用回绕为全 0，第二次为 [01,00×11]（little-endian 递增）
    let mut n = NonceCounter::new(12);
    assert_eq!(n.next().unwrap(), &[0u8; 12]);
    assert_eq!(n.next().unwrap(), &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut n2 = NonceCounter::new(1);
    assert_eq!(n2.next().unwrap(), &[0]);
    assert_eq!(n2.next().unwrap(), &[1]);
    // byte0 从 FF 走满一轮后进位到 byte1
    let mut n3 = NonceCounter::new(2);
    n3.next().unwrap(); // 全 0
    for _ in 0..255 {
        n3.next().unwrap(); // [1,0] ... [FF,0]
    }
    assert_eq!(n3.next().unwrap(), &[0, 1]); // byte0 FF→00 进位，byte1 00→01
    assert_eq!(n3.next().unwrap(), &[1, 1]);
}

#[test]
fn capacity_matches_each_suites_nonce_space() {
    // 上限 = 2^(8*nonce_len)，与套件表一致；XChaCha 的 2^192 饱和于 u128。
    assert_eq!(NonceCounter::capacity(0), 0);
    assert_eq!(NonceCounter::capacity(1), 256);
    assert_eq!(NonceCounter::capacity(2), 65536);
    for suite in [
        CipherSuite::Aes128Gcm,
        CipherSuite::Aes256Gcm,
        CipherSuite::ChaCha20IetfPoly1305,
    ] {
        assert_eq!(NonceCounter::capacity(suite.nonce_len()), 1u128 << 96);
    }
    assert_eq!(
        NonceCounter::capacity(CipherSuite::XChaCha20IetfPoly1305.nonce_len()),
        u128::MAX
    );
}

#[test]
fn one_byte_counter_uses_every_nonce_exactly_once_then_refuses() {
    // 穷举最小计数空间：capacity(1)=256 个 nonce 逐个取用且互不重复，
    // 第 257 步必须拒绝（此处正是 Xray 侧静默回绕复用全 0 的位置）。
    let mut counter = NonceCounter::new(1);
    let mut seen = [false; 256];
    for _ in 0..256 {
        let nonce = counter.next().expect("前 256 个 nonce 全部合法");
        assert_eq!(nonce.len(), 1);
        let value = nonce[0] as usize;
        assert!(
            !seen[value],
            "nonce {value:02x} 被重复取用：必须 fail-closed 而不是回绕"
        );
        seen[value] = true;
        assert!(!counter.is_exhausted());
    }
    assert!(seen.iter().all(|used| *used), "计数空间必须被完整覆盖");
    assert!(
        matches!(counter.next(), Err(Error::NonceExhausted)),
        "取尽后必须返回 NonceExhausted"
    );
    assert!(counter.is_exhausted());
}

#[test]
fn last_legal_nonce_succeeds_next_step_is_rejected() {
    // 12 字节真实长度：放到倒数第二个位置，确认"恰好最后一个合法 nonce"成功。
    let mut counter = NonceCounter::at_value(&[
        0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ]);
    assert_eq!(
        counter.next().unwrap(),
        &[0xFF; 12],
        "全 FF 是最后一个合法 nonce"
    );
    assert!(!counter.is_exhausted(), "尚未取尽时不得提前报错");
    assert!(
        matches!(counter.next(), Err(Error::NonceExhausted)),
        "再下一步就是复用首个 nonce，必须拒绝"
    );
    assert!(counter.is_exhausted());
}

#[test]
fn exhausted_counter_stays_exhausted_and_never_resumes() {
    // 取尽是不可逆状态：反复取用继续报同一个错，永不恢复、不 panic，
    // 且内部值绝不落到"全 0"那种可与首个 nonce 重复的形态。
    let mut counter = NonceCounter::at_value(&[0xFD, 0xFF]);
    assert_eq!(counter.next().unwrap(), &[0xFE, 0xFF]);
    assert_eq!(counter.next().unwrap(), &[0xFF, 0xFF], "最后一个合法 nonce");
    for attempt in 0..8 {
        assert!(
            matches!(counter.next(), Err(Error::NonceExhausted)),
            "第 {attempt} 次重试仍必须拒绝"
        );
        assert!(counter.is_exhausted());
        assert_eq!(counter.counter, vec![0xFF, 0xFF], "拒绝步不得改动内部值");
    }
}

#[test]
fn first_wrap_from_all_ff_is_the_zero_nonce_not_exhaustion() {
    // 唯一允许整串进位的一步是首步：全 FF → 全 0 是第一个合法 nonce，
    // 若把它误判为取尽会破坏与 Xray 的线格式互通（回归防护）。
    let mut counter = NonceCounter::new(2);
    assert_eq!(counter.next().unwrap(), &[0x00, 0x00]);
    assert!(!counter.is_exhausted());
    assert_eq!(counter.next().unwrap(), &[0x01, 0x00]);
}

#[test]
fn zero_length_nonce_is_exhausted_from_the_start() {
    // nonce_len = 0 没有任何可用 nonce 形态：构造即取尽，取用一律报错。
    let mut counter = NonceCounter::new(0);
    assert!(counter.is_exhausted());
    assert!(
        matches!(counter.next(), Err(Error::NonceExhausted)),
        "零长度 nonce 不得返回空切片当作可用 nonce"
    );
    assert_eq!(NonceCounter::capacity(0), 0);
}

#[test]
fn seal_reports_exhaustion_then_poisons_the_session() {
    // 恰好最后一个合法 nonce 的 seal 成功；再 seal 一次报 NonceExhausted，
    // 且对象永久 poison（继续报错，不会"跳过这一步"后恢复）。
    let subkey = vec![0xA5u8; 16];
    let mut seed = [0xFFu8; 12];
    seed[0] = 0xFE;
    let mut a = session_at_nonce(CipherSuite::Aes128Gcm, subkey, &seed);
    let last_ct = a.seal(b"last block").expect("最后一个合法 nonce 必须成功");
    assert!(!a.nonce_exhausted());
    assert!(matches!(
        a.seal(b"one block too many"),
        Err(Error::NonceExhausted)
    ));
    assert!(a.nonce_exhausted());
    for _ in 0..4 {
        assert!(matches!(a.seal(b"retry"), Err(Error::NonceExhausted)));
        assert!(matches!(a.open(&last_ct), Err(Error::NonceExhausted)));
    }
}

#[test]
fn open_reports_exhaustion_on_the_same_poisoned_state() {
    // 读侧同样 fail-closed：取尽后 open 报 NonceExhausted，而不是被误判成
    // AuthFailed（认证失败与密钥耗尽必须可区分，上层据此决定断连原因）。
    let subkey = vec![0x5Au8; 32];
    let mut seed = [0xFFu8; 12];
    seed[0] = 0xFE;
    let mut a = session_at_nonce(CipherSuite::Aes256Gcm, subkey, &seed);
    assert!(matches!(a.open(&[0u8; 16]), Err(Error::AuthFailed)));
    assert!(matches!(a.open(&[0u8; 16]), Err(Error::NonceExhausted)));
    assert!(a.nonce_exhausted());
    assert!(matches!(a.seal(b"x"), Err(Error::NonceExhausted)));
}

#[test]
fn exhaustion_error_message_holds_no_key_or_nonce_material() {
    // 错误文本必须是静态的：不含 subkey、nonce 字节、长度等任何可关联细节。
    let subkey = vec![0x42u8; 16];
    let mut seed = [0xFFu8; 12];
    seed[0] = 0xFE;
    let mut a = session_at_nonce(CipherSuite::Aes128Gcm, subkey.clone(), &seed);
    a.seal(b"x").unwrap();
    let rendered = a.seal(b"y").expect_err("必须报错").to_string();
    assert_eq!(
        rendered,
        "AEAD nonce space exhausted for this session key: refusing to reuse a nonce, rotate the key"
    );
    for byte in subkey.iter().chain(seed.iter()) {
        assert!(
            !rendered.contains(&format!("{byte:02x}")),
            "错误消息泄漏了字节 {byte:02x}"
        );
        assert!(!rendered.contains(&format!("{byte}")));
    }
    assert!(!rendered.contains('[') && !rendered.contains(']'));
    // Debug 形态同样不得带出密钥材料。
    let debugged = format!("{:?}", a.seal(b"z").err().unwrap());
    for byte in subkey.iter().chain(seed.iter()) {
        assert!(!debugged.contains(&format!("{byte:02x}")));
    }
}

#[test]
fn suite_params_match_xray_table() {
    assert_eq!(CipherSuite::Aes128Gcm.key_len(), 16);
    assert_eq!(CipherSuite::Aes128Gcm.salt_len(), 16);
    assert_eq!(CipherSuite::Aes256Gcm.salt_len(), 32);
    assert_eq!(CipherSuite::ChaCha20IetfPoly1305.nonce_len(), 12);
    assert_eq!(CipherSuite::XChaCha20IetfPoly1305.nonce_len(), 24);
}

#[test]
fn seal_open_roundtrip_all_suites() {
    for suite in [
        CipherSuite::Aes128Gcm,
        CipherSuite::Aes256Gcm,
        CipherSuite::ChaCha20IetfPoly1305,
        CipherSuite::XChaCha20IetfPoly1305,
    ] {
        let subkey = vec![7u8; suite.key_len()];
        let mut a = SessionAead::new(suite, subkey.clone());
        let mut b = SessionAead::new(suite, subkey);
        let pt = b"hello shadowsocks";
        let ct = a.seal(pt).unwrap();
        assert_eq!(ct.len(), pt.len() + 16);
        assert_eq!(b.open(&ct).unwrap(), pt);
    }
}

#[test]
fn tampered_ct_fails_closed() {
    let subkey = vec![9u8; 16];
    let mut a = SessionAead::new(CipherSuite::Aes128Gcm, subkey.clone());
    let mut b = SessionAead::new(CipherSuite::Aes128Gcm, subkey);
    let mut ct = a.seal(b"data").unwrap();
    ct[0] ^= 0xFF;
    assert!(b.open(&ct).is_err());
}
