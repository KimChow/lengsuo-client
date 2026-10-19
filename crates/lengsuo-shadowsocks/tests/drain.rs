//! 行为探测缓解（`drain`）与分块 padding（`padding`）的集成测试。
//!
//! 两个方向都要证明：
//! 1. **限量丢弃与抵扣**：预算对齐参考 `16+38/3266/64`，salt 读满后按
//!    `AcknowledgeReceive` 抵扣，正常客户端不被惩罚；
//! 2. **不得成为密码预言机**：`Reader::with_drainer` 挂上后，错误口令与正确口令
//!    在**可观测的 drain 预算**上完全一致（同一部署 seed ⇒ 同一预算）。
//!
//! 口令是测试专用假凭据；这些用例只覆盖本实现的缓解逻辑，**不宣称与参考二进制
//! 实跑互通**（互通状态见 `docs/shadowsocks-status.md`）。

use std::time::Duration;

use lengsuo_shadowsocks::{
    dechunk_padded, decode_flags, encode_padded, BehaviorSeedLimitedDrainer, BehaviorSeedSource,
    CipherSuite, PaddingError, PaddingPolicy, TcpReader, TcpWriter, DRAIN_FOUNDATION,
    MAX_PADDING_LEN,
};
use tokio::io::{duplex, AsyncWriteExt};
use tokio::time::timeout;

const PASSWORD: &[u8] = b"drain-test-passw0rd";
const WRONG_PASSWORD: &[u8] = b"wrong-passw0rd";
const SUITE: CipherSuite = CipherSuite::Aes256Gcm;
const WAIT: Duration = Duration::from_secs(2);

/// 把若干段封成一条完整的线上字节流（salt + chunk）。
async fn seal(segments: &[&[u8]]) -> Vec<u8> {
    let mut wire: Vec<u8> = Vec::new();
    {
        let mut writer =
            TcpWriter::new(&mut wire, SUITE, PASSWORD, WAIT).expect("测试套件应可构造写端");
        for segment in segments {
            timeout(WAIT, writer.send(segment))
                .await
                .expect("send 未被外层超时")
                .expect("写出应成功");
        }
        timeout(WAIT, writer.shutdown())
            .await
            .expect("shutdown 未被外层超时")
            .expect("写半关闭应成功");
    }
    wire
}

#[test]
fn drain_budget_is_seeded_and_bounded_like_the_reference() {
    // 参考：NewBehaviorSeedLimitedDrainer(seed, 16+38, 3266, 64)。
    for seed in [1i64, 42, 1234567890123, 0x7fff_ffff_ffff_ffff] {
        let d = BehaviorSeedLimitedDrainer::new_shadowsocks(seed);
        assert!(
            d.drain_size >= DRAIN_FOUNDATION as i64,
            "seed {seed} 低于参考下限"
        );
        assert!(
            d.drain_size < (DRAIN_FOUNDATION + 3266 + 64) as i64,
            "seed {seed} 超出参考上限"
        );
    }
}

#[test]
fn seed_is_derived_from_the_key_not_the_password() {
    // 「非密码预言机」的静态断言：seed 由**配置期的 key** 推导
    // （Add → hmac_sha256("SSBSKDF", key) → crc64 ECMA），与连接上送来的口令无关。
    // 因此同一部署内所有连接（含错误口令）得到同一个 seed。
    let a = BehaviorSeedSource::from_key(PASSWORD);
    let b = BehaviorSeedSource::from_key(PASSWORD);
    assert_eq!(a, b, "同 key 必得同 seed");
    assert_ne!(a, 0);
    assert_ne!(
        a,
        BehaviorSeedSource::from_key(WRONG_PASSWORD),
        "不同部署 key 应给出不同 seed（否则等于没种）"
    );

    // 预算本身还含一次全局 roll（参考如此），所以逐次构造不保证等值；
    // 但下限 16+38 是硬下界，且不同口令不改变 seed，从而不改变预算分布。
    let d = BehaviorSeedLimitedDrainer::new_shadowsocks(a as i64);
    assert!(d.drain_size >= DRAIN_FOUNDATION as i64);
}

#[test]
fn seed_source_latches_from_the_key() {
    // Validator.Add 折入 key，GetBehaviorSeed 首次取用时闩锁；后续取值稳定，
    // 因此同一次部署内所有连接共享同一 seed（否则就成了预言机）。
    let mut src = BehaviorSeedSource::new();
    src.add_key(PASSWORD);
    let first = src.get_behavior_seed_i64();
    assert_ne!(first, 0);
    assert!(src.is_fused());
    for _ in 0..8 {
        assert_eq!(src.get_behavior_seed_i64(), first);
    }
    // 闩锁后折入新 key 不再改变 seed（参考的 `if !v.behaviorFused`）。
    src.add_key(b"late-key");
    assert_eq!(src.get_behavior_seed_i64(), first);
}

#[tokio::test]
async fn correct_password_credits_the_salt_against_the_budget() {
    // 正常客户端：salt 读满即按 AcknowledgeReceive(salt_len) 抵扣，
    // 抵扣后预算必须严格小于未抵扣时的预算。
    let wire = seal(&[b"GET / HTTP/1.1\r\n\r\n"]).await;

    let reader = TcpReader::new(&wire[..], SUITE, PASSWORD, WAIT).expect("测试套件应可构造读端");
    assert_eq!(reader.drain_budget(), None, "默认不挂 drainer");

    let mut reader = TcpReader::new(&wire[..], SUITE, PASSWORD, WAIT)
        .expect("测试套件应可构造读端")
        .with_drainer_seed(7);
    let before = reader.drain_budget().expect("已挂 drainer");
    let chunk = timeout(WAIT, reader.recv())
        .await
        .expect("recv 未被外层超时")
        .expect("正常口令应读取成功");
    assert!(chunk.is_some());
    let after = reader.drain_budget().expect("已挂 drainer");
    assert!(
        after < before,
        "salt 抵扣后预算应变小：before={before} after={after}"
    );
    assert_eq!(
        before - after,
        reader.salt_len() as i64,
        "抵扣量应等于一次 salt 长度"
    );
}

#[tokio::test]
async fn read_budget_never_grows_and_stays_finite() {
    // fail-closed 边界：预算只能被抵扣（单调不增），且始终是个有限值，
    // 不会因认证失败而无限堆积。
    let wire = seal(&[b"short"]).await;
    let mut reader = TcpReader::new(&wire[..], SUITE, PASSWORD, WAIT)
        .expect("测试套件应可构造读端")
        .with_drainer_seed(99);
    let mut last = reader.drain_budget().expect("已挂 drainer");
    assert!(last.abs() < 1 << 20, "预算必须落在参考量级内，不得无界堆积");
    for _ in 0..3 {
        let _ = timeout(WAIT, reader.recv()).await;
        let now = reader.drain_budget().expect("已挂 drainer");
        assert!(now <= last, "预算不得增长：{last} -> {now}");
        assert!(now.abs() < 1 << 20, "预算必须保持有限量级");
        last = now;
    }
}

#[tokio::test]
async fn drain_cost_is_identical_for_every_wrong_password() {
    // 「非密码预言机」的端到端断言：缓解措施的**代价**不随口令变化。
    //
    // 语义澄清（对齐参考 Drain/WithError）：成功握手只抵扣已认证前缀（salt），
    // 失败握手还要把剩余预算整段读掉——所以「成功 vs 失败」本来就可区分，这正是
    // 参考的设计：探测者付出代价，真实客户端不必付。可区分性必须被限制在
    // 「失败 vs 成功」，绝不能细到「这个错误口令 vs 那个错误口令」。
    let wire = seal(&[b"payload bytes"]).await;

    let cost = |password: &'static [u8]| {
        let wire = &wire;
        async move {
            let mut reader = TcpReader::new(&wire[..], SUITE, password, WAIT)
                .expect("测试套件应可构造读端")
                .with_drainer_seed(12345);
            let start = reader.drain_budget().expect("已挂 drainer");
            let outcome = timeout(WAIT, reader.recv())
                .await
                .expect("recv 未被外层超时");
            let end = reader.drain_budget().expect("已挂 drainer");
            (outcome.is_err(), start - end)
        }
    };

    // 两把不同的错误口令：都失败，且抵扣量（即读掉多少字节）必须完全一致。
    let (failed_a, cost_a) = cost(b"wrong-passw0rd").await;
    let (failed_b, cost_b) = cost(b"another-bad-one!").await;
    assert!(failed_a && failed_b, "两把错误口令都必须失败");
    assert_eq!(
        cost_a, cost_b,
        "不同错误口令的 drain 代价必须相同，否则就是密码预言机"
    );

    // 正确口令只抵扣 salt，不触发整段丢弃 ⇒ 代价严格小于失败路径。
    let (failed_ok, cost_ok) = cost(PASSWORD).await;
    assert!(!failed_ok, "正确口令必须成功");
    assert!(
        cost_ok < cost_a,
        "成功路径不得付出丢弃代价：ok={cost_ok} bad={cost_a}"
    );
}

#[tokio::test]
async fn handshake_failure_is_reported_not_silently_passed_through() {
    // 网络失败不得静默直连/静默成功：错误口令必须报错且方向永久失效。
    let wire = seal(&[b"payload"]).await;
    let mut reader = TcpReader::new(&wire[..], SUITE, WRONG_PASSWORD, WAIT)
        .expect("测试套件应可构造读端")
        .with_drainer_seed(1);
    let first = timeout(WAIT, reader.recv())
        .await
        .expect("recv 未被外层超时");
    assert!(first.is_err(), "错误口令必须报错");
    let second = timeout(WAIT, reader.recv())
        .await
        .expect("recv 未被外层超时");
    assert!(second.is_err(), "失败后不得复活");
}

#[tokio::test]
async fn drainer_does_not_disturb_the_byte_stream() {
    // 挂了 drainer 的读端在正常口令下必须交付与未挂时逐字节相同的明文。
    let payload = b"the exact same bytes must come out";
    let wire = seal(&[payload]).await;

    let mut plain = TcpReader::new(&wire[..], SUITE, PASSWORD, WAIT).expect("读端");
    let expected = timeout(WAIT, plain.recv())
        .await
        .expect("recv")
        .expect("ok")
        .expect("有数据");

    let mut hooked = TcpReader::new(&wire[..], SUITE, PASSWORD, WAIT)
        .expect("读端")
        .with_drainer_seed(3);
    let got = timeout(WAIT, hooked.recv())
        .await
        .expect("recv")
        .expect("ok")
        .expect("有数据");
    assert_eq!(got, expected);
    assert_eq!(got, payload);
}

#[tokio::test]
async fn drainer_hook_does_not_break_duplex_roundtrip() {
    // 只加钩子、不改 tcp 逻辑：双工往返仍成立。
    let (client, server) = duplex(64 * 1024);
    let (mut server_read, mut server_write) = tokio::io::split(server);
    let (mut client_read, mut client_write) = tokio::io::split(client);

    let server_task = tokio::spawn(async move {
        let mut writer = TcpWriter::new(&mut server_write, SUITE, PASSWORD, WAIT).unwrap();
        timeout(WAIT, writer.send(b"pong")).await.unwrap().unwrap();
        timeout(WAIT, writer.shutdown()).await.unwrap().unwrap();
        let mut reader = TcpReader::new(&mut server_read, SUITE, PASSWORD, WAIT)
            .unwrap()
            .with_drainer_seed(5);
        timeout(WAIT, reader.recv()).await.unwrap().unwrap()
    });

    let mut writer = TcpWriter::new(&mut client_write, SUITE, PASSWORD, WAIT).unwrap();
    timeout(WAIT, writer.send(b"ping")).await.unwrap().unwrap();
    timeout(WAIT, writer.shutdown()).await.unwrap().unwrap();

    let mut reader = TcpReader::new(&mut client_read, SUITE, PASSWORD, WAIT).unwrap();
    let pong = timeout(WAIT, reader.recv()).await.unwrap().unwrap();
    assert_eq!(pong.as_deref(), Some(&b"pong"[..]));

    let ping = server_task.await.unwrap();
    assert_eq!(ping.as_deref(), Some(&b"ping"[..]));

    client_write.shutdown().await.ok();
}

// ---- padding ----

#[test]
fn padding_is_bounded_by_the_flags_nibble() {
    assert_eq!(MAX_PADDING_LEN, 15, "高半字节只能表达 0..=15");
}

#[test]
fn padding_roundtrip_holds_for_every_boundary_length() {
    for pad in 0..=MAX_PADDING_LEN {
        for len in [1usize, 2, 15, 16, 255, 4096] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut policy = PaddingPolicy::Fixed(pad);
            let (wire, flags) = encode_padded(&payload, &mut policy, 0x07).unwrap();
            assert_eq!(flags & 0x0F, 0x07, "低半字节必须保留");
            let got = dechunk_padded(&wire, decode_flags(flags)).unwrap();
            assert_eq!(got, payload, "pad={pad} len={len}");
        }
    }
}

#[test]
fn padding_rejects_malformed_frames_fail_closed() {
    // 声明长度超过缓冲区 ⇒ 截断；超过半字节 ⇒ 越界；纯 padding ⇒ 空载荷。
    assert!(matches!(
        dechunk_padded(&[0u8; 2], 9),
        Err(PaddingError::Truncated { .. })
    ));
    assert!(matches!(
        dechunk_padded(&[0u8; 64], 16),
        Err(PaddingError::LengthOutOfRange(16))
    ));
    assert!(matches!(
        dechunk_padded(&[0u8; 6], 6),
        Err(PaddingError::EmptyPayload)
    ));
}

#[test]
fn padding_length_is_never_constant_when_rolled() {
    // 逐字节边界之外还要证明策略真的会变化；恒 0 的策略等于没做 padding。
    let mut policy = PaddingPolicy::with_seed(2024);
    let rolls: Vec<usize> = (0..32).map(|_| policy.roll()).collect();
    assert!(rolls.iter().any(|&r| r > 0));
    assert!(rolls.iter().all(|&r| r <= MAX_PADDING_LEN));
}
