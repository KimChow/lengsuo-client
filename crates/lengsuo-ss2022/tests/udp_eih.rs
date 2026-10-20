//! SIP023 EIH 的 UDP 侧：多用户身份头编解码、拒绝路径与跨重启重放（纯 Rust）。
//!
//! 逐字节对齐固定参考 sing-shadowsocks v0.2.7
//! （`shadowaead_2022/protocol.go:468` `clientPacketConn.WritePacket` 与
//! `shadowaead_2022/service_multi.go:269` `MultiService.newPacket`）。
//!
//! 判据要点：
//! - 多用户 UDP：客户端用 2 层身份链发包，服务端命中**正确用户**，载荷逐字节一致；
//! - 身份头篡改 1 字节 ⇒ 服务端拒绝（fail-closed）；
//! - 未知指纹 ⇒ 服务端拒绝；
//! - 链长不匹配 ⇒ 服务端拒绝；
//! - ChaCha + 多用户 ⇒ 显式 `Error`（不 panic、不按 AES 处理）；
//! - 跨重启重放：写盘后新实例读回，同一 salt 重放仍被拒。
use lengsuo_ss2022::{
    crypto::{Key, Method},
    eih::{User, UserTable},
    eih_udp::{EihUdpChain, EihUdpSender, EihUdpServer},
    receiver::Clock,
    replay_store::ReplayStore,
    Error,
};
use ss_core::target::TargetAddr;
use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟应晚于纪元")
        .as_secs()
}

fn clock() -> Clock {
    Clock {
        unix_seconds: now_secs(),
        monotonic: Instant::now(),
    }
}

fn key(method: Method, byte: u8) -> Key {
    Key::new(method, &vec![byte; method.key_len()]).expect("假 PSK 长度应匹配套件")
}

fn peer(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn target() -> TargetAddr {
    TargetAddr::V4([127, 0, 0, 1], 53)
}

/// 生产类型刻意不实现 `Debug`（避免 PSK 进日志），因此不能用 `expect_err`。
fn expect_error<T>(result: Result<T, Error>) -> Error {
    match result {
        Ok(_) => panic!("该操作必须失败"),
        Err(error) => error,
    }
}

/// 两层身份链的 PSK：`[服务端身份, 中继, 最终用户]`。
fn two_layer_psks(method: Method) -> Vec<Key> {
    vec![key(method, 0x11), key(method, 0x22), key(method, 0x33)]
}

/// 与 `two_layer_psks` 对应的用户表：中继 uid=1，最终用户 uid=2。
fn two_layer_users(method: Method) -> UserTable {
    UserTable::new(vec![
        User {
            uid: 1,
            key: key(method, 0x22),
        },
        User {
            uid: 2,
            key: key(method, 0x33),
        },
    ])
    .expect("用户表应合法")
}

fn make_server(identity: Key, users: UserTable, layers: usize) -> EihUdpServer {
    EihUdpServer::new(identity, users, layers, 4, Duration::from_secs(60)).expect("服务端应可构造")
}

/// ① 多用户 UDP：2 层身份链 → 服务端命中正确用户，载荷逐字节一致。
#[test]
fn two_layer_chain_resolves_the_right_user_and_payload() {
    let psks = two_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("身份链应可构造");
    assert_eq!(chain.layers(), 2);
    let mut sender = EihUdpSender::new(chain).expect("发送端应可构造");
    let payload = b"udp-eih-multi-user-payload";
    let packet = sender
        .seal(&target(), payload, now_secs(), 0)
        .expect("封包应成功");

    let mut server = make_server(psks[0].clone(), two_layer_users(Method::Aes256), 2);
    let decoded = server
        .receive(&packet, peer(1), clock())
        .expect("服务端应接受合法多用户包");
    assert_eq!(decoded.payload, payload, "载荷必须逐字节一致");
    assert_eq!(decoded.uids, vec![1, 2], "两层应分别命中中继与最终用户");
    assert_eq!(decoded.uid, 2, "归属用户应为最终用户");
    assert_eq!(decoded.session_id, sender.session_id());
    assert_eq!(decoded.packet_id, 0);
    assert_eq!(decoded.target, target());
}

/// ①b 一层身份链（与参考服务端逐字节等价的层数）同样可用。
#[test]
fn single_layer_chain_matches_reference_layer_count() {
    let identity = key(Method::Aes128, 0x11);
    let user = key(Method::Aes128, 0x22);
    let users = UserTable::new(vec![User {
        uid: 7,
        key: user.clone(),
    }])
    .expect("用户表");
    let chain = EihUdpChain::new(vec![identity.clone(), user.clone()]).expect("身份链");
    assert_eq!(chain.layers(), 1);
    let mut sender = EihUdpSender::new(chain).expect("发送端");
    let payload = b"one-layer";
    let packet = sender
        .seal(&target(), payload, now_secs(), 0)
        .expect("封包");
    // 线上布局：separate header 16 + 身份头 16 + AEAD。
    assert_eq!(packet.len(), 16 + 16 + 1 + 8 + 2 + 7 + payload.len() + 16);

    let mut server = make_server(identity, users, 1);
    let decoded = server
        .receive(&packet, peer(1), clock())
        .expect("服务端应接受");
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.uids, vec![7]);
    assert_eq!(decoded.uid, 7);
}

/// ② 身份头篡改 1 字节 ⇒ 服务端拒绝（fail-closed）。
#[test]
fn tampered_identity_header_is_rejected() {
    let psks = two_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("身份链");
    let mut sender = EihUdpSender::new(chain).expect("发送端");
    let packet = sender
        .seal(&target(), b"payload", now_secs(), 0)
        .expect("封包");

    let mut server = make_server(psks[0].clone(), two_layer_users(Method::Aes256), 2);
    // 篡改第 1 层身份头的 1 字节。
    let mut tampered = packet.clone();
    tampered[16] ^= 0x01;
    assert!(
        server.receive(&tampered, peer(1), clock()).is_err(),
        "篡改身份头必须被拒绝"
    );
    // 篡改 separate header 也必须被拒绝。
    let mut tampered = packet.clone();
    tampered[0] ^= 0x01;
    assert!(server.receive(&tampered, peer(1), clock()).is_err());
    // 篡改 AEAD 密文同样被拒绝。
    let mut tampered = packet.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(server.receive(&tampered, peer(1), clock()).is_err());
    // 合法包仍然可解（证明上面的拒绝不是「全部拒绝」）。
    assert!(server.receive(&packet, peer(1), clock()).is_ok());
}

/// ③ 未知指纹 ⇒ 服务端拒绝。
#[test]
fn unknown_fingerprint_is_rejected() {
    let psks = two_layer_psks(Method::Aes256);
    // 客户端用不在用户表中的最终用户 PSK。
    let stranger = key(Method::Aes256, 0x99);
    let chain = EihUdpChain::new(vec![psks[0].clone(), psks[1].clone(), stranger]).expect("链");
    let mut sender = EihUdpSender::new(chain).expect("发送端");
    let packet = sender
        .seal(&target(), b"payload", now_secs(), 0)
        .expect("封包");
    let mut server = make_server(psks[0].clone(), two_layer_users(Method::Aes256), 2);
    assert!(matches!(
        server.receive(&packet, peer(1), clock()),
        Err(Error::IdentityUnknown)
    ));
}

/// ④ 链长不匹配 ⇒ 拒绝。
///
/// 服务端期望 1 层而客户端写 2 层（以及反向）都必须拒绝，不得「凑巧」解出。
#[test]
fn mismatched_chain_length_is_rejected() {
    let psks = two_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("链");
    let mut sender = EihUdpSender::new(chain).expect("发送端");
    let packet = sender
        .seal(&target(), b"payload", now_secs(), 0)
        .expect("封包");

    // 服务端期望 1 层，实际 2 层。
    let mut server = make_server(psks[0].clone(), two_layer_users(Method::Aes256), 1);
    let outcome = server.receive(&packet, peer(1), clock());
    assert!(
        matches!(outcome, Err(Error::EihChainMismatch)),
        "链长不匹配必须明确拒绝"
    );

    // 反向：服务端期望 2 层而客户端只写 1 层。
    let identity = psks[0].clone();
    let user = psks[2].clone();
    let one = EihUdpChain::new(vec![identity.clone(), user.clone()]).expect("链");
    let mut sender = EihUdpSender::new(one).expect("发送端");
    let short = sender
        .seal(&target(), b"payload", now_secs(), 0)
        .expect("封包");
    let mut server = make_server(psks[0].clone(), two_layer_users(Method::Aes256), 2);
    assert!(matches!(
        server.receive(&short, peer(1), clock()),
        Err(Error::EihChainMismatch)
    ));
}

/// ⑤ ChaCha + 多用户 ⇒ 显式 `Error`（不得 panic、不得静默按 AES 处理）。
#[test]
fn chacha_multi_user_is_fail_closed() {
    let identity = key(Method::ChaCha20, 0x11);
    let user = key(Method::ChaCha20, 0x22);
    let error = expect_error(EihUdpChain::new(vec![identity.clone(), user.clone()]));
    assert!(
        matches!(error, Error::Unsupported),
        "ChaCha 多用户应报 Unsupported，实际 {error:?}"
    );
    // 错误里不得含 PSK、指纹或密文。
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("11"), "错误不得含 PSK 字节：{rendered}");
    assert!(!rendered.contains("22"), "错误不得含 PSK 字节：{rendered}");

    // 单个 PSK 的 ChaCha 链也不合法（UDP 身份头至少要 2 个 PSK）。
    assert!(matches!(
        expect_error(EihUdpChain::new(vec![identity])),
        Error::EihMissing
    ));
}

/// ⑥ 跨重启重放：写盘 → 新实例读回 ⇒ 同一 salt 重放被拒。
#[test]
fn replay_is_rejected_across_restart_with_multi_user_udp() {
    let path = std::env::temp_dir().join(format!(
        "lengsuo-ss2022-udp-eih-replay-{}.bin",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let psks = two_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("链");
    let mut sender = EihUdpSender::new(chain).expect("发送端");
    let packet = sender
        .seal(&target(), b"replay-me", now_secs(), 0)
        .expect("封包");

    {
        let store = ReplayStore::load(&path).expect("加载存储");
        let mut server = make_server(psks[0].clone(), two_layer_users(Method::Aes256), 2)
            .with_replay_store(store);
        server
            .receive(&packet, peer(1), clock())
            .expect("首次应接受");
        // 同进程内的重复包也必须被重放窗口拒绝。
        assert!(matches!(
            server.receive(&packet, peer(1), clock()),
            Err(Error::Replay)
        ));
        server.flush_replay().expect("落盘");
    }

    // 模拟重启：新服务端实例 + 从同一路径加载的 store。
    let store = ReplayStore::load(&path).expect("重启后加载快照");
    let mut restarted =
        make_server(psks[0].clone(), two_layer_users(Method::Aes256), 2).with_replay_store(store);
    assert!(
        matches!(
            restarted.receive(&packet, peer(1), clock()),
            Err(Error::Replay)
        ),
        "重启后同一 salt 的重放必须被拒"
    );
    let _ = std::fs::remove_file(&path);
}

const CHILD_ENV: &str = "LENGSUO_UDP_EIH_REPLAY_CHILD";
const PATH_ENV: &str = "LENGSUO_UDP_EIH_REPLAY_PATH";

/// 子进程入口：加载（或新建）快照，接受一个固定 `(session, packet id)`，落盘后退出。
///
/// 只有在 `CHILD_ENV` 存在时才执行，正常测试运行不会命中。
#[test]
fn child_process_writes_replay_snapshot() {
    if std::env::var(CHILD_ENV).is_err() {
        return;
    }
    let path = std::env::var(PATH_ENV).expect("子进程必须收到快照路径");
    let mut store = ReplayStore::load(path).expect("加载快照");
    assert!(store.accept([0x5A; 8], 41), "子进程首次应接受");
    store.flush().expect("落盘");
    std::process::exit(0);
}

/// 父进程：用**真正的第二个进程**写快照，再在本进程加载并判定重放。
///
/// 判据：子进程退出码必须为 0 且快照存在；本进程加载后同一
/// `(session_id, packet_id)` 必须 fail-closed 拒绝，递增的新 id 仍然接受。
#[test]
fn replay_survives_a_real_process_restart() {
    let path = std::env::temp_dir().join(format!(
        "lengsuo-ss2022-udp-eih-proc-{}.bin",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let executable = std::env::current_exe().expect("应能取到测试二进制路径");
    let status = std::process::Command::new(&executable)
        .args([
            "child_process_writes_replay_snapshot",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .env(PATH_ENV, &path)
        .status()
        .expect("子进程应可启动");
    assert!(status.success(), "子进程应成功写入快照");
    assert!(path.exists(), "子进程应落盘快照");

    // 本进程（新实例）加载同一快照：已见 packet id 必须拒绝。
    let mut store = ReplayStore::load(&path).expect("重启后加载快照");
    assert!(store.contains([0x5A; 8], 41), "重启后应加载到已见 id");
    assert!(
        !store.accept([0x5A; 8], 41),
        "跨进程重启后同一 (session, packet id) 必须 fail-closed 拒绝"
    );
    for id in 42..46 {
        assert!(store.accept([0x5A; 8], id), "递增 id {id} 应接受");
    }
    let _ = std::fs::remove_file(&path);
}

/// 身份头层数上限与空链的策略拒绝。
#[test]
fn chain_length_policy_is_enforced() {
    // 超过上限的链在构造期拒绝。
    let mut psks = vec![key(Method::Aes128, 0x01)];
    for index in 0..=lengsuo_ss2022::eih_udp::MAX_UDP_IDENTITY_LAYERS {
        psks.push(key(Method::Aes128, (index + 2) as u8));
    }
    assert!(matches!(
        expect_error(EihUdpChain::new(psks)),
        Error::EihChainTooLong
    ));
    // 单个 PSK 不足以构成身份链。
    assert!(matches!(
        expect_error(EihUdpChain::new(vec![key(Method::Aes128, 0x22)])),
        Error::EihMissing
    ));
    // 服务端层数 0 非法。
    let users = UserTable::new(vec![User {
        uid: 1,
        key: key(Method::Aes128, 0x22),
    }])
    .expect("用户表");
    assert!(matches!(
        expect_error(EihUdpServer::new(
            key(Method::Aes128, 0x11),
            users,
            0,
            4,
            Duration::from_secs(60)
        )),
        Error::EihMissing
    ));
}

/// 截断的身份头必须 fail-closed，而不是回退到单用户 PSK。
#[test]
fn truncated_packet_is_rejected() {
    let psks = two_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("链");
    let mut sender = EihUdpSender::new(chain).expect("发送端");
    let packet = sender
        .seal(&target(), b"payload", now_secs(), 0)
        .expect("封包");
    let mut server = make_server(psks[0].clone(), two_layer_users(Method::Aes256), 2);
    // 截断到不足一个身份头。
    assert!(server.receive(&packet[..20], peer(1), clock()).is_err());
    // 空包。
    assert!(server.receive(&[], peer(1), clock()).is_err());
}
