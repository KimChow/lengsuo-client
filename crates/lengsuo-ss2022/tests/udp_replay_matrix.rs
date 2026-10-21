//! SS2022 UDP（EIH 方向）重放矩阵：同进程 / 跨重启 / 窗口边界 / 篡改拒绝。
//!
//! # 参考事实（逐行核对过，勿凭推测）
//!
//! SS2022 的线上字节由 **sing-shadowsocks/shadowaead_2022** 生成，**不是** Xray
//! 自带的 `proxy/shadowsocks_2022/`（Xray 层只做账号/路由适配）。
//! 固定参考：Xray v26.3.27（`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//! → `github.com/sagernet/sing-shadowsocks v0.2.7`。
//!
//! | 事实 | 出处 |
//! |---|---|
//! | 滑动窗口是**纯内存**结构（`last uint64` + `ring [128]uint64`），**无任何落盘** | `shadowaead_2022/slidingwindow.go:13-16` |
//! | 窗口长度 `swSize = (swRingBlocks-1)*swBlockBits = 8128` | `shadowaead_2022/slidingwindow.go:3-9` |
//! | 服务端 UDP 收包：`Check` 不过即丢弃（`ErrPacketIdNotUnique`） | `shadowaead_2022/service_multi.go:324-327` |
//! | 服务端 UDP 收包：**AEAD 解密成功之后**才 `Add`（解密失败不占窗口） | `shadowaead_2022/service_multi.go:329-338` |
//! | 会话（连同窗口）存于**内存 LRU** `udpSessions` | `shadowaead_2022/service.go:57-58,77-80` |
//! | 客户端 UDP 收包同构（`Check` / `Add`） | `shadowaead_2022/protocol.go:589-592,639-657` |
//! | TCP salt 防重放也是内存态（`replay.NewSimple(60s)`，map + 超时清理） | `shadowaead_2022/service.go:53,75` + `sing@v0.5.1 common/replay/simple.go` |
//! | 时间戳窗口 ±30 秒 | `shadowaead_2022/service_multi.go:351-359` |
//!
//! ⇒ **参考没有任何跨进程重启的重放保护**：进程退出 ⇒ 窗口与会话表一并清零。
//! 本仓**默认路径（未挂接 `ReplayStore`）与之逐条一致**；挂接 `ReplayStore` 是
//! 本仓**可选的增强**（比参考更强），不是参考行为，详见 `docs/ss2022-replay.md`。
#![allow(dead_code)]

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    eih::{User, UserTable},
    eih_udp::{EihUdpChain, EihUdpSender, EihUdpServer},
    receiver::Clock,
    replay_store::ReplayStore,
    Error,
};
use serde_json::{json, Value};
use ss_core::{
    replay::{Window, WINDOW_BITS},
    target::TargetAddr,
};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{free_port, launch, WAIT};

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

/// 由显式字节构造 PSK（仅用于参考互通用例的固定假凭据）。
fn key_from(method: Method, psk: &[u8]) -> Key {
    Key::new(method, psk).expect("假 PSK 长度应匹配套件")
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

/// 一层身份链的 PSK：`[服务端身份, 最终用户]`（与参考服务端只剥一层等价）。
fn one_layer_psks(method: Method) -> Vec<Key> {
    vec![key(method, 0x11), key(method, 0x22)]
}

fn one_layer_users(method: Method) -> UserTable {
    UserTable::new(vec![User {
        uid: 2,
        key: key(method, 0x22),
    }])
    .expect("用户表应合法")
}

fn make_server(identity: Key, users: UserTable, layers: usize) -> EihUdpServer {
    EihUdpServer::new(identity, users, layers, 4, Duration::from_secs(60)).expect("服务端应可构造")
}

fn temp_path(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "lengsuo-ss2022-udp-replay-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    directory.join("replay.bin")
}

// ───────────────────────── ① 同进程内重放被拒 ─────────────────────────

/// ① 同一 EIH 报文用两次 ⇒ 第二次必须被拒（参考 `service_multi.go:324` 同构）。
///
/// 同时证明服务端不是「来者不拒」：换一个新包 id 仍应被接受。
#[test]
fn same_process_replay_of_the_same_eih_packet_is_rejected() {
    let psks = one_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("身份链应可构造");
    let mut sender = EihUdpSender::new(chain).expect("发送端应可构造");
    let first = sender
        .seal(&target(), b"first", now_secs(), 0)
        .expect("封包应成功");
    let second = sender
        .seal(&target(), b"second", now_secs(), 0)
        .expect("封包应成功");

    let mut server = make_server(psks[0].clone(), one_layer_users(Method::Aes256), 1);
    let decoded = server
        .receive(&first, peer(1), clock())
        .expect("首个包应被接受");
    assert_eq!(decoded.packet_id, 0);
    assert_eq!(decoded.payload, b"first".as_slice());

    // 同一报文再来一次 ⇒ 重放窗口必须拒绝。
    assert!(
        matches!(server.receive(&first, peer(1), clock()), Err(Error::Replay)),
        "同进程重放必须被拒"
    );
    // 新包 id 仍被接受（证明上面不是「一律拒绝」）。
    let decoded = server
        .receive(&second, peer(1), clock())
        .expect("新包 id 应被接受");
    assert_eq!(decoded.packet_id, 1);
    assert_eq!(decoded.payload, b"second".as_slice());
}

// ───────────────────── ② 跨「重启」重放（与参考一致） ─────────────────────

/// ② 跨「重启」重放：内存态窗口随实例一起清空 ⇒ **重放被接受**。
///
/// 这与参考**逐条一致**：参考的窗口是纯内存结构
/// （`shadowaead_2022/slidingwindow.go:13-16`），会话表是内存 LRU
/// （`shadowaead_2022/service.go:57-58,77-80`），进程退出即清零 ⇒ 重启后
/// 同一 EIH 可重放。参考侧另有实跑证据见本文件末尾的
/// `xray_reference_rejects_replay_in_process_but_accepts_it_after_restart`。
///
/// ⛔ 本用例断言的是**实际且符合参考**的行为（被接受），
/// **不是**「必须拒绝」；也不得据此声称「已实现跨重启重放保护」。
#[test]
fn cross_restart_replay_is_accepted_like_the_reference() {
    let psks = one_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("身份链应可构造");
    let mut sender = EihUdpSender::new(chain).expect("发送端应可构造");
    let packet = sender
        .seal(&target(), b"cross-restart", now_secs(), 0)
        .expect("封包应成功");

    {
        // 第一个实例：接受，内存窗口记下 (session id, packet id)。
        let mut server = make_server(psks[0].clone(), one_layer_users(Method::Aes256), 1);
        let decoded = server
            .receive(&packet, peer(1), clock())
            .expect("首个实例应接受");
        assert_eq!(decoded.packet_id, 0);
    }

    // 「重启」= 新建实例 ⇒ 内存态状态随之清空。
    let mut restarted = make_server(psks[0].clone(), one_layer_users(Method::Aes256), 1);
    let decoded = restarted
        .receive(&packet, peer(1), clock())
        .expect("重启后重放应被接受（与参考一致：参考窗口纯内存）");
    assert_eq!(decoded.payload, b"cross-restart".as_slice());
    assert_eq!(decoded.packet_id, 0, "packet id 未变");
    assert_eq!(decoded.session_id, sender.session_id(), "会话 id 未变");
}

/// ②b 本仓**可选**增强：挂接 `ReplayStore` 后跨重启重放被拒（比参考更强）。
///
/// 这是本仓自有的、可选的、默认关闭的能力；参考**没有**等价物。
#[test]
fn cross_restart_replay_is_rejected_when_the_store_is_attached() {
    let path = temp_path("store");
    let _ = std::fs::remove_file(&path);
    let psks = one_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("身份链应可构造");
    let mut sender = EihUdpSender::new(chain).expect("发送端应可构造");
    let packet = sender
        .seal(&target(), b"persisted", now_secs(), 0)
        .expect("封包应成功");

    {
        let store = ReplayStore::load(&path).expect("加载存储");
        let mut server = make_server(psks[0].clone(), one_layer_users(Method::Aes256), 1)
            .with_replay_store(store);
        server
            .receive(&packet, peer(1), clock())
            .expect("首次应接受");
        server.flush_replay().expect("落盘");
    }

    // 重启：从磁盘快照恢复 ⇒ 同一 (session, packet id) fail-closed 拒绝。
    let store = ReplayStore::load(&path).expect("重启后加载快照");
    let mut restarted =
        make_server(psks[0].clone(), one_layer_users(Method::Aes256), 1).with_replay_store(store);
    assert!(
        matches!(
            restarted.receive(&packet, peer(1), clock()),
            Err(Error::Replay)
        ),
        "挂接持久化集合后跨重启重放必须拒绝"
    );
    let _ = std::fs::remove_file(&path);
}

// ───────────────────────── ③ 窗口边界 ─────────────────────────

/// 参考 `shadowaead_2022/slidingwindow.go` 的**逐行 Rust 转写**（对照模型）。
///
/// 常量取自 `slidingwindow.go:3-9`：`swBlockBitLog=6`、`swBlockBits=64`、
/// `swRingBlocks=128`、`swSize=(swRingBlocks-1)*swBlockBits=8128`。
struct ReferenceWindow {
    last: u64,
    ring: [u64; 128],
}

/// 参考窗口长度：`(swRingBlocks - 1) * swBlockBits`。
const REFERENCE_WINDOW_SIZE: u64 = (128 - 1) * 64;

impl ReferenceWindow {
    fn new() -> Self {
        Self {
            last: 0,
            ring: [0; 128],
        }
    }

    /// `slidingwindow.go:25-37` 的 `Check`。
    fn check(&self, counter: u64) -> bool {
        if counter > self.last {
            return true;
        }
        if self.last - counter > REFERENCE_WINDOW_SIZE {
            return false;
        }
        let block = ((counter >> 6) & 127) as usize;
        let bit = counter & 63;
        self.ring[block] >> bit & 1 == 0
    }

    /// `slidingwindow.go:41-63` 的 `Add`。
    fn add(&mut self, counter: u64) {
        if counter > self.last {
            let mut last_block = self.last >> 6;
            let block = counter >> 6;
            let mut diff = (block - last_block) as usize;
            if diff > 128 {
                diff = 128;
            }
            for _ in 0..diff {
                last_block = (last_block + 1) & 127;
                self.ring[last_block as usize] = 0;
            }
            self.last = counter;
        }
        let block = ((counter >> 6) & 127) as usize;
        let bit = counter & 63;
        self.ring[block] |= 1 << bit;
    }

    /// 参考服务端「先 Check，AEAD 成功后才 Add」的组合
    /// （`service_multi.go:324` 与 `:338`）。
    fn accept(&mut self, counter: u64) -> bool {
        if !self.check(counter) {
            return false;
        }
        self.add(counter);
        true
    }
}

/// ③a 窗口边界：本仓窗口长度（8192）与参考（8128）不同，且**只在「从未见过
/// 的旧 id」上**分道扬镳；一切**重放**判定两边完全一致。
///
/// 分歧的精确定义：
/// - 本仓 `ss_core::replay::Window`：`highest - counter >= 8192` 才判过期；
/// - 参考：`last - counter > 8128` 即判过期。
///
/// 于是：
/// - 距最高点 8129..=8191 的**新** id，本仓接受、参考拒绝（窗口长 63 位）；
/// - 距最高点 ≥ 8192 的 id，两边都拒绝；
/// - **任何被收下过的 id（重放），两边都拒绝**（本仓记为 Duplicate/TooOld，
///   参考记为 `ErrPacketIdNotUnique`）——这是用户可见的重放语义，两边一致。
#[test]
fn window_diverges_from_the_reference_only_at_the_old_edge() {
    let mut reference = ReferenceWindow::new();
    let mut repo = Window::new(u64::MAX);
    let mut seen: BTreeSet<u64> = BTreeSet::new();

    // 判定并记录：谁接受、谁拒绝。
    let step = |counter: u64,
                reference: &mut ReferenceWindow,
                repo: &mut Window,
                seen: &mut BTreeSet<u64>| {
        let reference_ok = reference.accept(counter);
        let repo_ok = repo.accept_authenticated(counter).is_ok();
        if reference_ok {
            seen.insert(counter);
        }
        (reference_ok, repo_ok)
    };

    // 起点：id 0（空窗口首包），随后大跨度跳到 100000（把中间都变成「新旧边界」）。
    assert_eq!(step(0, &mut reference, &mut repo, &mut seen), (true, true));
    assert_eq!(
        step(100_000, &mut reference, &mut repo, &mut seen),
        (true, true)
    );

    // 边界扫描：距最高点 delta 的「新」id（100000-delta 从未收下过）。
    let mut divergent = Vec::new();
    for delta in [1u64, 8127, 8128, 8129, 8190, 8191, 8192, 8193] {
        let counter = 100_000 - delta;
        assert!(!seen.contains(&counter), "被测 id 必须是从未见过的新 id");
        let (reference_ok, repo_ok) = step(counter, &mut reference, &mut repo, &mut seen);
        if reference_ok != repo_ok {
            divergent.push((delta, reference_ok, repo_ok));
        }
    }
    assert_eq!(
        divergent,
        vec![
            (8129, false, true),
            (8190, false, true),
            (8191, false, true)
        ],
        "分歧只应出现在距最高点 8129..=8191 的新 id 上（本仓窗口 8192 vs 参考 8128）"
    );

    // 一切**重放**判定两边必须一致：被收下过的 id 再来一次，两边都拒绝。
    for replayed in [0u64, 100_000, 100_000 - 8128, 100_000 - 8129] {
        let reference_ok = reference.accept(replayed);
        let repo_ok = repo.accept_authenticated(replayed).is_ok();
        assert!(!reference_ok, "参考必须拒绝重放 {replayed}");
        assert!(!repo_ok, "本仓必须拒绝重放 {replayed}");
    }
    assert_eq!(WINDOW_BITS as u64, 8192, "本仓窗口位数");
    assert_eq!(REFERENCE_WINDOW_SIZE, 8128, "参考窗口长度");
}

/// ③b 端到端：窗口推进到把旧 EIH 挤出之后，**同一个旧包仍被拒绝**。
///
/// 与参考一致：参考 `Check` 对 `last - counter > 8128` 直接拒绝，
/// 本仓对 `highest - counter >= 8192` 判过期 ⇒ 两边都**不会**让旧包复活。
/// 参考「出窗后新 id 仍可用」是窗口语义本身（`Check` 对 `counter > last`
/// 直接放行），本仓同样放行。
#[test]
fn eih_udp_replay_stays_rejected_after_the_window_advanced() {
    let psks = one_layer_psks(Method::Aes256);
    let chain = EihUdpChain::new(psks.clone()).expect("身份链应可构造");
    let mut sender = EihUdpSender::new(chain).expect("发送端应可构造");
    let mut server = make_server(psks[0].clone(), one_layer_users(Method::Aes256), 1);

    // 首包：id 0。留一份副本，待窗口推进后重放。
    let oldest = sender
        .seal(&target(), b"oldest", now_secs(), 0)
        .expect("封包应成功");
    server
        .receive(&oldest, peer(1), clock())
        .expect("首包应被接受");

    // 把窗口推进到 8192+：此后 id 0 距最高点 ≥ 8192，已被挤出窗口。
    for _ in 0..8192 {
        let packet = sender
            .seal(&target(), b"filler", now_secs(), 0)
            .expect("封包应成功");
        server
            .receive(&packet, peer(1), clock())
            .expect("递增 id 应被接受");
    }
    // 此时最高 packet id = 8192。旧包 id 0 已出窗 ⇒ 仍必须被拒（两边一致）。
    assert!(
        matches!(
            server.receive(&oldest, peer(1), clock()),
            Err(Error::Replay)
        ),
        "出窗后的旧 EIH 仍必须被拒（与参考一致）"
    );
}

// ───────────────────── ④ 伪造 / 篡改 EIH 必须 fail-closed ─────────────────────

/// ④ 伪造 / 篡改 EIH 一律 fail-closed，且**不得污染**会话窗口。
///
/// 关键性质（与参考 `service_multi.go:329-338` 一致：AEAD 成功之后才 `Add`）：
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

    // 篡改 AEAD 密文 ⇒ 认证失败（参考 `service_multi.go:331-334` 同构）。
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

// ───────────── ⑤ 与真实参考（固定 Xray）交叉验证：跨重启不防重放 ─────────────

/// Xray 多用户 SS2022 入站配置：`password` 是服务端身份 PSK，
/// `clients[*].password` 是用户 PSK。
fn multi_user_config(port: u16, method: &str, identity: &[u8], users: &[(&str, &[u8])]) -> Value {
    let clients: Vec<Value> = users
        .iter()
        .map(|(email, psk)| json!({"email": email, "password": STANDARD.encode(psk)}))
        .collect();
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "shadowsocks",
            "settings": {
                "method": method,
                "password": STANDARD.encode(identity),
                "network": "tcp,udp",
                "clients": clients
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    })
}

/// 真实参考（固定 Xray v26.3.27 = sing-shadowsocks v0.2.7）取证：
/// - **同进程内**：同一个 EIH 报文第二次必须被参考丢弃（不转发）；
/// - **跨重启**：参考进程重启后，同一个 EIH 报文**被接受并转发**
///   ⇒ 证明参考**没有**跨重启的重放保护（窗口纯内存）。
///
/// 这是「参考行为」的一手证据，不是纯读代码推断。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_reference_rejects_replay_in_process_but_accepts_it_after_restart() {
    const OVERALL: Duration = Duration::from_secs(120);
    const NO_REPLY: Duration = Duration::from_secs(3);
    const BIND: &str = "127.0.0.1:0";
    const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

    tokio::time::timeout(OVERALL, async {
        let method = Method::Aes256;
        let identity_psk = vec![0xAA; 32];
        let user_psk = vec![0x11; 32];
        let identity = key_from(method, &identity_psk);
        let user = key_from(method, &user_psk);

        // 回环 echo：统计抵达次数，用于判定「参考是否转发」。
        let echo = tokio::net::UdpSocket::bind(BIND)
            .await
            .expect("echo 应可监听");
        let echo_port = echo.local_addr().expect("echo 有地址").port();
        let delivered = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&delivered);
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 16384];
            loop {
                let Ok((received, from)) = echo.recv_from(&mut buffer).await else {
                    break;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = echo.send_to(&buffer[..received], from).await;
            }
        });

        let port = free_port();
        let config = multi_user_config(
            port,
            "2022-blake3-aes-256-gcm",
            &identity_psk,
            &[("user1", &user_psk)],
        );
        let reference = launch(config.clone(), port).await;

        let socket = tokio::net::UdpSocket::bind(BIND).await.expect("回环可监听");
        socket
            .connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("应可连接参考");
        let chain = EihUdpChain::new(vec![identity.clone(), user.clone()]).expect("身份链");
        let mut sender = EihUdpSender::new(chain).expect("发送端");
        let payload = b"replay-probe";
        let sealed_at = now_secs();
        let packet = sender
            .seal(&TargetAddr::V4(LOOPBACK, echo_port), payload, sealed_at, 0)
            .expect("封包应成功");

        let mut buffer = [0u8; 16384];
        // ① 首次：参考必须接受并转发。
        socket.send(&packet).await.expect("应可发出");
        let received = tokio::time::timeout(WAIT, socket.recv(&mut buffer))
            .await
            .expect("首次必须收到回包（超时不算通过）")
            .expect("应可收到回包");
        let decoded = user
            .open_server(&buffer[..received], now_secs(), sender.session_id())
            .expect("响应方向应可解密");
        assert_eq!(decoded.payload, payload, "首次回程载荷必须逐字节一致");
        assert_eq!(
            delivered.load(Ordering::SeqCst),
            1,
            "首次必须恰好抵达 echo 一次"
        );

        // ② 同进程重放：参考必须丢弃（窗口 `slidingwindow.go` 拒绝）。
        socket.send(&packet).await.expect("应可发出");
        assert!(
            tokio::time::timeout(NO_REPLY, socket.recv(&mut buffer))
                .await
                .is_err(),
            "参考必须拒绝同进程重放（不应有回包）"
        );
        assert_eq!(delivered.load(Ordering::SeqCst), 1, "重放不得抵达 echo");

        // ③ 重启参考进程：内存态窗口清空 ⇒ 同一报文必须被接受并转发。
        drop(reference);
        let _restarted = launch(config, port).await;
        let elapsed = now_secs().saturating_sub(sealed_at);
        assert!(
            elapsed <= 30,
            "重放必须落在参考的时间戳窗口（±30s）内，实测 {elapsed}s"
        );
        socket.send(&packet).await.expect("应可发出");
        let received = tokio::time::timeout(WAIT, socket.recv(&mut buffer))
            .await
            .expect("重启后参考必须接受重放（内存态窗口已清空）")
            .expect("应可收到回包");
        let decoded = user
            .open_server(&buffer[..received], now_secs(), sender.session_id())
            .expect("响应方向应可解密");
        assert_eq!(decoded.payload, payload, "重启后回程载荷必须逐字节一致");
        assert_eq!(
            delivered.load(Ordering::SeqCst),
            2,
            "重启后重放必须抵达 echo（证明参考不防跨重启重放）"
        );

        echo_task.abort();
    })
    .await
    .expect("参考重放取证总超时");
}
