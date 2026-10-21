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
//! | 服务端 UDP 收包：**AEAD 解密成功之后**才 `Add`（解密失败不占窗口） | `shadowaead_2022/service_multi.go:330-338` |
//! | 会话（连同窗口）存于**内存 LRU** `udpSessions` | `shadowaead_2022/service.go:55,77-80` |
//! | 客户端 UDP 收包同构（`Check` / `Add`） | `shadowaead_2022/protocol.go:589,639,657` |
//! | TCP salt 防重放也是内存态（`replay.NewSimple(60s)`，map + 超时清理） | `shadowaead_2022/service.go:53,75` + `sing@v0.5.1 common/replay/simple.go` |
//! | 时间戳窗口 ±30 秒 | `shadowaead_2022/service_multi.go:357-358` |
//!
//! ⇒ **参考没有任何跨进程重启的重放保护**：进程退出 ⇒ 窗口与会话表一并清零。
//! 本仓**默认路径（未挂接 `ReplayStore`）与之逐条一致**；挂接 `ReplayStore` 是
//! 本仓**可选的增强**（比参考更强），不是参考行为，详见 `docs/ss2022-replay.md`。
//!
//! # 用例分组（按职责拆到子模块，每个文件都在 400 行软目标内）
//!
//! | 位置 | 用例 | 职责 |
//! |---|---|---|
//! | 本文件 | ① 同进程重放被拒、② 跨「重启」重放（默认路径）、②b 挂 `ReplayStore` | 重放判定的基线行为 |
//! | `udp_replay_matrix/window_edge.rs` | ③a 窗口边界对照模型、③b 窗口推进后旧 EIH 仍被拒 | 窗口长度与出窗语义 |
//! | `udp_replay_matrix/tamper.rs` | ④ 篡改/伪造/截断 fail-closed 且不污染窗口 | 认证失败路径 |
//! | `udp_replay_matrix/reference_interop.rs` | ⑤ 真实固定参考一手证据（`#[ignore]`） | 参考互通 |
//!
//! 裸 `mod window_edge;` 会去找 `tests/window_edge.rs`，故用 `#[path]` 显式指到
//! `tests/udp_replay_matrix/` 子目录（与 `crates/lengsuo-hysteria/tests/lifecycle.rs`
//! 同一写法）。
#![allow(dead_code)]

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

#[path = "udp_replay_matrix/reference_interop.rs"]
mod reference_interop;
#[path = "udp_replay_matrix/tamper.rs"]
mod tamper;
#[path = "udp_replay_matrix/window_edge.rs"]
mod window_edge;

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
    path::PathBuf,
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
/// （`shadowaead_2022/service.go:55,77-80`），进程退出即清零 ⇒ 重启后
/// 同一 EIH 可重放。参考侧另有实跑证据见
/// `udp_replay_matrix/reference_interop.rs` 的
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
