//! 跨进程重启的 UDP 重放保护：用**真正的第二个进程**验证落盘状态被加载。
//!
//! 判据：进程 A 接受 `(session, packet id)` 后落盘退出；进程 B 加载同一快照，
//! 同一 `(session, packet id)` 必须 fail-closed 拒绝，递增的新 id 必须接受。
//! 快照路径由环境变量 `LENGSUO_REPLAY_PATH` 指定（临时目录），不写仓内固定路径。
//!
//! 第二进程通过重新执行本测试二进制实现，不使用 sleep 当同步手段：
//! 父进程用 `Child::wait` 等退出码，子进程一次性完成读写并退出。
use lengsuo_ss2022::replay_store::ReplayStore;
use std::{path::PathBuf, process::Command};

/// `Receiver` 挂接存储后端到端拒绝 ChaCha 重放：第二条相同报文 fail-closed。
#[test]
fn receiver_with_store_rejects_replay_after_reload() {
    use lengsuo_ss2022::{
        crypto::{Key, Method},
        packet::Sender,
        receiver::{Clock, Receiver},
        Error,
    };
    use ss_core::target::TargetAddr;
    use std::{
        net::SocketAddr,
        time::{Duration, Instant},
    };

    let path = temporary_path("receiver");
    let _ = std::fs::remove_file(&path);
    let key = Key::new(Method::ChaCha20, &[0x11; 32]).unwrap();
    let mut sender = Sender::new(key.clone(), None).unwrap();
    let packet = sender
        .seal(&TargetAddr::V4([127, 0, 0, 1], 53), b"payload", 1000, 0)
        .unwrap();
    let peer = SocketAddr::from(([127, 0, 0, 1], 40000));
    let clock = Clock {
        unix_seconds: 1000,
        monotonic: Instant::now(),
    };

    {
        let store = ReplayStore::load(&path).unwrap();
        let mut receiver = Receiver::new(key.clone(), None, 4, Duration::from_secs(60))
            .unwrap()
            .with_replay_store(store);
        receiver.receive(&packet, peer, clock).unwrap();
        assert!(matches!(
            receiver.receive(&packet, peer, clock),
            Err(Error::Replay)
        ));
        receiver.flush_replay().unwrap();
    }

    // 模拟重启：新 Receiver + 从同一路径加载的 store。
    let store = ReplayStore::load(&path).unwrap();
    let mut restarted = Receiver::new(key, None, 4, Duration::from_secs(60))
        .unwrap()
        .with_replay_store(store);
    assert!(matches!(
        restarted.receive(&packet, peer, clock),
        Err(Error::Replay)
    ));
    let _ = std::fs::remove_file(&path);
}

const CHILD_ENV: &str = "LENGSUO_REPLAY_CHILD";
const PATH_ENV: &str = "LENGSUO_REPLAY_PATH";
const SESSION_ID: [u8; 8] = [0x5A; 8];
const FIRST_ID: u64 = 41;

fn temporary_path(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "lengsuo-ss2022-restart-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    directory.join("replay.bin")
}

/// 子进程入口：加载（或新建）快照，接受 `FIRST_ID`，落盘后退出。
/// 只有在 `CHILD_ENV` 存在时才执行，正常测试运行不会命中。
#[test]
fn child_process_writes_then_replays() {
    if std::env::var(CHILD_ENV).is_err() {
        return;
    }
    let path = std::env::var(PATH_ENV).expect("子进程必须收到快照路径");
    let mut store = ReplayStore::load(path).unwrap();
    // 首次接受固定 id 并落盘，模拟重启前的进程状态。
    assert!(store.accept(SESSION_ID, FIRST_ID), "子进程首次应接受");
    store.flush().unwrap();
    std::process::exit(0);
}

/// 父进程：先跑子进程写入快照，再在本进程加载同一路径做重放判定。
#[test]
fn replay_is_rejected_across_process_restart() {
    let path = temporary_path("parent");
    let _ = std::fs::remove_file(&path);
    let executable = std::env::current_exe().unwrap();
    let status = Command::new(&executable)
        .args([
            "child_process_writes_then_replays",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .env(PATH_ENV, &path)
        .status()
        .unwrap();
    assert!(status.success(), "子进程应成功写入快照");
    assert!(path.exists(), "子进程应落盘快照");

    // 新进程（本进程）加载同一快照：已见 packet id 必须拒绝。
    let mut store = ReplayStore::load(&path).unwrap();
    assert!(
        store.contains(SESSION_ID, FIRST_ID),
        "重启后应加载到已见 id"
    );
    assert!(
        !store.accept(SESSION_ID, FIRST_ID),
        "重启后同一 (session, packet id) 必须 fail-closed 拒绝"
    );
    // 正常递增 id 全收。
    for id in (FIRST_ID + 1)..(FIRST_ID + 5) {
        assert!(store.accept(SESSION_ID, id), "递增 id {id} 应接受");
    }
    // 另一会话不受影响。
    assert!(store.accept([0x99; 8], FIRST_ID), "其它会话应独立");
    let _ = std::fs::remove_file(&path);
}

/// 两次 `ReplayStore` 构造（同进程内模拟重启）之间同样拒绝重放。
#[test]
fn replay_is_rejected_across_store_reload() {
    let path = temporary_path("reload");
    let _ = std::fs::remove_file(&path);
    {
        let mut store = ReplayStore::load(&path).unwrap();
        assert!(store.accept(SESSION_ID, 0));
        assert!(store.accept(SESSION_ID, 1));
        store.flush().unwrap();
    }
    let mut reopened = ReplayStore::load(&path).unwrap();
    assert!(!reopened.accept(SESSION_ID, 0), "重放 id 0 必须拒绝");
    assert!(!reopened.accept(SESSION_ID, 1), "重放 id 1 必须拒绝");
    assert!(reopened.accept(SESSION_ID, 2), "递增 id 2 应接受");
    let _ = std::fs::remove_file(&path);
}
