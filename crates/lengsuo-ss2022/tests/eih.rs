//! SIP023 EIH 固定向量、拒绝路径、链式解析与服务端方向（纯 Rust，默认套件）。
//!
//! 向量由参考原语独立生成：Go `lukechampine.com/blake3` + `crypto/aes`，按
//! `sing-shadowsocks v0.2.7` 的 `writeExtendedIdentityHeaders` 公式计算。
//! 这些断言锁定「salt 之后是 16 字节 AES 块身份头」的线格式；真实互通见
//! `tests/xray_eih.rs`（Xray 多用户入站，`#[ignore]`）。
use lengsuo_ss2022::{
    crypto::{Key, Method},
    eih::{
        decode_chain, decode_header, EihServer, IdentityChain, User, UserTable,
        IDENTITY_HEADER_LEN, MAX_IDENTITY_LAYERS,
    },
    tcp::{receive::clock_at, Association, Direction, Reader, SessionReplay, Writer},
    Error,
};
use ss_core::target::TargetAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟应晚于纪元")
        .as_secs()
}

fn clock() -> lengsuo_ss2022::receiver::Clock {
    clock_at(now_secs(), Instant::now())
}

fn key(method: Method, byte: u8) -> Key {
    Key::new(method, &vec![byte; method.key_len()]).expect("假 PSK 长度应匹配套件")
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn table(user_key: Key, uid: u64) -> UserTable {
    UserTable::new(vec![User { uid, key: user_key }]).expect("单用户表应合法")
}

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("回环可监听");
    let client = TcpStream::connect(listener.local_addr().expect("有地址"))
        .await
        .expect("回环可连接");
    let (server, _peer) = listener.accept().await.expect("回环可接受");
    (client, server)
}

// 用例按主题拆到 `tests/eih/` 下，用 `include!` **文本并入**同一模块（不是
// `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致（`mod` 方案会
// 把名字变成 `vectors::xxx` 等，属于改名）。代价是分文件之间不能重复 `use`，
// 故所有 `use` 都留在本入口文件。
include!("eih/vectors.rs");
include!("eih/fail_closed.rs");
include!("eih/user_table.rs");
include!("eih/session.rs");
