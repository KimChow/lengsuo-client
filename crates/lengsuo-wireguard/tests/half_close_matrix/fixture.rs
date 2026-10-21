//! 半关闭 / 超时 / 清理三格共用的测试夹具。
//!
//! 全部为**假凭据**与**回环地址**；不引入真实网络、不引入后台线程、不输出密钥。
//!
//! 夹具提供三样东西：
//! 1. [`establish`]：一次完整的 Rust↔Rust 握手闭环（发起方 `Handshake` ↔ 响应方
//!    `Responder`），返回两端的会话材料；
//! 2. [`LoopbackPair`]：两个绑在 `127.0.0.1:0` 的 UDP socket，用于「对端接受
//!    连接后不回应」的握手超时场景；
//! 3. [`open_fd_count`] / [`thread_count`]：Linux 下的资源计数观测点，用来
//!    证明关闭后没有残留读循环/后台任务。
#![allow(dead_code)]

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use lengsuo_wireguard::handshake::{Handshake, Responder, ResponderKeys, TransportKeys};
use lengsuo_wireguard::transport::TransportKey;

/// 假静态私钥：仅测试用，非任何真实凭据。
pub const CLIENT_STATIC: [u8; 32] = [0x11; 32];
pub const SERVER_STATIC: [u8; 32] = [0x22; 32];
/// 假 PSK（两侧一致）。
pub const PSK: [u8; 32] = [0x33; 32];
/// 假 PSK（与对端不同，用于「握手被拒」分支）。
pub const PSK_WRONG: [u8; 32] = [0x44; 32];

/// 假 index（线上是随机 32 位；此处取固定假值）。
pub const CLIENT_INDEX: u32 = 0x1000_0001;
pub const SERVER_INDEX: u32 = 0x2000_0002;

/// 假临时密钥种子（`create_initiation` / `create_response` 的随机源注入点）。
pub const CLIENT_EPHEMERAL: [u8; 32] = [0xAA; 32];
pub const SERVER_EPHEMERAL: [u8; 32] = [0xBB; 32];
/// 第二条会话用的**不同**临时种子——用于证明旧密文在新会话里不可用。
pub const CLIENT_EPHEMERAL_ALT: [u8; 32] = [0xC1; 32];

/// 假载荷：只用于断言相等，绝不写进日志。
pub const PAYLOAD_A: &[u8] = b"dir-a-payload";
pub const PAYLOAD_B: &[u8] = b"dir-b-payload";

/// 握手会话的参数。
pub struct SessionSpec {
    pub client_static: [u8; 32],
    pub server_static: [u8; 32],
    /// 发起方使用的 PSK。
    pub client_psk: Option<[u8; 32]>,
    /// 响应方使用的 PSK（与发起方不同即模拟「错密码」）。
    pub server_psk: Option<[u8; 32]>,
    pub client_ephemeral: [u8; 32],
    pub server_ephemeral: [u8; 32],
    pub client_index: u32,
    pub server_index: u32,
}

impl Default for SessionSpec {
    fn default() -> Self {
        Self {
            client_static: CLIENT_STATIC,
            server_static: SERVER_STATIC,
            client_psk: None,
            server_psk: None,
            client_ephemeral: CLIENT_EPHEMERAL,
            server_ephemeral: SERVER_EPHEMERAL,
            client_index: CLIENT_INDEX,
            server_index: SERVER_INDEX,
        }
    }
}

/// 由静态私钥导出 X25519 公钥（用 x25519-dalek 公开 API，与被测代码同一实现）。
pub fn x25519_pub(secret: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    *PublicKey::from(&StaticSecret::from(*secret)).as_bytes()
}

/// 一个端点在握手完成后的会话材料（不含握手中间态）。
#[derive(Clone)]
pub struct Node {
    /// 本端 index（transport 报文的 receiver）。
    pub local_index: u32,
    /// 对端 index（transport 报文的发送目标）。
    pub remote_index: u32,
    /// 本端发送密钥。
    pub send_key: [u8; 32],
    /// 本端接收密钥。
    pub recv_key: [u8; 32],
}

impl Node {
    /// 本端的发送上下文。
    pub fn sender(&self) -> lengsuo_wireguard::transport::Sender {
        lengsuo_wireguard::transport::Sender::new(
            TransportKey::new(&self.send_key).expect("发送密钥长度合法"),
            self.remote_index,
            0,
        )
    }

    /// 本端的接收上下文。
    pub fn receiver(&self) -> lengsuo_wireguard::transport::Receiver {
        lengsuo_wireguard::transport::Receiver::new(
            TransportKey::new(&self.recv_key).expect("接收密钥长度合法"),
            self.local_index,
            u64::MAX,
        )
    }
}

/// 完成一次 Rust↔Rust 握手闭环，返回 (发起方, 响应方) 的会话材料。
///
/// 握手次序严格对齐参考 `device/noise-protocol.go` 的
/// `CreateMessageInitiation` → `ConsumeMessageInitiation` → `CreateMessageResponse`
/// → `ConsumeMessageResponse` → `BeginSymmetricSession`。
///
/// 断言：客户端发送密钥 == 服务端接收密钥，反向同理——方向性密钥顺序若写反，
/// 后面所有 transport 断言都会变成「假绿」。
pub fn establish(spec: &SessionSpec) -> (Node, Node) {
    let client_public = x25519_pub(&spec.client_static);
    let server_public = x25519_pub(&spec.server_static);

    let mut initiator = Handshake::new(
        &spec.client_static,
        &server_public,
        spec.client_psk,
        spec.client_index,
    )
    .expect("发起方可构造");
    let initiation = initiator
        .create_initiation(spec.client_ephemeral)
        .expect("initiation 可生成");

    let mut responder = Responder::new(
        &spec.server_static,
        &client_public,
        spec.server_psk,
        spec.server_index,
    )
    .expect("响应方可构造");
    responder
        .consume_initiation(&initiation)
        .expect("initiation 必须可剥壳");
    let mut response = responder
        .create_response(spec.server_ephemeral, spec.server_index)
        .expect("response 可构造");
    responder.add_macs(&mut response);

    let keys: TransportKeys = initiator
        .consume_response(&response)
        .expect("response 必须可消费");
    let server_keys: ResponderKeys = responder.begin_symmetric_session().expect("对称会话可派生");

    assert_eq!(
        keys.send, server_keys.receive,
        "客户端发送密钥必须等于服务端接收密钥"
    );
    assert_eq!(
        keys.receive, server_keys.send,
        "客户端接收密钥必须等于服务端发送密钥"
    );
    assert_eq!(keys.local_index, spec.client_index);
    assert_eq!(keys.remote_index, spec.server_index);
    assert_eq!(server_keys.local_index, spec.server_index);
    assert_eq!(server_keys.remote_index, spec.client_index);

    (
        Node {
            local_index: keys.local_index,
            remote_index: keys.remote_index,
            send_key: keys.send,
            recv_key: keys.receive,
        },
        Node {
            local_index: server_keys.local_index,
            remote_index: server_keys.remote_index,
            send_key: server_keys.send,
            recv_key: server_keys.receive,
        },
    )
}

/// 两个绑在回环的 UDP socket：客户端与「接受连接但不应答」的服务端。
pub struct LoopbackPair {
    pub client: UdpSocket,
    pub server: UdpSocket,
    pub client_addr: SocketAddr,
    pub server_addr: SocketAddr,
}

impl LoopbackPair {
    /// 建立回环 socket 对，读取超时固定为 2s（有限，绝不无限等待）。
    pub fn new() -> Self {
        let client = UdpSocket::bind("127.0.0.1:0").expect("回环 UDP 可绑定");
        let server = UdpSocket::bind("127.0.0.1:0").expect("回环 UDP 可绑定");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("读超时可设置");
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("写超时可设置");
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("读超时可设置");
        let client_addr = client.local_addr().expect("客户端本地地址");
        let server_addr = server.local_addr().expect("服务端本地地址");
        assert!(client_addr.ip().is_loopback(), "只允许回环地址");
        assert!(server_addr.ip().is_loopback(), "只允许回环地址");
        Self {
            client,
            server,
            client_addr,
            server_addr,
        }
    }
}

/// 错误是否属于「超时类」（读超时在 Unix 上表现为 `WouldBlock`）。
pub fn is_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// 错误读数：只输出错误类型名，绝不输出密钥/明文。
///
/// 握手产物 `TransportKeys` **刻意不实现 `Debug`**（密钥材料不得进日志），
/// 因此 `Result<TransportKeys, _>` 整体不能 `{:?}`。本 helper 只取错误侧。
pub fn err_name<T>(outcome: &Result<T, lengsuo_wireguard::TransportError>) -> String {
    match outcome {
        Ok(_) => "未返回错误".to_string(),
        Err(error) => format!("{error:?}"),
    }
}

/// 进程当前打开的文件描述符数量（Linux `/proc/self/fd`）。
///
/// 返回 `None` 表示该平台没有可观测点——调用方必须如实报告「无法断言」。
pub fn open_fd_count() -> Option<usize> {
    let entries = std::fs::read_dir("/proc/self/fd").ok()?;
    let mut count = 0usize;
    for entry in entries.flatten() {
        let _ = entry;
        count += 1;
    }
    Some(count)
}

/// 进程当前的线程数量（Linux `/proc/self/task`）。
///
/// 返回 `None` 表示该平台没有可观测点。
pub fn thread_count() -> Option<usize> {
    let entries = std::fs::read_dir("/proc/self/task").ok()?;
    let mut count = 0usize;
    for entry in entries.flatten() {
        let _ = entry;
        count += 1;
    }
    Some(count)
}

/// 「进程级读数观测窗」的独占锁。
///
/// 线程数（`/proc/self/task`）与 fd 数（`/proc/self/fd`）都是**进程级**读数，
/// 会被同一测试二进制里并行执行的其它用例干扰——尤其是
/// `tokio::task::spawn_blocking`（阻塞任务池的 worker 线程会按需增长）与
/// 其它用例打开的回环 socket。
///
/// 因此本文件的**全部**用例都取这把锁 ⇒ 文件内串行执行 ⇒ 观测窗内读数
/// 只反映本用例自身的行为。不同测试二进制是不同进程，互不影响。
///
/// 用 `tokio::sync::Mutex`（异步感知）：`std::sync::MutexGuard` 跨 `.await`
/// 持有是 clippy 明令禁止的错误（`await_holding_lock`），而本文件确有一个
/// `#[tokio::test]` 用例要在持锁期间 await。
static SERIAL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 取得串行执行锁（异步用例用）。
pub async fn serial_guard_async() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL_LOCK.lock().await
}

/// 取得串行执行锁（同步用例用）。
///
/// 同步用例不在 async 上下文里，因此用 `blocking_lock` 阻塞取锁是安全的。
pub fn serial_guard() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL_LOCK.blocking_lock()
}
