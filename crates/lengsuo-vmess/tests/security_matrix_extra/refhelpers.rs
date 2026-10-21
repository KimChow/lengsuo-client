//! 参考互通用例的本地小工具（不引入新依赖）。
//!
//! 语义基线：Xray commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//!
//! - `cmd_key_from_uuid`：`MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")`
//!   （参考 `common/protocol/id.go` 的 `NewID`）。
//! - `response_key_iv`：`SHA256(requestBodyKey/IV)[:16]`
//!   （参考 `proxy/vmess/encoding/server.go` 的 `EncodeResponseHeader`）。
//! - `spawn_echo`：本地回显后端（回显收到的全部字节），仅供互通判据使用。
//!
//! 凭据说明：UUID 是**随机生成的测试假凭据**，全程**不打印**（避免日志泄漏）。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// 生成 RFC4122 v4 UUID 字节（测试假凭据，**不打印**）。
pub fn uuid_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("getrandom 生成 UUID");
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    bytes
}

/// UUID 字节 → 连字符小写十六进制。
pub fn uuid_string(bytes: &[u8; 16]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// `MD5(uuid || 固定盐)` = 参考的 cmd key（`common/protocol/id.go` `NewID`）。
pub fn cmd_key_from_uuid(uuid: &[u8; 16]) -> [u8; 16] {
    use md5::Digest as _;
    let mut hasher = md5::Md5::default();
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hasher.finalize().into()
}

/// `responseBodyKey/IV = SHA256(requestBodyKey/IV)[:16]`。
pub fn response_key_iv(body_key: &[u8; 16], body_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    use sha2::{Digest as _, Sha256};
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&Sha256::digest(body_key)[..16]);
    iv.copy_from_slice(&Sha256::digest(body_iv)[..16]);
    (key, iv)
}

/// 起一个本地回显后端（回显收到的全部字节）。
pub async fn spawn_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let (addr, handle, _) = spawn_echo_counted().await;
    (addr, handle)
}

/// 起一个**带连接计数**的本地回显后端。
///
/// 返回 `(地址, 任务句柄, 计数器)`。计数器是**后端被真正连上的次数**。
///
/// 为什么需要它：判定「参考是否把请求转发到了后端」不能只看「客户端有没有
/// 收到回显」——参考在**拒绝**时可能同样不回数据。用后端连接数才能区分
/// 「请求根本没被转发」（后端没被连上）与「转发了但没回数据」。
pub async fn spawn_echo_counted() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("可监听回显端口");
    let addr = listener.local_addr().expect("有地址");
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    (addr, handle, accepts)
}
