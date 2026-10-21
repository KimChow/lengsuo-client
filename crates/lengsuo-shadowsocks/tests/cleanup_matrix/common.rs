//! 「清理」矩阵的**共享夹具**（仅回环、假口令、临时端口/临时目录）。
//!
//! 与固定参考（Xray v26.3.27 / `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//! `proxy/shadowsocks/server.go` 的 `handleConnection` 对齐的是**收尾语义**：
//!
//! - 参考用 `task.Run(ctx, requestDoneAndCloseWriter, responseDone)` **并发**跑两个
//!   方向；任一方向出错即 `common.Interrupt(link.Reader)` + `common.Interrupt(link.Writer)`
//!   中断另一方向并回收连接（`server.go:286-289`）。
//! - 参考的请求方向干净结束是 `task.Close(link.Writer)`（对上游写半关闭），
//!   回程方向结束是 `responseWriter` 的写半关闭。
//! - 参考的 `signal.CancelAfterInactivity` + `policy` 分级超时本端用统一的
//!   会话超时近似（见 `docs/shadowsocks-status.md` 偏离清单）。
//!
//! 本模块只提供**可复用的观测手段**，不重复 `tests/relay_e2e.rs` 已覆盖的场景
//! （绝不回退直连 / 截断 / `shutdown` 回收）。观测手段（上游事件、端口占用、
//! 记忆池条目）见同目录的 `probe.rs`。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use lengsuo_shadowsocks::{
    CipherSuite, RelayConfig, RelayConfigParts, RelayHandle, RelayService, SaltStateConfig,
    TargetAddr, TcpReader, TcpWriter,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 测试假口令，与任何生产凭据无关。
pub const PASSWORD: &str = "ss-cleanup-matrix-fake-passw0rd";
/// 单次 I/O 等待上限。
pub const WAIT: Duration = Duration::from_secs(5);
/// 本文件统一的套件（salt 长度 32 字节）。
pub const SUITE: CipherSuite = CipherSuite::Aes256Gcm;
/// 中继的会话超时（**大于** [`OBSERVE`]：这样「在 OBSERVE 内看到收尾」
/// 才能证明是**感知到断开**后的主动关闭，而不是会话超时兜底）。
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// 「及时感知」的观察上限：必须显著小于 [`IDLE_TIMEOUT`]。
pub const OBSERVE: Duration = Duration::from_secs(3);

/// 临时目录守卫：salt 记忆池状态文件只落系统临时目录，用例结束删除。
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "lengsuo-ss-cleanup-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("创建临时目录失败");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 单线程 runtime + LocalSet：中继用 `spawn_local`，必须在 LocalSet 里驱动。
pub fn local_set() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

/// 中继配置：挂上 salt 记忆池的持久化状态文件（可选）。
pub fn config(replay: Option<(usize, Duration)>, state: Option<&Path>) -> RelayConfig {
    let base = RelayConfig::new(
        RelayConfigParts {
            suite: SUITE,
            idle_timeout: IDLE_TIMEOUT,
            replay,
        },
        PASSWORD.as_bytes(),
    );
    match state {
        Some(path) => base.with_salt_state(SaltStateConfig::new(path.to_path_buf())),
        None => base,
    }
}

/// 起一个中继服务，返回监听地址与句柄。
pub async fn start_relay(
    replay: Option<(usize, Duration)>,
    state: Option<&Path>,
) -> (SocketAddr, RelayHandle) {
    let service = RelayService::bind(
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
        config(replay, state),
    )
    .await
    .expect("中继绑定");
    let addr = service.local_addr().expect("中继地址");
    let handle = service.start().await.expect("中继启动");
    (addr, handle)
}

/// 用**固定 salt** 构造一段合法的 TCP 线上字节（salt + 一个 chunk）。
///
/// 本端公开的 [`TcpWriter`] 强随机生成 salt，无法指定；这里用 ss-core 原语拼帧，
/// 只改变 salt 的选择，不改任何线上格式。首段明文 = 目标地址 + 载荷
/// （中继的握手要求）。这样测试才能断言「某条连接用过的 salt 在连接结束后
/// 是否仍留在记忆池里」——而记忆池的**实现真实语义**正是「记录后按时间窗保留，
/// 连接收尾不删除」（见 `docs/shadowsocks-status.md` 的语义说明）。
pub async fn fixed_salt_request(salt: &[u8], target: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    assert_eq!(salt.len(), SUITE.salt_len(), "salt 长度必须与套件一致");
    let master = ss_core::kdf::evp_bytes_to_key(PASSWORD.as_bytes(), SUITE.key_len());
    let subkey = ss_core::kdf::hkdf_sha1_subkey(&master, salt, SUITE.key_len());
    let mut aead = ss_core::crypto::SessionAead::new(SUITE, subkey);
    let mut plain = Vec::new();
    target.encode_checked(&mut plain).expect("回环目标可编码");
    plain.extend_from_slice(payload);
    let mut wire = Vec::new();
    wire.extend_from_slice(salt);
    ss_core::chunk::write_chunk(&mut wire, &mut aead, &plain)
        .await
        .expect("固定 salt 帧应可构造");
    wire
}

/// 把**原始线上字节**写到中继并半关闭写端（不做任何封装）。
pub async fn send_raw(relay: SocketAddr, wire: &[u8]) -> TcpStream {
    let mut stream = timeout(WAIT, TcpStream::connect(relay))
        .await
        .expect("连接中继超时")
        .expect("连接中继");
    timeout(WAIT, stream.write_all(wire))
        .await
        .expect("写中继超时")
        .expect("写中继失败");
    timeout(WAIT, stream.shutdown())
        .await
        .expect("写半关闭超时")
        .expect("写半关闭失败");
    stream
}

/// 用 RST 中断一条已建立的连接（**不发 EOF**）。
pub fn abort(stream: TcpStream) {
    let _ = stream.set_zero_linger();
    drop(stream);
}

/// 客户端方向的一次「写请求」——**不半关闭写端**（连接保持打开）。
///
/// 用于「一条连接要活过另一条连接的异常结束」的并行场景。
pub async fn write_request(stream: &mut TcpStream, target: &TargetAddr, payload: &[u8]) {
    let mut request: Vec<u8> = Vec::new();
    target.encode_checked(&mut request).expect("回环目标可编码");
    request.extend_from_slice(payload);
    let mut writer =
        TcpWriter::new(&mut *stream, SUITE, PASSWORD.as_bytes(), WAIT).expect("构造写端");
    timeout(WAIT, writer.send(&request))
        .await
        .expect("send 未被外层超时")
        .expect("send 成功");
    drop(writer);
}

/// 客户端方向的一次「写**多个** chunk」——**不半关闭写端**（连接保持打开）。
///
/// 同一个 [`TcpWriter`] 上连发 `payloads.len()` 个 chunk（salt 只在第一个 chunk
/// 之前上线，nonce 序列连续）。用于覆盖「同一个连接里连发多个 chunk」时，
/// 中继**必须把每个 chunk 都转发给上游**——只发一个 chunk 的用例覆盖不到
/// `copy_request` 的「后续 chunk 转发」分支。
pub async fn write_request_chunks(stream: &mut TcpStream, target: &TargetAddr, payloads: &[&[u8]]) {
    let mut writer =
        TcpWriter::new(&mut *stream, SUITE, PASSWORD.as_bytes(), WAIT).expect("构造写端");
    for (index, payload) in payloads.iter().enumerate() {
        let mut request: Vec<u8> = Vec::new();
        if index == 0 {
            target.encode_checked(&mut request).expect("回环目标可编码");
        }
        request.extend_from_slice(payload);
        timeout(WAIT, writer.send(&request))
            .await
            .expect("send 未被外层超时")
            .expect("send 成功");
    }
    drop(writer);
}

/// 客户端方向的一次「写请求 → 半关闭写端」。
pub async fn send_request(stream: &mut TcpStream, target: &TargetAddr, payload: &[u8]) {
    let mut request: Vec<u8> = Vec::new();
    target.encode_checked(&mut request).expect("回环目标可编码");
    request.extend_from_slice(payload);
    let mut writer =
        TcpWriter::new(&mut *stream, SUITE, PASSWORD.as_bytes(), WAIT).expect("构造写端");
    timeout(WAIT, writer.send(&request))
        .await
        .expect("send 未被外层超时")
        .expect("send 成功");
    timeout(WAIT, writer.shutdown())
        .await
        .expect("shutdown 未被外层超时")
        .expect("写半关闭应成功");
    drop(writer);
}

/// 客户端方向的一次「写请求 → 读回程到干净 EOF」，返回回程字节。
///
/// 读端用 [`TcpReader`] 解帧；**写端必须先半关闭**（否则回程方向不会结束）。
pub async fn roundtrip(relay: SocketAddr, target: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut stream = timeout(WAIT, TcpStream::connect(relay))
        .await
        .expect("连接中继超时")
        .expect("连接中继");
    send_request(&mut stream, target, payload).await;
    read_response(stream).await
}

/// 读回程方向到干净 EOF，返回收到的全部字节（解帧错误 ⇒ 明确失败）。
pub async fn read_response(mut stream: TcpStream) -> Vec<u8> {
    let (read_half, _write_half) = stream.split();
    let mut reader = TcpReader::new(read_half, SUITE, PASSWORD.as_bytes(), WAIT).expect("构造读端");
    let mut got = Vec::new();
    for _ in 0..16 {
        match timeout(WAIT, reader.recv()).await.expect("recv 超时") {
            Ok(Some(chunk)) => got.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(err) => panic!("回程读取失败（应等到干净 EOF）：{err}"),
        }
    }
    got
}

/// 读回程方向的**下一个 chunk**（`None` = 干净 EOF）。
///
/// 回程方向有自己的新 salt，`TcpReader` 首次 `recv` 时自动读取并派生。
pub async fn read_one_chunk(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut reader =
        TcpReader::new(&mut *stream, SUITE, PASSWORD.as_bytes(), WAIT).expect("构造读端");
    match timeout(WAIT, reader.recv()).await.expect("recv 超时") {
        Ok(chunk) => chunk,
        Err(err) => panic!("回程读取失败：{err}"),
    }
}
