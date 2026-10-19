//! AnyTLS v2 **服务端**实现，对齐 anytls-go fd6167a：
//! `cmd/server/{inbound_tcp,outbound_tcp,myserver}.go` 与 `proxy/session/{session,stream,frame}.go`。
//!
//! 分层（每层对应参考里的一组函数）：
//! - [`tls`]：TcpStream → 已握手 TLS 流（参考 `tls.Server(c, tlsConfig)`）。
//! - [`writer`]：控制帧/数据帧编码 + padding 写出策略（参考 `writeControlFrame` /
//!   `writeDataFrame` / `writeConn`）。
//! - [`sink`]：会话级共享写出句柄（参考 `connLock` 串行化）。
//! - [`streams`]：单流双向中继与 SYNACK/FIN 生命周期（参考 `outbound_tcp.go` +
//!   `session/stream.go`）。
//! - [`session`]：认证 → Settings 协商 → 帧循环装配（参考 `handleTcpConnection`）。
pub mod session;
pub mod sink;
pub mod streams;
pub mod tls;
pub mod writer;

pub use session::SessionStats;

/// 认证 padding 上限：参考无显式上限，此处给 4 KiB 防御余量。
pub(crate) const PADDING_LIMIT: u16 = 4096;
/// 单会话活跃流上限（本端自设，参考无上限）。
pub const MAX_STREAMS: usize = 64;

/// 服务端会话的最小装配：认证口令 + padding 方案 + 容量/超时。
///
/// TLS 由调用方负责（见 [`tls`]）：`Session::run` 接的是已握手的流。
#[derive(Clone)]
pub struct ServerConfig {
    /// 认证口令（明文；会话内部只保存 SHA256 摘要用于常量时间比对）。
    pub password: Vec<u8>,
    /// padding 方案；默认 [`padding::PaddingScheme::default_scheme`]。
    pub padding: crate::padding::PaddingScheme,
    /// 单会话活跃流上限。
    pub max_streams: usize,
    /// 每次读写操作的等待上限。
    pub wait: std::time::Duration,
}

impl ServerConfig {
    pub fn new(password: &[u8], wait: std::time::Duration) -> Self {
        Self {
            password: password.to_vec(),
            padding: crate::padding::PaddingScheme::default_scheme(),
            max_streams: MAX_STREAMS,
            wait,
        }
    }
}

/// 跑完一条已握手流上的 AnyTLS 服务端会话；等价于
/// `Session::new(stream, &config.password, config.padding, config.max_streams, config.wait)?.run()`。
pub async fn serve<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    config: ServerConfig,
) -> Result<session::SessionStats, crate::Error> {
    session::Session::new(
        stream,
        &config.password,
        config.padding,
        config.max_streams,
        config.wait,
    )?
    .run()
    .await
}
