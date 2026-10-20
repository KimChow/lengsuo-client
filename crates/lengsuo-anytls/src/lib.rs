#![forbid(unsafe_code)]
//! AnyTLS v2 认证、帧原语、产品 TLS 信任链及服务端入站会话状态机；
//! 复用池与参考互通仍未闭环，不可作为可用代理。
pub mod auth;
pub mod client_state;
pub mod frame;
pub mod padding;
pub mod pool;
pub mod server;
pub mod server_state;
pub mod socks;
pub mod stream;
pub mod tls;
pub mod tunnel;
pub mod udp_assoc;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("协议数据未完整")]
    Incomplete,
    #[error("不支持或非法的协议字段")]
    Invalid,
    #[error("数据长度超过容量限制")]
    TooLarge,
    #[error("认证失败")]
    Authentication,
    #[error("操作超时")]
    Timeout,
    #[error("流操作失败：{0}")]
    Io(#[from] std::io::Error),
    /// TLS 信任链配置失败；文案为静态原因，绝不携带证书、私钥或 CA 内容。
    #[error("TLS 信任链配置失败：{0}")]
    TlsConfig(&'static str),
}
