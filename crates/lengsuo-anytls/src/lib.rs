#![forbid(unsafe_code)]
//! AnyTLS v2 认证、帧原语及服务端入站会话状态机；
//! 尚未实现 TLS、复用池与参考互通，不可作为可用代理。
pub mod auth;
pub mod client_state;
pub mod frame;
pub mod padding;
pub mod server;
pub mod server_state;

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
}
