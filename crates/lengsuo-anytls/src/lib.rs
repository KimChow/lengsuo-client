#![forbid(unsafe_code)]
//! AnyTLS v2 认证及帧原语；尚未实现会话复用和参考互通，不可作为可用代理。
pub mod auth;
pub mod frame;

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
