//! 中继服务的失败原因。
//!
//! 所有变体都不含口令、主密钥、salt 或 subkey，可安全落日志。

use std::io;

use crate::salt_store::SaltStoreError;

/// 中继失败原因。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 配置非法（空口令、零截止时间、零容量等）。
    #[error("中继配置非法：{0}")]
    Config(String),

    /// 监听器绑定/接受失败，或服务无法继续。
    #[error("监听失败：{0}")]
    Listen(#[source] io::Error),

    /// 请求方向握手（salt + 地址）失败。失败即关连接，不重试、不直连。
    #[error("握手失败：{0}")]
    Handshake(#[source] crate::tcp::Error),

    /// 拨号目标失败（连接被拒/超时/域名解析失败）。**不直连、不降级**。
    #[error("目标不可达：{0}")]
    Unreachable(String),

    /// 中继过程中某一方向失败。
    #[error("中继失败：{0}")]
    Stream(#[source] crate::tcp::Error),

    /// 会话超过截止时间。
    #[error("会话超时")]
    Timeout,

    /// 连接的底层读写失败。
    #[error("连接 I/O 失败：{0}")]
    Io(#[source] io::Error),

    /// 重放窗口构造失败（配置容量/时间窗非法）。
    #[error("重放窗口非法：{0}")]
    Replay(#[source] crate::replay::Error),

    /// salt 记忆池持久化失败（状态文件损坏 ⇒ fail-closed 拒绝启动；写盘失败）。
    #[error("salt 记忆池持久化失败：{0}")]
    SaltStore(#[source] SaltStoreError),
}
