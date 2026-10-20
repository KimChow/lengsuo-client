#![forbid(unsafe_code)]
//! SIP022 AES 原语：UDP 报文与会话，以及 TCP 双向流编解码；完整运行时尚未完成，不是可用代理服务。
pub mod crypto;
pub mod eih;
pub mod packet;
pub mod receiver;
pub mod replay_store;
pub mod tcp;

pub use eih::{EihHeader, EihServer, IdentityChain, ResolvedIdentity, User, UserTable};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("会话策略非法")]
    SessionPolicy,
    #[error("会话容量已满")]
    SessionCapacity,
    #[error("检测到时钟回退")]
    ClockRollback,
    #[error("报文重放或计数器已过期")]
    Replay,
    #[error("密钥长度不匹配")]
    KeyLength,
    #[error("报文长度非法")]
    Length,
    #[error("报文认证失败")]
    Authentication,
    #[error("报文方向不匹配")]
    Direction,
    #[error("报文时间超出允许窗口")]
    Timestamp,
    #[error("响应与客户端会话不匹配")]
    ClientSession,
    #[error("发送计数器已耗尽")]
    Exhausted,
    #[error("无法取得系统随机数")]
    Entropy,
    #[error("AEAD 加密失败")]
    Seal,
    #[error("头部填充或声明长度非法")]
    HeaderPadding,
    #[error("读取超时")]
    Timeout,
    #[error("流已因失败永久失效")]
    Poisoned,
    #[error("流内 I/O 失败")]
    Io(#[from] std::io::Error),
    #[error("目标地址非法：{0}")]
    Address(#[from] ss_core::Error),
    #[error("该方法不支持此操作")]
    Unsupported,
    #[error("重放快照损坏或格式非法")]
    ReplayStore,
    #[error("配置要求多用户身份头，但请求中没有可用的身份头")]
    EihMissing,
    #[error("身份头被截断")]
    EihTruncated,
    #[error("身份链超过本实现允许的层数")]
    EihChainTooLong,
    #[error("身份头长度或出现方向非法")]
    EihShape,
    #[error("身份头只允许出现在请求方向")]
    EihDirection,
    #[error("用户表为空或含重复 uid/身份指纹")]
    EihUserTable,
    #[error("身份指纹不在用户表中")]
    IdentityUnknown,
}
