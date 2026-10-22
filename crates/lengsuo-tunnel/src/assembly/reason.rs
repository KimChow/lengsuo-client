//! 失败原因的**固定短语**映射。
//!
//! # 为什么单独一个文件
//!
//! 装配层的错误文本必须满足两条纪律：
//!
//! 1. ⛔ **不含密钥、不含载荷字节**——只出现角色名、状态名与固定短语；
//! 2. ⛔ **可判定**——上层能按短语区分「认证失败」与「长度非法」，
//!    而不是只拿到一坨 `Err(...)`。
//!
//! 上游的错误类型里带着长度、计数器、index 等**上下文数据**，
//! 直接 `to_string()` 会把这些数字带进日志 ⇒ 本文件把它们**收敛成短语**。
//!
//! 这些短语是**契约的一部分**：改动它们等于改协议侧的错误语义。

use lengsuo_wireguard::handshake::ResponderError;
use lengsuo_wireguard::transport::Error as TransportError;

/// 发起方握手失败的固定短语。
pub(crate) fn initiator_reason(error: TransportError) -> &'static str {
    match error {
        TransportError::AuthFailed => "响应报文认证失败",
        TransportError::TooLong { .. } => "响应报文长度非法",
        TransportError::ReceiverMismatch { .. } => "响应报文接收者标识不匹配",
        TransportError::Poisoned => "发起方握手状态机失步",
        TransportError::CounterExhausted { .. } | TransportError::SealFailed => {
            "发起方握手内部状态异常"
        }
        TransportError::KeyLength { .. } => "会话密钥长度非法",
        TransportError::NotTransport(_) | TransportError::Wire(_) | TransportError::Replay(_) => {
            "响应报文不是合法的握手响应"
        }
    }
}

/// 响应方握手失败的固定短语。
pub(crate) fn responder_reason(error: ResponderError) -> &'static str {
    match error {
        ResponderError::Length { .. } => "initiation 长度非法",
        ResponderError::NotInitiation => "不是握手初始化报文",
        ResponderError::AuthFailed => "initiation 段认证失败",
        ResponderError::InvalidKey => "无效公钥或共享密钥为全零",
        ResponderError::UnknownPeer => "未知对端",
        ResponderError::Replay => "握手重放",
        ResponderError::Flood => "握手洪水",
        ResponderError::State(_) => "响应方握手状态机失步",
        ResponderError::Mac => "MAC 校验失败",
    }
}

/// 封装失败的固定短语。
pub(crate) fn seal_reason(error: TransportError) -> &'static str {
    match error {
        TransportError::TooLong { .. } => "明文超长（超过单包上限）",
        TransportError::CounterExhausted { .. } => "发送计数器已用尽",
        TransportError::Poisoned => "发送上下文已 poison",
        TransportError::SealFailed => "AEAD 封装失败",
        _ => "封装失败",
    }
}
