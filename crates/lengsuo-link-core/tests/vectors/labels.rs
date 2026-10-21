//! 跨端**稳定错误标签**（帧层 / 会话层）。
//!
//! # 为什么标签必须稳定
//!
//! `Display` / `Debug` 的措辞会随实现改动而变，把它当跨端契约 ⇒ 移动端
//! 一升级就误判。本模块给每个错误类别一个**稳定的 kebab-case 标签**，
//! 移动端按标签判断失败原因。
//!
//! ⛔ 标签是**跨端契约**：改了标签就是改了协议 ⇒ 移动端要同步升级。

// ---------------------------------------------------------------- 稳定错误标签
//
// ⛔ **不要**断言 Rust `Debug` 文本当跨端契约：Debug 文本会随措辞变化。
// 下面的标签是**稳定契约**，移动端按标签判断失败原因。

/// 帧层错误标签（跨端契约）。
pub mod frame_label {
    /// 帧头魔数不匹配。
    pub const BAD_MAGIC: &str = "frame.bad_magic";
    /// 帧头校验和不符。
    pub const HEADER_CRC_MISMATCH: &str = "frame.header_crc_mismatch";
    /// 帧头声明的载荷长度超过上限（**不截断**）。
    pub const PAYLOAD_TOO_LONG: &str = "frame.payload_too_long";
    /// 输入不足以切出一帧（**不返回部分数据**）。
    pub const INCOMPLETE: &str = "frame.incomplete";
    /// 帧长与声明不符。
    pub const LENGTH_MISMATCH: &str = "frame.length_mismatch";
    /// 未知帧类型。
    pub const UNKNOWN_FRAME_TYPE: &str = "frame.unknown_frame_type";
    /// 保留标志位非零。
    pub const RESERVED_FLAGS: &str = "frame.reserved_flags";
    /// 协议版本不受支持。
    pub const UNSUPPORTED_VERSION: &str = "frame.unsupported_version";
}

/// 会话层错误标签（跨端契约）。
pub mod session_label {
    /// 角色不匹配。
    pub const ROLE_MISMATCH: &str = "session.role_mismatch";
    /// AEAD 认证失败（**不回退明文**）。
    pub const AUTH_FAILED: &str = "session.auth_failed";
    /// 会话已失效。
    pub const INVALIDATED: &str = "session.invalidated";
    /// 状态不允许该操作。
    pub const INVALID_STATE: &str = "session.invalid_state";
    /// 帧层错误（经会话层上报）。
    pub const FRAME: &str = "session.frame";
    /// 世代号不匹配（两侧世代号必须相等）。
    pub const GENERATION_MISMATCH: &str = "session.generation_mismatch";
}

/// 帧层错误 → 稳定标签。
pub fn frame_error_label(error: &lengsuo_link_core::frame::FrameError) -> &'static str {
    use lengsuo_link_core::frame::FrameError as E;
    match error {
        E::BadMagic { .. } => frame_label::BAD_MAGIC,
        E::HeaderCrcMismatch { .. } => frame_label::HEADER_CRC_MISMATCH,
        E::PayloadTooLong { .. } => frame_label::PAYLOAD_TOO_LONG,
        E::Incomplete { .. } => frame_label::INCOMPLETE,
        E::LengthMismatch { .. } => frame_label::LENGTH_MISMATCH,
        E::UnknownFrameType { .. } => frame_label::UNKNOWN_FRAME_TYPE,
        E::ReservedFlags { .. } => frame_label::RESERVED_FLAGS,
        E::UnsupportedVersion { .. } => frame_label::UNSUPPORTED_VERSION,
        other => panic!("帧层错误没有稳定标签：{other:?}"),
    }
}

/// 会话层错误 → 稳定标签。
pub fn session_error_label(error: &lengsuo_link_core::session::SessionError) -> &'static str {
    use lengsuo_link_core::session::SessionError as E;
    match error {
        E::RoleMismatch { .. } => session_label::ROLE_MISMATCH,
        E::AuthFailed => session_label::AUTH_FAILED,
        E::Invalidated => session_label::INVALIDATED,
        E::InvalidState { .. } => session_label::INVALID_STATE,
        E::Frame(_) => session_label::FRAME,
        other => panic!("会话层错误没有稳定标签：{other:?}"),
    }
}
