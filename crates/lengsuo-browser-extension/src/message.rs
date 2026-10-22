//! 消息类型表（契约 §5.3）与跨仓常量（契约 §5.0）。
//!
//! 表里的 **11 种类型全部是「扩展 → host」的请求**；契约没有定义
//! host → 扩展的方向 ⇒ 本模块也不臆造反向类型。
//!
//! # 编号的跨仓对照
//!
//! 编号来自冻结的契约 §5.3，扩展侧另有一份独立实现（本仓之外的
//! `extensions/credential/src/background/native_bridge.js` 里的 `MSG` 表）。
//! 两边的编号逐项一致这件事由**固定向量文件**钉住
//! （`tests/vectors/credential-wire-v1.json` 的 `extension_message_types` 段），
//! 而不是靠口头约定。
//!
//! [`MessageType::name`] 刻意返回扩展侧 `MSG` 表的**键名**，
//! 于是「编号一致」可以被机械比对：向量文件里的每个键都必须能
//! 由本枚举还原出来。

/// Native Messaging **host 名**（契约 §5.0 的跨仓常量）。
///
/// 扩展用它 `connectNative`，客户端仓的 host 用它做注册名。
/// ⛔ 本 crate 不涉及扩展 ID 与扩展目录名（那两项跨仓取值尚待裁定）。
pub const HOST_NAME: &str = "lengsuo.credential";

/// 「回退到浏览器原生响应」的消息类型编号（契约 §5.3）。
///
/// 扩展拿不到托管响应时**必须回退到浏览器原生响应**，而不是 reject，
/// 这样页面上的用户仍能登录。
pub const NATIVE_RESPONSE_FALLBACK_TYPE: u8 = 10;

/// 消息类型：扩展 → host 的请求类型（契约 §5.3，共 11 种）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// 0：列举凭据。
    ListCredentials = 0,
    /// 1：取密码。
    GetPassword = 1,
    /// 2：取 TOTP 验证码。
    GetTotp = 2,
    /// 3：创建 passkey（create）。
    PasskeyCreate = 3,
    /// 4：取断言（get）。
    PasskeyGet = 4,
    /// 5：保存密码。
    SavePassword = 5,
    /// 6：风控预检。
    RiskCheck = 6,
    /// 7：撤销 passkey 引用。
    RevokePasskeyRef = 7,
    /// 8：恢复码解封。
    Recover = 8,
    /// 9：授权查询。
    AuthQuery = 9,
    /// 10：保留原生作回退（`UseNativeResponse`）。
    UseNativeResponse = 10,
}

impl MessageType {
    /// 全部 11 种（顺序即编号顺序）。
    pub const ALL: [MessageType; 11] = [
        Self::ListCredentials,
        Self::GetPassword,
        Self::GetTotp,
        Self::PasskeyCreate,
        Self::PasskeyGet,
        Self::SavePassword,
        Self::RiskCheck,
        Self::RevokePasskeyRef,
        Self::Recover,
        Self::AuthQuery,
        Self::UseNativeResponse,
    ];

    /// 线上字节值（契约 §5.3 的编号）。
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// 由线上字节值还原；未知编号返回 `None`。
    ///
    /// 未知编号**必须**被显式拒绝：将来新增的类型会被旧端误解，
    /// 所以解码路径靠这个函数 fail-closed。
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::ListCredentials),
            1 => Some(Self::GetPassword),
            2 => Some(Self::GetTotp),
            3 => Some(Self::PasskeyCreate),
            4 => Some(Self::PasskeyGet),
            5 => Some(Self::SavePassword),
            6 => Some(Self::RiskCheck),
            7 => Some(Self::RevokePasskeyRef),
            8 => Some(Self::Recover),
            9 => Some(Self::AuthQuery),
            10 => Some(Self::UseNativeResponse),
            _ => None,
        }
    }

    /// 跨仓对照用的名称：**与扩展侧 `MSG` 表的键同名**。
    ///
    /// 固定向量文件里的 `extension_message_types` 段用的就是这套键名，
    /// 于是「编号跨仓一致」是机器可查的。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ListCredentials => "LIST_CREDENTIALS",
            Self::GetPassword => "GET_PASSWORD",
            Self::GetTotp => "GET_TOTP",
            Self::PasskeyCreate => "PASSKEY_CREATE",
            Self::PasskeyGet => "PASSKEY_GET",
            Self::SavePassword => "SAVE_PASSWORD",
            Self::RiskCheck => "RISK_CHECK",
            Self::RevokePasskeyRef => "REVOKE_PASSKEY_REF",
            Self::Recover => "RECOVER",
            Self::AuthQuery => "AUTH_QUERY",
            Self::UseNativeResponse => "USE_NATIVE_RESPONSE",
        }
    }

    /// 是否是「回退到浏览器原生响应」的信号。
    ///
    /// 契约 §5.3：仅 `type = 10` 是回退信号，其余 10 种都不是。
    #[must_use]
    pub const fn is_native_response_fallback(self) -> bool {
        matches!(self, Self::UseNativeResponse)
    }
}

impl core::fmt::Display for MessageType {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}
