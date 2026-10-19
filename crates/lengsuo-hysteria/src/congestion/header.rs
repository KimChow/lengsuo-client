//! `Hysteria-CC-RX` / `Hysteria-CC-TX` 头的编解码。
//!
//! 参考常量（Xray `transport/internet/hysteria/config.go`）：
//! ```text
//! CommonHeaderCCRX = "Hysteria-CC-RX"
//! ```
//! 参考只在协商路径上使用 **RX** 一个头（`hub.go` / `dialer.go`），
//! 本卡任务书同时点名 RX 与 TX，故两者都提供，且 **TX 与 RX 编解码同构**
//! （同一 `u64` 十进制字符串 + `"auto"` 哨兵），保证与参考 RX 逐字节一致；
//! TX 在参考中未出现，属本仓补充面，已在报告中登记为「参考未覆盖」。
//!
//! 取值语义（对齐参考 `hub.go` 行 166/193-203 与 `dialer.go` 行 274/304-313）：
//! - 服务端响应头写 `strconv.FormatUint(BrutalDown, 10)` —— 即**纯十进制 u64**；
//! - 客户端请求头同样写 `FormatUint(BrutalDown, 10)`；
//! - 客户端读服务端响应头时额外识别哨兵 `"auto"`（`serverAuto == "auto"`
//!   即走 BBR 分支）；
//! - 解析用 `strconv.ParseUint(s, 10, 64)` 且**忽略错误**（`_`）——
//!   即非法值在参考中退化为 `0`（= 未指定）。本卡要求 fail-closed，
//!   故 `decode` 返回 `Result`，把「非法」与「0」严格区分；调用方若需
//!   复刻参考的宽容语义，用 `decode_or_unset`，并在报告中说明。

use super::bandwidth::Bandwidth;

/// 请求/响应共用的 RX 头名（逐字节对齐参考常量）。
pub const HEADER_CC_RX: &str = "Hysteria-CC-RX";
/// TX 头名（参考未出现，本仓对称补充）。
pub const HEADER_CC_TX: &str = "Hysteria-CC-TX";
/// 客户端识别服务端「自动」的哨兵值（对齐 `dialer.go` `serverAuto == "auto"`）。
pub const CC_AUTO: &str = "auto";

/// 头值解析失败原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// 既不是 `"auto"` 也不是十进制 u64。
    #[error("CC 头值非法（期望 \"auto\" 或十进制 u64）：{value:?}")]
    InvalidValue { value: String },

    /// 十进制数值超出 u64（对齐 `ParseUint(s, 10, 64)` 的越界拒绝）。
    #[error("CC 头值超出 u64：{value:?}")]
    OutOfRange { value: String },
}

/// 解码后的 CC 头。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcHeader {
    /// 对端声明「自动」（参考 `"auto"` 哨兵）。
    Auto,
    /// 对端声明的字节/秒（可为 0 = 未指定）。
    Bps(Bandwidth),
}

impl CcHeader {
    /// 按参考 `_ := strconv.ParseUint(...)` 的宽容语义解码：
    /// 任何非法值退化为 `Bps(0)`（等价参考中错误被丢弃）。
    ///
    /// **仅**用于需要严格复刻参考「非法即 0」行为的调用点；协商判据
    /// 本身仍应使用 `decode` 以 fail-closed。
    pub fn decode_or_unset(value: &str) -> CcHeader {
        Self::decode(value).unwrap_or(CcHeader::Bps(Bandwidth(0)))
    }

    /// 严格解码：`"auto"` → `Auto`；十进制 u64 → `Bps`；其余 → `Err`。
    ///
    /// 注意参考的 `strings.ToLower` 并不作用于该头（只在 `Bandwidth.Bps()`
    /// 内部对配置字符串做），但 HTTP 头名大小写不敏感、值大小写敏感；
    /// 这里对 `"auto"` 做精确匹配，与参考 `== "auto"` 一致。
    pub fn decode(value: &str) -> Result<CcHeader, HeaderError> {
        if value == CC_AUTO {
            return Ok(CcHeader::Auto);
        }
        // 对齐 strconv.ParseUint(s, 10, 64)：仅十进制、无符号、无空白容忍。
        if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
            match value.parse::<u64>() {
                Ok(v) => return Ok(CcHeader::Bps(Bandwidth(v))),
                Err(_) => {
                    return Err(HeaderError::OutOfRange {
                        value: value.to_string(),
                    })
                }
            }
        }
        Err(HeaderError::InvalidValue {
            value: value.to_string(),
        })
    }
}

/// 编码 CC 头值：`Bandwidth` → 十进制 u64 字符串。
///
/// 对齐参考 `strconv.FormatUint(BrutalDown, 10)`：无前导零、`0` 编码为 `"0"`。
pub fn encode(bw: Bandwidth) -> String {
    bw.bps().to_string()
}

/// 编码 `"auto"` 哨兵。
pub fn encode_auto() -> String {
    CC_AUTO.to_string()
}
