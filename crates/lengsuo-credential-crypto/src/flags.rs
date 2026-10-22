//! authData 的标志位。
//!
//! 契约 §2.1：
//!
//! | 位 | 值 | 含义 |
//! |---|---|---|
//! | UP | 0x01 | User Present |
//! | UV | 0x04 | User Verified |
//! | BE | 0x08 | Backup Eligibility |
//! | BS | 0x10 | Backup State |
//! | **AT** | **0x40** | Attested credential data included |
//! | **ED** | **0x80** | Extension data included |
//!
//! ⚠️ **AT 与 ED 的值不同**：AT = 0x40，ED = 0x80。
//! 把 ED 误写成 0x40 会让「有扩展数据」与「有认证凭据数据」不可区分 ⇒ 本模块
//! 用**互不相同的常量**表达两者，并在测试里钉死。

/// User Present：本次操作经过用户在场确认。
pub const FLAG_UP: u8 = 0x01;
/// User Verified：本次操作经过用户身份验证。
pub const FLAG_UV: u8 = 0x04;
/// Backup Eligibility：凭据可被备份。
pub const FLAG_BE: u8 = 0x08;
/// Backup State：凭据当前处于已备份状态。
pub const FLAG_BS: u8 = 0x10;
/// Attested credential data included：authData 尾部带 attested credential data。
pub const FLAG_AT: u8 = 0x40;
/// Extension data included：authData 尾部带扩展数据。
pub const FLAG_ED: u8 = 0x80;

/// 托管模式默认标志位：`UP | UV | AT` = 0x45。
pub const MANAGED_DEFAULT: u8 = FLAG_UP | FLAG_UV | FLAG_AT;

/// 全部已定义标志位的掩码（未定义位必须为 0）。
pub const KNOWN_MASK: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT | FLAG_ED;

/// 托管模式的默认标志位。
pub fn managed_default() -> u8 {
    MANAGED_DEFAULT
}

/// 校验标志位：只允许已定义的位被置起。
///
/// 未定义位非 0 ⇒ 拒绝（不猜、不静默清零）。
pub fn validate(flags: u8) -> Result<(), FlagsError> {
    if flags & !KNOWN_MASK != 0 {
        return Err(FlagsError::UnknownBits {
            bits: flags & !KNOWN_MASK,
        });
    }
    Ok(())
}

/// 标志位校验失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlagsError {
    /// 置起了协议未定义的位。
    #[error("标志位含未定义位 {bits:#04x}")]
    UnknownBits {
        /// 被置起的未定义位。
        bits: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_default_is_0x45() {
        assert_eq!(MANAGED_DEFAULT, 0x45);
        assert_eq!(managed_default(), 0x45);
    }

    #[test]
    fn at_and_ed_are_distinct() {
        assert_eq!(FLAG_AT, 0x40);
        assert_eq!(FLAG_ED, 0x80);
        assert_ne!(FLAG_AT, FLAG_ED);
    }

    #[test]
    fn known_mask_covers_all_defined_bits() {
        assert_eq!(KNOWN_MASK, 0x01 | 0x04 | 0x08 | 0x10 | 0x40 | 0x80);
        assert_eq!(KNOWN_MASK, 0xdd);
    }

    #[test]
    fn validate_rejects_undefined_bits() {
        assert!(validate(MANAGED_DEFAULT).is_ok());
        assert!(validate(0x00).is_ok());
        // 全部已定义位都置起 ⇒ 仍然合法。
        assert!(validate(KNOWN_MASK).is_ok());
        // 0x02 是未定义位（0x01 UP 已定义，0x04 UV 已定义 ⇒ 0x02 空缺）。
        assert_eq!(validate(0x02), Err(FlagsError::UnknownBits { bits: 0x02 }));
        // 0xff 含未定义位 ⇒ 拒绝。
        assert_eq!(validate(0xff), Err(FlagsError::UnknownBits { bits: 0x22 }));
    }
}
