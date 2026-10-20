//! TCP 选项区原语：MSS 选项的构造与解析。
//!
//! 主动打开方向必须按接口 MTU 通告 MSS（RFC 9293 §2.3 的 MSS 选项，kind=2、
//! length=4、2 字节 MSS 值）。本模块是纯字节层：不构造 IP 头、不发报文，也不
//! 校验 TCP 状态。
//!
//! 解析一律 fail-closed：选项区长度非法、未知 kind 的 length 越界、拿到截断的
//! 选项时一律返回 `None`，绝不越界读取、绝不 panic。

/// MSS 选项的 kind（RFC 9293 §2.3）。
pub const MSS_OPTION_KIND: u8 = 2;
/// MSS 选项的字节长度。
pub const MSS_OPTION_LEN: usize = 4;

/// 构造 MSS 选项（kind=2、length=4、2 字节 MSS 值），占满 4 字节对齐。
pub fn mss_option(mss: u16) -> Vec<u8> {
    vec![
        MSS_OPTION_KIND,
        MSS_OPTION_LEN as u8,
        u8::try_from(mss >> 8).unwrap_or(0),
        u8::try_from(mss & 0xff).unwrap_or(0),
    ]
}

/// 从 TCP 选项区解析对端通告的 MSS；没有该选项时返回 `None`。
///
/// 选项区格式：kind、length、value…；遇到 kind=0（EOL）或 length 非法即停止，
/// 绝不越界读取。
pub fn parse_mss_option(options: &[u8]) -> Option<u16> {
    let mut index = 0usize;
    while index < options.len() {
        let kind = options[index];
        if kind == 0 {
            return None;
        }
        if kind == 1 {
            index += 1;
            continue;
        }
        let length = usize::from(*options.get(index + 1)?);
        if length < 2 || index + length > options.len() {
            return None;
        }
        if kind == MSS_OPTION_KIND {
            if length != MSS_OPTION_LEN {
                return None;
            }
            let hi = *options.get(index + 2)?;
            let lo = *options.get(index + 3)?;
            return Some(u16::from_be_bytes([hi, lo]));
        }
        index += length;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mss_option_round_trip() {
        let option = mss_option(1460);
        assert_eq!(option.len(), 4);
        assert_eq!(option[0], MSS_OPTION_KIND);
        assert_eq!(option[1], MSS_OPTION_LEN as u8);
        assert_eq!(parse_mss_option(&option), Some(1460));
        // 无该选项 / 非法长度 / 截断都返回 None，不 panic。
        assert_eq!(parse_mss_option(&[]), None);
        assert_eq!(parse_mss_option(&[2, 3, 0, 5]), None);
        assert_eq!(parse_mss_option(&[2]), None);
        assert_eq!(parse_mss_option(&[1, 2, 0]), None);
        // EOL 之后的内容不解析。
        assert_eq!(parse_mss_option(&[0, 2, 4, 0]), None);
        // 未知 kind 按 length 跳过。
        assert_eq!(parse_mss_option(&[8, 2, 0, 0]), None);
    }
}
