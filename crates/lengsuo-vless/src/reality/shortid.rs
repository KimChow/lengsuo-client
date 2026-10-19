//! REALITY 短 ID 解析与匹配。
//!
//! 参考 `infra/conf/transport_internet.go`（客户端，`tls.go:949-955` 附近）：
//!
//! ```go
//! if len(c.ShortId) > 16 {
//!     return nil, errors.New(`too long "shortId": `, c.ShortId)
//! }
//! config.ShortId = make([]byte, 8)
//! if _, err = hex.Decode(config.ShortId, []byte(c.ShortId)); err != nil {
//!     return nil, errors.New(`invalid "shortId": `, c.ShortId)
//! }
//! ```
//!
//! 服务端 `transport_internet.go:888-893` 对 `shortIds` 数组项同构：
//! 先 `hex.DecodeString` 到 8 字节缓冲，再 `len(decoded) > 8` 报
//! `too long "shortIds"`。
//!
//! ## 关键语义（逐条对齐）
//!
//! 1. **长度上限以「十六进制字符数」计**：客户端 `len(c.ShortId) > 16` 才报错，
//!    即最多 16 个 hex 字符 = 8 字节。服务端等价地判解码后 > 8 字节。
//! 2. **输出定长 8 字节**：先 `make([]byte,8)` 全 0，再 `hex.Decode` 就地写。
//!    Go 的 `hex.Decode` 只写「解码出的字节数」，尾部**保持 0**。所以
//!    `"ab"` → `[0xab,0,0,0,0,0,0,0]`，是左对齐高位补零，不是右对齐。
//! 3. **奇数长度 hex 是错误**：`hex.Decode` 遇 `ErrLength` 返回错误
//!    （Go 的 `encoding/hex` 拒绝奇数字符数）。
//! 4. **空串合法**：`hex.Decode` 对空输入返回 `(0,nil)`，得到全 0 的 8 字节，
//!    即「空短 ID」== 零填充，**不是**「无短 ID」。客户端 `config.ShortId`
//!    恒为这 8 字节，服务端 `ShortIds[zero]` 命中与否取决于服务端配置。
//! 5. **不校验 hex 之外的内容**（大小写均可，`hex.Decode` 接受 `A-F`/`a-f`）。

use thiserror::Error;

/// 短 ID 的最大十六进制字符数（参考：客户端 `len > 16` 报错）。
pub const MAX_HEX_LEN: usize = 16;

/// 短 ID 展开后的定长字节数。
pub const SHORT_ID_LEN: usize = 8;

/// 短 ID 解析失败。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShortIdError {
    /// 参考客户端：`too long "shortId"`。
    #[error("REALITY: too long \"shortId\": {len} hex chars (max {MAX_HEX_LEN})")]
    TooLong { len: usize },
    /// 参考：`invalid "shortId"`（非 hex 字符，或 Go `hex.Decode` 的 `ErrLength`）。
    #[error("REALITY: invalid \"shortId\"")]
    Invalid,
}

/// 解析短 ID 字符串，产出左对齐、高位补零的 8 字节。
///
/// 语义逐条对齐参考（见模块文档）。空串返回全 0，不报错。
pub fn parse_short_id(s: &str) -> Result<[u8; SHORT_ID_LEN], ShortIdError> {
    let bytes = s.as_bytes();
    // 对齐参考：先判字符数上限，再解码。空串在此通过（0 <= 16）。
    if bytes.len() > MAX_HEX_LEN {
        return Err(ShortIdError::TooLong { len: bytes.len() });
    }
    // 对齐 Go `hex.Decode` 的 `ErrLength`：奇数长度直接失败。
    if !bytes.len().is_multiple_of(2) {
        return Err(ShortIdError::Invalid);
    }
    // 对齐 `make([]byte,8)` + 就地写入：尾部保持 0。
    let mut out = [0u8; SHORT_ID_LEN];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// 单字符 hex 值。`None` 表示非法字符（参考的 `hex.InvalidByteError`）。
fn hex_val(b: u8) -> Result<u8, ShortIdError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ShortIdError::Invalid),
    }
}

/// 服务端短 ID 匹配：参考 `config.ShortIds` 是 `map[[8]byte]bool`，
/// 用**解密后明文 `[8..16)` 的前 8 字节**做键查表（`tls.go:251-260`）。
///
/// 注意：客户端填进 `SessionId[8..]` 的是 24 字节（8 字节短 ID + 16 字节零），
/// 服务端只取前 8 字节，因此本函数只比较 `[u8; 8]`，多出的字节不参与。
///
/// 比较用 [`subtle::ConstantTimeEq`]：短 ID 本身不是秘密（会明文出现在
/// ClientHello 的 AEAD 明文里），但服务端配置侧的匹配结果不应通过时序泄漏
/// 「前几字节对了」，故仍按常量时间比较。
pub fn short_id_matches(configured: &[[u8; SHORT_ID_LEN]], client: &[u8; SHORT_ID_LEN]) -> bool {
    let mut hit = 0u8;
    for c in configured {
        hit |= c.ct_eq(client).unwrap_u8();
    }
    hit == 1
}

use subtle::ConstantTimeEq;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_all_zero_not_error() {
        // 参考：hex.Decode 空串 → (0, nil)，得到全 0 的 8 字节。
        assert_eq!(parse_short_id("").unwrap(), [0u8; 8]);
    }

    #[test]
    fn short_hex_is_left_aligned_zero_padded() {
        // 参考：make([]byte,8) 后只写解码出的字节，尾部保持 0。
        assert_eq!(parse_short_id("ab").unwrap(), [0xab, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            parse_short_id("0123456789ab").unwrap(),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0]
        );
    }

    #[test]
    fn full_16_hex_fills_all_eight() {
        assert_eq!(
            parse_short_id("0123456789abcdef").unwrap(),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    #[test]
    fn uppercase_hex_accepted() {
        assert_eq!(
            parse_short_id("ABCDEF").unwrap(),
            [0xab, 0xcd, 0xef, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn too_long_is_rejected() {
        // 17 hex 字符 → 参考 `len > 16` 报 too long。
        let s = "0".repeat(MAX_HEX_LEN + 1);
        assert_eq!(parse_short_id(&s), Err(ShortIdError::TooLong { len: 17 }));
        // 长度上限按字符数（奇数 17 也不该走 Invalid，参考先判长度）。
        // 15 个奇数字符：长度未超上限，落到 Go `hex.Decode` 的 `ErrLength`
        // → `invalid "shortId"`（参考先判长度、再解码）。
        assert_eq!(
            parse_short_id("0123456789abcde"),
            Err(ShortIdError::Invalid)
        );
    }

    #[test]
    fn odd_length_rejected() {
        assert_eq!(parse_short_id("a"), Err(ShortIdError::Invalid));
        assert_eq!(parse_short_id("abc"), Err(ShortIdError::Invalid));
    }

    #[test]
    fn non_hex_rejected() {
        assert_eq!(parse_short_id("zz"), Err(ShortIdError::Invalid));
        assert_eq!(parse_short_id("ab cd"), Err(ShortIdError::Invalid));
        assert_eq!(parse_short_id("ab_cd"), Err(ShortIdError::Invalid));
        assert_eq!(parse_short_id("ab\n"), Err(ShortIdError::Invalid));
        // 非 ASCII 也不放行（按字节判，UTF-8 多字节必然非 hex）。
        assert_eq!(parse_short_id("é"), Err(ShortIdError::Invalid));
    }

    #[test]
    fn length_hex_matrix() {
        // 长度 × 合法性矩阵：0..=16 偶数全合法，17+ 全 TooLong，奇数全 Invalid。
        for n in 0..=16usize {
            let s = "0".repeat(n);
            let got = parse_short_id(&s);
            if n % 2 == 0 {
                assert!(got.is_ok(), "len {n} should parse");
                assert_eq!(got.unwrap(), [0u8; 8], "len {n} all-zero hex");
            } else {
                assert_eq!(got, Err(ShortIdError::Invalid), "len {n} odd");
            }
        }
        for n in [17usize, 18, 100] {
            let s = "0".repeat(n);
            assert_eq!(
                parse_short_id(&s),
                Err(ShortIdError::TooLong { len: n }),
                "len {n} too long"
            );
        }
    }

    #[test]
    fn match_is_exact_eight_bytes() {
        let a = parse_short_id("ab").unwrap();
        let b = parse_short_id("ab00").unwrap();
        // "ab" 与 "ab00" 展开后都是 [0xab,0,...]，服务端按 8 字节键匹配 → 相等。
        assert!(short_id_matches(&[a], &b));
        assert!(short_id_matches(&[[0u8; 8]], &parse_short_id("").unwrap()));
        assert!(!short_id_matches(&[a], &parse_short_id("cd").unwrap()));
        assert!(!short_id_matches(&[], &a));
    }

    #[test]
    fn match_scans_all_configured_entries() {
        let entries = [
            parse_short_id("11").unwrap(),
            parse_short_id("22").unwrap(),
            parse_short_id("33").unwrap(),
        ];
        assert!(short_id_matches(&entries, &parse_short_id("33").unwrap()));
        assert!(!short_id_matches(&entries, &parse_short_id("44").unwrap()));
    }
}
