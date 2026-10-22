//! 手写最小 CBOR 编码器。
//!
//! 契约 §3 明确要求：本仓无 CBOR 依赖 ⇒ **手写最小 CBOR 编码**
//! （只支持本卡用到的 map / bytes / text / int）⇒ **不引入通用 CBOR 库**
//! （缩小依赖面 + 避免 canonicalization 分歧）。
//!
//! 支持的主类型（定长 / 短格式 + bytes 的单字节长度扩展）：
//!
//! | 值 | 头字节 | 说明 |
//! |---|---|---|
//! | unsigned int | `0x00 \| len`（len < 24） | 0..=23 |
//! | bytes（短） | `0x40 \| len`（len < 24） | |
//! | bytes（1 字节长度） | `0x58` + 1 字节长度 | 24..=255 |
//! | text（短） | `0x60 \| len`（len < 24） | |
//! | map | `0xA0 \| len`（len < 24） | len = 项数 |
//!
//! ⚠️ **不定长 bytes 头极易写错**：`authData` 长度 = 132 + credIdLen；
//! credId 为 16 字节时 = 148 字节 ⇒ **> 24 ⇒ 必须用 `0x58` + 1 字节长度**。
//! 测试逐字节钉死这一点。

use crate::error::Error;

/// CBOR 值。
///
/// 只支持契约用到的四种：整数、字节串、文本串、map。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborValue {
    /// 无符号整数。
    Uint(u64),
    /// 字节串。
    Bytes(Vec<u8>),
    /// 文本串（UTF-8）。
    Text(String),
    /// 键值对序列（保持插入顺序 ⇒ 编码确定）。
    Map(Vec<(CborValue, CborValue)>),
}

impl CborValue {
    /// 构造文本串。
    pub fn text(value: &str) -> Self {
        Self::Text(value.to_owned())
    }

    /// 构造字节串。
    pub fn bytes(value: &[u8]) -> Self {
        Self::Bytes(value.to_vec())
    }
}

/// 把一个值编码成 CBOR 字节。
pub fn encode(value: &CborValue) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

fn encode_into(value: &CborValue, out: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        CborValue::Uint(n) => {
            // 只支持 0..=23（契约用不到更大的整数）。
            let n = u8::try_from(*n).map_err(|_| Error::CborEncode)?;
            if n >= 24 {
                return Err(Error::CborEncode);
            }
            out.push(n);
            Ok(())
        }
        CborValue::Bytes(bytes) => {
            write_head(out, 0x40, bytes.len())?;
            out.extend_from_slice(bytes);
            Ok(())
        }
        CborValue::Text(text) => {
            let bytes = text.as_bytes();
            write_head(out, 0x60, bytes.len())?;
            out.extend_from_slice(bytes);
            Ok(())
        }
        CborValue::Map(entries) => {
            let count = u8::try_from(entries.len()).map_err(|_| Error::CborEncode)?;
            if count >= 24 {
                return Err(Error::CborEncode);
            }
            out.push(0xa0 | count);
            for (key, val) in entries {
                encode_into(key, out)?;
                encode_into(val, out)?;
            }
            Ok(())
        }
    }
}

/// 写主类型头 + 长度。
///
/// `major` 是主类型位（0x40 = bytes，0x60 = text）。
fn write_head(out: &mut Vec<u8>, major: u8, len: usize) -> Result<(), Error> {
    if len < 24 {
        out.push(major | len as u8);
    } else if len <= u8::MAX as usize {
        // ⚠️ bytes 的 1 字节长度扩展：0x58 + len。
        // text 的对应扩展是 0x78，本卡用不到（所有文本 < 24 字节）。
        if major != 0x40 {
            return Err(Error::CborEncode);
        }
        out.push(0x58);
        out.push(len as u8);
    } else {
        return Err(Error::CborEncode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_map_is_a0() {
        assert_eq!(encode(&CborValue::Map(vec![])).unwrap(), vec![0xa0]);
    }

    #[test]
    fn three_entry_map_is_a3() {
        let v = CborValue::Map(vec![
            (CborValue::text("a"), CborValue::Uint(1)),
            (CborValue::text("b"), CborValue::Uint(2)),
            (CborValue::text("c"), CborValue::Uint(3)),
        ]);
        assert_eq!(encode(&v).unwrap()[0], 0xa3);
    }

    #[test]
    fn short_text_header_is_0x60_len() {
        assert_eq!(
            encode(&CborValue::text("none")).unwrap(),
            b"\x64none".to_vec()
        );
    }

    #[test]
    fn short_bytes_header_is_0x40_len() {
        assert_eq!(
            encode(&CborValue::bytes(&[0xaa, 0xbb])).unwrap(),
            vec![0x42, 0xaa, 0xbb]
        );
    }

    #[test]
    fn long_bytes_uses_0x58_with_one_length_byte() {
        let data = vec![0x5au8; 148];
        let out = encode(&CborValue::bytes(&data)).unwrap();
        assert_eq!(out.len(), 150);
        assert_eq!(out[0], 0x58);
        assert_eq!(out[1], 148);
    }

    #[test]
    fn bytes_of_exactly_24_use_extended_header() {
        let data = vec![0x00u8; 24];
        let out = encode(&CborValue::bytes(&data)).unwrap();
        assert_eq!(out[0], 0x58);
        assert_eq!(out[1], 24);
    }

    #[test]
    fn bytes_of_23_use_short_header() {
        let data = vec![0x00u8; 23];
        let out = encode(&CborValue::bytes(&data)).unwrap();
        assert_eq!(out[0], 0x40 | 23);
    }
}
