//! attestationObject（`fmt = "none"`）。
//!
//! 契约 §3：
//!
//! ```text
//! attestationObject = CBOR {
//!   "fmt":    "none",
//!   "attStmt": {},
//!   "authData": <authData 字节>
//! }
//! ```
//!
//! | 约束 | 依据 |
//! |---|---|
//! | `fmt` 必须是 `"none"` | 托管模式不做真实证明 |
//! | `attStmt` 必须是**空 map** | none 格式无证明语句 |
//! | `authData` 的 aaguid **必须全零** | 见 [`crate::authdata::AAGUID`] |
//! | `attestationObject` 是 **CBOR**（不是裸 JSON） | WebAuthn 规范 |
//!
//! ⚠️ `authData` 长度 = 132 + credIdLen；credId 为 16 字节时 = 148 ⇒ **> 24**
//! ⇒ CBOR 里的 bytes 头必须是 **`0x58` + 1 字节长度**，不是 `0x58` 短头。

use crate::cbor::{encode, CborValue};
use crate::error::Error;

/// 证明格式：托管模式固定为 `"none"`。
pub const FMT_NONE: &str = "none";

/// 构造 attestationObject 的 CBOR 字节。
///
/// 键顺序固定为 `fmt` / `attStmt` / `authData` ⇒ 编码结果确定。
pub fn build(auth_data: &[u8]) -> Result<Vec<u8>, Error> {
    let value = CborValue::Map(vec![
        (CborValue::text("fmt"), CborValue::text(FMT_NONE)),
        (CborValue::text("attStmt"), CborValue::Map(vec![])),
        (CborValue::text("authData"), CborValue::bytes(auth_data)),
    ]);
    encode(&value)
}

/// 从 attestationObject 里取出 authData 段（只解析本层需要的最小结构）。
///
/// 只支持顶层是 3 项 map、且 `authData` 是 bytes 的形态 ⇒ 遇到别的形态一律报错
/// （不猜、不尽力解析）。
pub fn auth_data_of(attestation_object: &[u8]) -> Result<&[u8], Error> {
    let mut reader = Reader::new(attestation_object);
    let count = reader.read_map_header()?;
    if count != 3 {
        return Err(Error::InvalidLength {
            expected: 3,
            actual: count,
        });
    }
    let mut found = None;
    for _ in 0..count {
        let key = reader.read_text()?;
        match key {
            b"fmt" => {
                let value = reader.read_text()?;
                if value != FMT_NONE.as_bytes() {
                    return Err(Error::InvalidLength {
                        expected: FMT_NONE.len(),
                        actual: value.len(),
                    });
                }
            }
            b"attStmt" => {
                let items = reader.read_map_header()?;
                if items != 0 {
                    return Err(Error::InvalidLength {
                        expected: 0,
                        actual: items,
                    });
                }
            }
            b"authData" => found = Some(reader.read_bytes()?),
            _ => return Err(Error::CborEncode),
        }
    }
    found.ok_or(Error::CborEncode)
}

/// 最小 CBOR 读取器（只支持本层产出的形态）。
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.pos).ok_or(Error::CborEncode)?;
        self.pos += 1;
        Ok(b)
    }

    /// map 的项数（只支持短格式）。
    fn read_map_header(&mut self) -> Result<usize, Error> {
        let head = self.byte()?;
        // ⚠️ 不能用 `head & 0xe0` 判主类型：0x58 & 0xe0 == 0x40（0x58 是
        // 「bytes + 1 字节长度」）。这里用**区间**判。
        if !(0xa0..=0xb7).contains(&head) {
            return Err(Error::CborEncode);
        }
        Ok((head & 0x1f) as usize)
    }

    /// 文本串（只支持短格式）。
    fn read_text(&mut self) -> Result<&'a [u8], Error> {
        let head = self.byte()?;
        if !(0x60..=0x77).contains(&head) {
            return Err(Error::CborEncode);
        }
        let len = (head & 0x1f) as usize;
        let end = self.pos + len;
        let slice = self.buf.get(self.pos..end).ok_or(Error::CborEncode)?;
        self.pos = end;
        Ok(slice)
    }

    /// 字节串（短格式 + 1 字节长度扩展）。
    fn read_bytes(&mut self) -> Result<&'a [u8], Error> {
        let head = self.byte()?;
        let len = if (0x40..=0x57).contains(&head) {
            (head & 0x1f) as usize
        } else if head == 0x58 {
            self.byte()? as usize
        } else {
            return Err(Error::CborEncode);
        };
        let end = self.pos + len;
        let slice = self.buf.get(self.pos..end).ok_or(Error::CborEncode)?;
        self.pos = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authdata;
    use crate::cose::cose_key;
    use crate::flags;

    fn sample_auth_data() -> Vec<u8> {
        authdata::build(
            &[0x11; 32],
            flags::MANAGED_DEFAULT,
            7,
            &[0x22; authdata::CREDENTIAL_ID_LEN],
            &cose_key(&[0x33; 32], &[0x44; 32]),
        )
        .unwrap()
    }

    #[test]
    fn cbor_bytes_are_exact() {
        let auth = sample_auth_data();
        let obj = build(&auth).unwrap();
        // map(3) { "fmt": "none", "attStmt": {}, "authData": bytes(148) }
        assert_eq!(obj[0], 0xa3);
        // "fmt"（3 字节文本）⇒ 0x63 + "fmt"
        assert_eq!(&obj[1..5], b"\x63fmt");
        // "none"（4 字节文本）⇒ 0x64 + "none"
        assert_eq!(&obj[5..10], b"\x64none");
        // "attStmt"（7 字节文本）⇒ 0x67 + "attStmt"
        assert_eq!(&obj[10..18], b"\x67attStmt");
        // attStmt 是空 map
        assert_eq!(obj[18], 0xa0);
        // "authData"（8 字节文本）⇒ 0x68 + "authData"
        assert_eq!(&obj[19..28], b"\x68authData");
        // ⚠️ bytes(148) 走不定长头：0x58 + 0x94
        assert_eq!(obj[28], 0x58);
        assert_eq!(obj[29], 148);
        assert_eq!(obj.len(), 30 + 148);
    }

    #[test]
    fn att_stmt_is_an_empty_map() {
        let obj = build(&sample_auth_data()).unwrap();
        let idx = obj
            .windows(7)
            .position(|w| w == b"attStmt")
            .expect("attStmt 键存在");
        assert_eq!(obj[idx + 7], 0xa0);
    }

    #[test]
    fn auth_data_round_trips() {
        let auth = sample_auth_data();
        let obj = build(&auth).unwrap();
        assert_eq!(auth_data_of(&obj).unwrap(), auth.as_slice());
    }

    #[test]
    fn unknown_format_is_rejected() {
        let value = CborValue::Map(vec![
            (CborValue::text("fmt"), CborValue::text("packed")),
            (CborValue::text("attStmt"), CborValue::Map(vec![])),
            (CborValue::text("authData"), CborValue::bytes(&[0u8; 4])),
        ]);
        let obj = encode(&value).unwrap();
        assert!(auth_data_of(&obj).is_err());
    }
}
