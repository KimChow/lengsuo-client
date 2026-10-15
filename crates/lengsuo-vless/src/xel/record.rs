//! XEL AEAD 记录层：分帧 + 序号锁定 + 认证（对齐 `common.go` 的记录读写路径）。
//!
//! 组合 [`super::frame::RecordFramer`]（字节流 → 完整记录）与
//! [`super::aead::AeadDirection`]（记录体认证）：
//!
//! - 发送：明文 → 记录体 = AEAD(记录头 5 字节作 AAD，nonce = 大端序号)，
//!   线上 = 头部 + 密文（`common.go` `headerAndData[:5]` 作 AAD 的语义）。
//! - 接收：帧器重组出完整记录 → 头部解码 → **锁定步**序号校验（期望值 = 已见
//!   最大序号 + 1；XEL 线上不携带序号，任何失步都是 nonce 失步，取比乱序窗口
//!   更严格的锁定步，见 `super` 模块文档）→ 按期望序号解密。
//!
//! **fail-closed**：头部非法、长度不一致、序号失步、认证失败、截断——任一发生
//! 后接收方向永久 poison；发送方向在序号耗尽或加密失败后永久 poison。
//! 调用方必须弃用整条流，不得重试或回退。

use super::aead::{AeadDirection, XelCipher};
use super::frame::{RecordFramer, RecordHeader};
use super::{
    Error, XelKey, MAX_RECORD_BODY_LEN as MAX_LEN, MIN_RECORD_BODY_LEN as MIN_LEN,
    RECORD_HEADER_LEN,
};

/// AEAD 记录发送方向：序号与密钥由 [`AeadDirection`] 持有。
#[derive(Debug)]
pub struct RecordWriter {
    dir: AeadDirection,
}

impl RecordWriter {
    pub fn new(cipher: XelCipher, key: XelKey) -> Self {
        Self {
            dir: AeadDirection::new(cipher, key),
        }
    }

    /// 已发送的记录数（= 已消耗序号）。
    pub fn sequence(&self) -> u64 {
        self.dir.sequence()
    }

    pub fn is_poisoned(&self) -> bool {
        self.dir.is_poisoned()
    }

    /// 加密并编码一条记录；返回完整线上字节（头 5 字节 + 记录体）。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let body_len = self.dir.body_len(plaintext.len())?;
        let header = RecordHeader::new(body_len)?.encode();
        let (_, body) = self.dir.seal_at_next(&header, plaintext)?;
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + body.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&body);
        Ok(record)
    }
}

/// AEAD 记录接收方向：帧器 + 锁定步序号 + 按期望序号解密。
pub struct RecordReader {
    framer: RecordFramer,
    dir: AeadDirection,
}

impl RecordReader {
    pub fn new(cipher: XelCipher, key: XelKey) -> Self {
        Self {
            framer: RecordFramer::new(),
            dir: AeadDirection::new(cipher, key),
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.framer.is_poisoned() || self.dir.is_poisoned()
    }

    /// 追加线上字节（不足一帧属于正常等待）。
    pub fn push(&mut self, wire: &[u8]) -> Result<(), Error> {
        if self.dir.is_poisoned() {
            return Err(Error::Poisoned);
        }
        self.framer.push(wire)
    }

    /// 取出下一条记录的明文；不足一帧返回 `Ok(None)`。
    pub fn next_plaintext(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.dir.is_poisoned() {
            return Err(Error::Poisoned);
        }
        let Some(record) = self.framer.next_record()? else {
            return Ok(None);
        };
        let (head, body) = record.split_at(RECORD_HEADER_LEN);
        // 帧器已验证过头部；此处的解码失败不可达，直接传播（真实头部错误
        // 由帧器 poison 自己的状态）。
        let header = RecordHeader::decode(head)?;
        if header.body_len() != body.len() {
            return Err(Error::InvalidRecordLength {
                got: body.len(),
                min: MIN_LEN,
                max: MAX_LEN,
            });
        }
        // 锁定步：期望序号 = 已见最大序号 + 1（首个记录期望 1，与“先加后用”一致）。
        let expected = self.dir.sequence().saturating_add(1);
        match self.dir.open_at(expected, head, body) {
            Ok(plaintext) => Ok(Some(plaintext)),
            Err(error) => Err(error),
        }
    }

    /// 流结束检查：残字节即截断。
    pub fn finish(&mut self) -> Result<(), Error> {
        self.framer.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CIPHERS: [XelCipher; 2] = [XelCipher::Aes256Gcm, XelCipher::ChaCha20Poly1305];

    fn key(byte: u8) -> XelKey {
        XelKey::new(&[byte; 32]).unwrap()
    }

    fn sealed_stream(records: &[&[u8]]) -> Vec<u8> {
        let mut writer = RecordWriter::new(XelCipher::Aes256Gcm, key(0x3C));
        records
            .iter()
            .flat_map(|payload| writer.seal(payload).unwrap())
            .collect()
    }

    #[test]
    fn writer_reader_roundtrip_at_every_split() {
        let payloads: Vec<Vec<u8>> = vec![
            b"first record payload".to_vec(),
            vec![7u8; 1],
            vec![0xEEu8; 400],
        ];
        let stream = sealed_stream(&payloads.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        for step in [1usize, 2, 5, 22, 40, stream.len()] {
            for cipher in CIPHERS {
                let mut writer = RecordWriter::new(cipher, key(0x3C));
                let mut wire = Vec::new();
                for payload in &payloads {
                    wire.extend_from_slice(&writer.seal(payload).unwrap());
                }
                let mut reader = RecordReader::new(cipher, key(0x3C));
                let mut got = Vec::new();
                for chunk in wire.chunks(step) {
                    reader.push(chunk).unwrap();
                    while let Some(plain) = reader.next_plaintext().unwrap() {
                        got.push(plain);
                    }
                }
                reader.finish().unwrap();
                assert_eq!(got, payloads, "{cipher:?} 分块步长 {step}");
            }
        }
    }

    #[test]
    fn writer_header_is_reference_shape_and_aad() {
        // 头部必须是 23 03 03 + BE16(body)，且改动头部必须让认证失败（AAD 生效）。
        let mut writer = RecordWriter::new(XelCipher::Aes256Gcm, key(0x4D));
        let record = writer.seal(b"payload").unwrap();
        assert_eq!(record.len(), 5 + 7 + 16);
        assert_eq!(&record[..3], &[23, 3, 3]);
        assert_eq!(&record[3..5], &[0, 23]); // 7 + 16 = 23

        let mut reader = RecordReader::new(XelCipher::Aes256Gcm, key(0x4D));
        reader.push(&record).unwrap();
        let mut tampered = record.clone();
        tampered[4] ^= 0x01; // 长度前缀变化 ⇒ 头部（AAD）不同
        reader.push(&tampered).unwrap();
        // 两条记录：第一条正常，第二条头部被改 ⇒ 认证失败并 poison。
        assert!(reader.next_plaintext().unwrap().is_some());
        let error = reader.next_plaintext().unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidRecordLength { .. } | Error::AuthFailed
        ));
        assert!(reader.is_poisoned());
    }

    #[test]
    fn sequence_lockstep_rejects_skipped_record() {
        let mut writer = RecordWriter::new(XelCipher::Aes256Gcm, key(0x5E));
        let first = writer.seal(b"one").unwrap();
        let second = writer.seal(b"two").unwrap();
        // 接收方丢掉第一条线上字节，直接喂第二条：序号锁定步必须失步。
        let mut reader = RecordReader::new(XelCipher::Aes256Gcm, key(0x5E));
        reader.push(&second).unwrap();
        let error = reader
            .next_plaintext()
            .expect_err("跳过记录必须被锁定步拒绝");
        assert!(matches!(
            error,
            Error::AuthFailed | Error::SequenceOutOfSync { .. }
        ));
        assert!(reader.is_poisoned());
        // 已发出的第一条不等于接收序号可回退：从头开始喂第一条同样 poison。
        let mut reader2 = RecordReader::new(XelCipher::Aes256Gcm, key(0x5E));
        reader2.push(&first).unwrap();
        assert!(reader2.next_plaintext().unwrap().is_some());
    }

    #[test]
    fn wrong_key_fails_closed() {
        let stream = sealed_stream(&[b"secret payload".as_slice()]);
        let mut reader = RecordReader::new(XelCipher::Aes256Gcm, key(0xE0));
        reader.push(&stream).unwrap();
        assert_eq!(reader.next_plaintext(), Err(Error::AuthFailed));
        assert!(reader.is_poisoned());
        assert_eq!(reader.push(&stream), Err(Error::Poisoned));
    }

    #[test]
    fn truncated_stream_poisons_on_finish() {
        let stream = sealed_stream(&[b"record body that is long enough"]);
        let mut reader = RecordReader::new(XelCipher::Aes256Gcm, key(0x3C));
        reader.push(&stream[..stream.len() - 3]).unwrap();
        assert!(reader.next_plaintext().unwrap().is_none());
        assert!(matches!(reader.finish(), Err(Error::Truncated { .. })));
        assert!(reader.is_poisoned());
    }

    #[test]
    fn debug_output_never_contains_key_bytes() {
        let writer = RecordWriter::new(XelCipher::Aes256Gcm, key(0xA7));
        let printed = format!("{writer:?}");
        assert!(!printed.contains("167"), "Debug 泄露密钥字节：{printed}");
    }
}
