//! XEL 记录分帧：5 字节头部（魔数 + 长度前缀）+ 密文记录体。
//!
//! 线格式对齐 `common.go` 的 `EncodeHeader`/`DecodeHeader`：
//! ```text
//! [ 23 03 03 ] [ BE16 记录体长度 ] [ 密文 || 16B tag ]
//! ```
//! - 头部魔数固定 `23 03 03`。
//! - 长度前缀是**记录体**长度（密文 + tag），参考允许 `17..=16640`。
//! - 头部同时是 AEAD 的附加认证数据（`common.go` 把 `headerAndData[:5]` 当 AAD 传入），
//!   所以任何头部改动都会让记录认证失败，不存在“裸长度前缀可信”的中间状态。
//!
//! 本模块只做分帧（不认证）：认证与序号锁定在 [`super::record`]，
//! 头部掩蔽在 [`super::xor`]。

use super::{Error, MAX_RECORD_BODY_LEN, MIN_RECORD_BODY_LEN, RECORD_HEADER_LEN, RECORD_MAGIC};

/// 一条记录头部：魔数已验证 + 记录体长度。
///
/// `body_len` 只可能是 `17..=16640`（由 [`RecordHeader::new`] 强制），
/// 因此编码成 BE16 不会截断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    /// 记录体长度（密文 + tag）。
    body_len: u16,
}

impl RecordHeader {
    /// 由记录体长度构造；越界即 fail-closed。
    pub fn new(body_len: usize) -> Result<Self, Error> {
        if !(MIN_RECORD_BODY_LEN..=MAX_RECORD_BODY_LEN).contains(&body_len) {
            return Err(Error::InvalidRecordLength {
                got: body_len,
                min: MIN_RECORD_BODY_LEN,
                max: MAX_RECORD_BODY_LEN,
            });
        }
        // new() 已限定上界，转换必然成功。
        Ok(Self {
            body_len: body_len as u16,
        })
    }

    /// 记录体长度（密文 + tag）。
    pub fn body_len(self) -> usize {
        self.body_len as usize
    }

    /// 整条记录的线上长度（头部 + 记录体）。
    pub fn record_len(self) -> usize {
        RECORD_HEADER_LEN + self.body_len()
    }

    /// 编码为线上 5 字节（等价 `EncodeHeader`）。
    pub fn encode(self) -> [u8; RECORD_HEADER_LEN] {
        [
            RECORD_MAGIC[0],
            RECORD_MAGIC[1],
            RECORD_MAGIC[2],
            (self.body_len >> 8) as u8,
            self.body_len as u8,
        ]
    }

    /// 解码 5 字节头部。
    ///
    /// 与 `common.go` `DecodeHeader` 的偏离（取更严格）：参考在魔数不符时把长度置
    /// 0 后继续运行；本函数返回 [`Error::InvalidHeader`]，调用方必须 poison 整条流。
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() < RECORD_HEADER_LEN {
            return Err(Error::Truncated {
                need: RECORD_HEADER_LEN,
                got: input.len(),
            });
        }
        if input[..3] != RECORD_MAGIC {
            return Err(Error::InvalidHeader);
        }
        RecordHeader::new(u16::from_be_bytes([input[3], input[4]]) as usize)
    }
}

/// 字节流记录帧器：把任意切分的分段重组成完整记录。
///
/// - [`RecordFramer::push`] 只追加字节；缓冲超过“头 + 最大记录体”即说明长度前缀
///   不可信 → fail-closed。
/// - [`RecordFramer::next_record`] 取出攒够的一条记录（含 5 字节头部）。
/// - [`RecordFramer::finish`] 在流结束时检查残字节：非空即截断。
///
/// 三者任一失败都会永久 poison，之后一律 [`Error::Poisoned`]。
pub struct RecordFramer {
    pending: Vec<u8>,
    poisoned: bool,
}

/// 单条记录的最大线上字节数（头 + 记录体上限）。
const MAX_PENDING: usize = RECORD_HEADER_LEN + MAX_RECORD_BODY_LEN;

impl Default for RecordFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordFramer {
    pub fn new() -> Self {
        Self {
            // 预分配只到“一条最小记录”，避免为不可信长度预留大块内存。
            pending: Vec::with_capacity(RECORD_HEADER_LEN + MIN_RECORD_BODY_LEN),
            poisoned: false,
        }
    }

    /// 已缓冲但尚未成帧的字节数（诊断用）。
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// 记录失效并清空缓冲，返回同一错误（fail-closed 的唯一出口）。
    fn fail(&mut self, error: Error) -> Error {
        self.poisoned = true;
        self.pending.clear();
        error
    }

    /// 追加线上字节；凑不齐一帧属于正常等待（返回 `Ok`），
    /// 只有超出任何合法记录可能占用的缓冲上限才失败。
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.pending.len().saturating_add(bytes.len()) > MAX_PENDING {
            let got = self.pending.len() + bytes.len();
            return Err(self.fail(Error::InvalidRecordLength {
                got,
                min: MIN_RECORD_BODY_LEN,
                max: MAX_RECORD_BODY_LEN,
            }));
        }
        self.pending.extend_from_slice(bytes);
        Ok(())
    }

    /// 取出一条完整记录（头部 + 记录体）；不足一帧返回 `Ok(None)`。
    ///
    /// 头部非法或长度越界都会 poison：长度前缀已被消费，继续攒字节只会把错位
    /// 当成协议，必须弃用整条流。
    pub fn next_record(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.pending.len() < RECORD_HEADER_LEN {
            return Ok(None);
        }
        let header = match RecordHeader::decode(&self.pending[..RECORD_HEADER_LEN]) {
            Ok(header) => header,
            // 头部本身不完整：继续等待。
            Err(Error::Truncated { .. }) => return Ok(None),
            Err(error) => return Err(self.fail(error)),
        };
        let total = header.record_len();
        if self.pending.len() < total {
            return Ok(None);
        }
        Ok(Some(self.pending.drain(..total).collect::<Vec<u8>>()))
    }

    /// 流结束检查：仍有残字节即为截断（fail-closed，残字节不外泄）。
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.pending.is_empty() {
            return Ok(());
        }
        let got = self.pending.len();
        let need = if got < RECORD_HEADER_LEN {
            RECORD_HEADER_LEN
        } else {
            match RecordHeader::decode(&self.pending[..RECORD_HEADER_LEN]) {
                Ok(header) => header.record_len(),
                Err(error) => return Err(self.fail(error)),
            }
        };
        Err(self.fail(Error::Truncated { need, got }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_record(body_len: usize, fill: u8) -> Vec<u8> {
        let mut record = RecordHeader::new(body_len).unwrap().encode().to_vec();
        record.resize(record.len() + body_len, fill);
        record
    }

    #[test]
    fn header_matches_reference_bytes() {
        // common.go EncodeHeader：h[0]=23, h[1]=3, h[2]=3, BE16(l)
        let header = RecordHeader::new(17).unwrap();
        assert_eq!(header.encode(), [23, 3, 3, 0, 17]);
        assert_eq!(header.body_len(), 17);
        assert_eq!(header.record_len(), 22);
        let max = RecordHeader::new(MAX_RECORD_BODY_LEN).unwrap();
        assert_eq!(max.encode(), [23, 3, 3, 0x41, 0x00]);
        assert_eq!(RecordHeader::decode(&max.encode()), Ok(max));
    }

    #[test]
    fn header_bounds_and_magic_are_rejected() {
        for body_len in [0, 16, MAX_RECORD_BODY_LEN + 1, 70000] {
            assert_eq!(
                RecordHeader::new(body_len),
                Err(Error::InvalidRecordLength {
                    got: body_len,
                    min: MIN_RECORD_BODY_LEN,
                    max: MAX_RECORD_BODY_LEN,
                }),
                "长度 {body_len} 应拒绝"
            );
        }
        let mut bytes = RecordHeader::new(20).unwrap().encode();
        bytes[0] = 22;
        assert_eq!(RecordHeader::decode(&bytes), Err(Error::InvalidHeader));
        bytes[0] = 23;
        bytes[2] = 4;
        assert_eq!(RecordHeader::decode(&bytes), Err(Error::InvalidHeader));
        assert_eq!(
            RecordHeader::decode(&[23, 3, 3, 0, 1]),
            Err(Error::InvalidRecordLength {
                got: 1,
                min: MIN_RECORD_BODY_LEN,
                max: MAX_RECORD_BODY_LEN,
            })
        );
        assert_eq!(
            RecordHeader::decode(&[23, 3, 3]),
            Err(Error::Truncated {
                need: RECORD_HEADER_LEN,
                got: 3
            })
        );
    }

    #[test]
    fn framer_reassembles_across_every_split() {
        let first = fake_record(18, 0xCC);
        let second = fake_record(17, 0xDD);
        let stream: Vec<u8> = first.iter().chain(second.iter()).copied().collect();
        for step in [1usize, 2, 3, 7, 22, stream.len()] {
            let mut framer = RecordFramer::new();
            let mut got: Vec<Vec<u8>> = Vec::new();
            for chunk in stream.chunks(step) {
                framer.push(chunk).unwrap();
                while let Some(one) = framer.next_record().unwrap() {
                    got.push(one);
                }
            }
            framer.finish().unwrap();
            assert_eq!(got, vec![first.clone(), second.clone()], "分片步长 {step}");
            assert_eq!(framer.buffered(), 0);
        }
    }

    #[test]
    fn framer_truncation_poisons() {
        let record = fake_record(20, 0);
        let mut framer = RecordFramer::new();
        framer.push(&record[..12]).unwrap();
        assert_eq!(framer.next_record().unwrap(), None);
        assert_eq!(framer.finish(), Err(Error::Truncated { need: 25, got: 12 }));
        assert!(framer.is_poisoned());
        assert_eq!(framer.push(&record[12..]), Err(Error::Poisoned));
        assert_eq!(framer.next_record(), Err(Error::Poisoned));
        assert_eq!(framer.finish(), Err(Error::Poisoned));
    }

    #[test]
    fn framer_rejects_unsane_length_prefix() {
        // 空缓冲只是等待，不是错误。
        let mut idle = RecordFramer::new();
        assert_eq!(idle.next_record().unwrap(), None);
        assert_eq!(idle.finish(), Ok(()));

        let mut framer = RecordFramer::new();
        framer.push(&[23, 3, 3, 0xFF, 0xFF]).unwrap();
        // BE16 = 65535 > 16640：长度前缀不可信，poison 而非继续攒字节。
        assert_eq!(
            framer.next_record(),
            Err(Error::InvalidRecordLength {
                got: 65535,
                min: MIN_RECORD_BODY_LEN,
                max: MAX_RECORD_BODY_LEN,
            })
        );
        assert_eq!(framer.next_record(), Err(Error::Poisoned));
        assert_eq!(framer.buffered(), 0);
    }

    #[test]
    fn framer_rejects_bad_magic_and_oversized_buffer() {
        let mut magic = RecordFramer::new();
        magic.push(&[24, 3, 3, 0, 17]).unwrap();
        assert_eq!(magic.next_record(), Err(Error::InvalidHeader));
        assert_eq!(magic.next_record(), Err(Error::Poisoned));

        // 合法头部 + 超过最大记录体的字节流：不可能属于任何合法记录。
        let mut flood = RecordFramer::new();
        flood
            .push(&RecordHeader::new(17).unwrap().encode())
            .unwrap();
        let block = vec![0u8; 4096];
        let mut written = 0;
        let mut failed = None;
        while written < MAX_PENDING {
            let take = block.len().min(MAX_PENDING - written + 1);
            match flood.push(&block[..take]) {
                Ok(()) => {
                    written += take;
                }
                Err(error) => {
                    failed = Some(error);
                    break;
                }
            }
        }
        assert!(
            matches!(failed, Some(Error::InvalidRecordLength { .. })),
            "超出最大缓冲必须按长度越界失败，实际 {failed:?}"
        );
        assert!(flood.is_poisoned());
    }

    #[test]
    fn framer_accepts_one_max_size_record() {
        let record = fake_record(MAX_RECORD_BODY_LEN, 0x5A);
        let mut framer = RecordFramer::new();
        framer.push(&record).unwrap();
        assert_eq!(framer.next_record().unwrap().as_deref(), Some(&record[..]));
        assert_eq!(framer.finish(), Ok(()));
    }
}
