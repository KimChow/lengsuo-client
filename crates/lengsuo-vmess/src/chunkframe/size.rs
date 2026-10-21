//! 长度段掩码流（`ShakeSizeParser`）与无掩码的裸 BE16 长度段。
//!
//! 语义来源：参考 `proxy/vmess/encoding/auth.go` 的 `ShakeSizeParser` 与
//! `PlainChunkSizeParser`，固定 commit `d2758a02`。掩码流跨 chunk 连续，
//! 每 chunk 消耗 2 字节。

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};

/// SHAKE128 掩码流（`ShakeSizeParser`）：跨 chunk 连续的 2 字节 BE16 掩码。
pub struct DataSizeParser {
    reader: Shake128Reader,
}

impl DataSizeParser {
    /// `NewShakeSizeParser(iv)`：以 16 字节请求/响应 IV 播种。
    #[must_use]
    pub fn new(seed: &[u8]) -> Self {
        let mut shake = Shake128::default();
        shake.update(seed);
        DataSizeParser {
            reader: shake.finalize_xof(),
        }
    }

    /// `next()`：流内读 2 字节作 BE16。
    fn next_u16(&mut self) -> u16 {
        let mut buffer = [0u8; 2];
        self.reader.read(&mut buffer);
        u16::from_be_bytes(buffer)
    }

    /// `Encode(size, b)`：掩码后的 2 字节声明长度。
    #[must_use]
    pub fn encode_size(&mut self, size: u16) -> [u8; 2] {
        (self.next_u16() ^ size).to_be_bytes()
    }

    /// `Decode(b)`：还原真实长度。
    #[must_use]
    pub fn decode_size(&mut self, wire: [u8; 2]) -> u16 {
        self.next_u16() ^ u16::from_be_bytes(wire)
    }

    /// `NextPaddingLen()`：`next() % 64`。
    #[must_use]
    pub fn next_padding_len(&mut self) -> u16 {
        self.next_u16() % 64
    }

    /// `MaxPaddingLen()`：常量 64。
    #[must_use]
    pub const fn max_padding_len() -> u16 {
        64
    }
}

/// 无掩码分帧的 size 编解码（`PlainChunkSizeParser`：裸 BE16）。
#[must_use]
pub fn plain_size_encode(size: u16) -> [u8; 2] {
    size.to_be_bytes()
}

/// `shake_mask` 兼容导出：单次掩码（无状态调用，测试/向量用）。
#[must_use]
pub fn shake_mask(seed: &[u8], index: usize) -> [u8; 2] {
    let mut parser = DataSizeParser::new(seed);
    for _ in 0..index {
        parser.next_padding_len_u16();
    }
    parser.encode_size(0)
}

impl DataSizeParser {
    fn next_padding_len_u16(&mut self) -> u16 {
        self.next_u16()
    }
}
