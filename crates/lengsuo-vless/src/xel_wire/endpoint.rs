//! 发送 / 接收方向原语：明文 ↔ 线上字节。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）。

use crate::xel::{
    record::{RecordReader, RecordWriter},
    xor::XorMask,
};

use super::config::{Error, MAX_PLAINTEXT_PER_RECORD};

/// 发送方向原语：明文 → 线上字节。
///
/// 语义全部来自 [`crate::xel::record::RecordWriter`]（记录封装、nonce 序号、
/// 头部作 AAD）与可选的 [`crate::xel::xor::XorMask`]（只掩蔽 5 字节头）。
pub struct XelSender {
    /// 记录层发送方向（由 [`super::config::XelWireConfig::split`] 构造）。
    pub(super) writer: RecordWriter,
    /// 可选的 XOR 头部掩蔽层。
    pub(super) mask: Option<XorMask>,
}

impl XelSender {
    /// 把明文封成线上字节（可能含多条记录）。
    ///
    /// 分块上限 [`MAX_PLAINTEXT_PER_RECORD`]，与参考 `common.go:55` 一致：
    /// 每 8192 字节明文一条记录，空明文产出空输出（参考 `common.go:48`）。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut wire = Vec::with_capacity(plaintext.len() + 5);
        for chunk in plaintext.chunks(MAX_PLAINTEXT_PER_RECORD) {
            let mut record = self.writer.seal(chunk)?;
            // 掩蔽层作用在「头 + 体」整条线上记录上（参考 `xor.go:41`）。
            if let Some(mask) = &mut self.mask {
                mask.mask_outgoing(&mut record)?;
            }
            wire.extend_from_slice(&record);
        }
        Ok(wire)
    }

    /// 已发送的记录数（= 已消耗的 nonce 序号）。
    pub fn sequence(&self) -> u64 {
        self.writer.sequence()
    }

    /// 方向是否已 poison（认证失败或序号耗尽后为真）。
    pub fn is_poisoned(&self) -> bool {
        self.writer.is_poisoned() || self.mask.as_ref().is_some_and(XorMask::is_poisoned)
    }
}

impl std::fmt::Debug for XelSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XelSender")
            .field("sequence", &self.writer.sequence())
            .field("poisoned", &self.is_poisoned())
            .finish_non_exhaustive()
    }
}

/// 接收方向原语：线上字节 → 明文。
///
/// 语义全部来自 [`crate::xel::record::RecordReader`]（分帧、锁定步序号、解封）
/// 与可选的 [`crate::xel::xor::XorMask`]（只去掩蔽 5 字节头）。
pub struct XelReceiver {
    /// 记录层接收方向（由 [`super::config::XelWireConfig::split`] 构造）。
    pub(super) reader: RecordReader,
    /// 可选的 XOR 头部掩蔽层。
    pub(super) mask: Option<XorMask>,
}

impl XelReceiver {
    /// 喂入线上字节，返回解出的明文（不足一条记录时返回空）。
    ///
    /// 顺序与参考一致：先去掩蔽（`xor.go:69`），再分帧解封（`common.go:80`）。
    pub fn open(&mut self, wire: &[u8]) -> Result<Vec<u8>, Error> {
        let mut plaintext = Vec::new();
        if let Some(mask) = &mut self.mask {
            // 掩蔽是**原地**的，必须先复制再改（调用方的缓冲不能被篡改）。
            let mut unmasked = wire.to_vec();
            mask.unmask_incoming(&mut unmasked)?;
            self.reader.push(&unmasked)?;
        } else {
            self.reader.push(wire)?;
        }
        while let Some(chunk) = self.reader.next_plaintext()? {
            plaintext.extend_from_slice(&chunk);
        }
        Ok(plaintext)
    }

    /// 流结束检查：残字节即截断（fail-closed）。
    pub fn finish(&mut self) -> Result<(), Error> {
        Ok(self.reader.finish()?)
    }

    /// 方向是否已 poison。
    pub fn is_poisoned(&self) -> bool {
        self.reader.is_poisoned() || self.mask.as_ref().is_some_and(XorMask::is_poisoned)
    }
}

impl std::fmt::Debug for XelReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XelReceiver")
            .field("poisoned", &self.is_poisoned())
            .finish_non_exhaustive()
    }
}
