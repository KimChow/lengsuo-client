//! XEL XOR 模式：记录头掩蔽层（对齐 `xor.go` 的 `NewXorConn`）。
//!
//! 参考语义（`xor.go`，逐条对齐）：
//! - 掩蔽密钥 = `blake3.DeriveKey("VLESS", key)` 派生 32 字节后作 AES-256-CTR
//!   密钥；IV 由调用方提供（16 字节 = AES 块长）。
//! - 线上是连续的 TLS 风格记录流：每条记录 5 字节头（魔数 `23 03 03` + BE16）+
//!   记录体。**只有头部被掩蔽，记录体原样上线**（机密性由底层 TLS 提供——这是
//!   参考实现的设计，本层照搬，不额外加密记录体）。
//! - 头部解码出的 BE16 值是**下一段跳过量**（`OutSkip`/`InSkip`）：跳过的字节
//!   不消耗掩蔽密钥流；密钥流只在被掩蔽的字节上推进，跨任意读写字节分块连续。
//! - 跨块的部分头部：先按密钥流掩蔽上线，同时以**明文**缓存在本地，凑满 5 字节
//!   后一起解码（与参考一致，保证密钥流位置与单次大块调用完全一致）。
//!
//! **与参考的有意偏离**（取更严格，见 `super` 模块文档）：
//! `xor.go` 忽略 `DecodeHeader` 错误继续运行；本实现把魔数不符或长度越界视为
//! [`Error::InvalidHeader`] 并永久 poison——错位继续只会把攻击当协议。
//!
//! 本模块不含密钥的 `Debug` 输出；错误消息只含长度/状态。

use aes::cipher::generic_array::GenericArray;
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;

use super::frame::RecordHeader;
use super::{Error, XelKey, RECORD_HEADER_LEN};

/// blake3 派生上下文，与 `xor.go` `NewCTR` 的 `"VLESS"` 逐字一致。
const DERIVE_CONTEXT: &str = "VLESS";
/// AES-CTR IV 长度（AES 块长）。
pub const IV_LEN: usize = 16;

/// 从主密钥材料派生 32 字节 CTR 密钥（`blake3.DeriveKey("VLESS", key)`）。
fn derive_ctr_key(key: &XelKey) -> [u8; 32] {
    blake3::derive_key(DERIVE_CONTEXT, key.as_slice())
}

/// 单方向掩蔽状态：CTR 密钥流 + 跳过计数 + 部分头缓冲。
struct MaskDirection {
    ctr: Ctr128BE<Aes256>,
    skip: usize,
    header: Vec<u8>,
    poisoned: bool,
}

impl MaskDirection {
    fn new(key: &XelKey, iv: &[u8]) -> Result<Self, Error> {
        if iv.len() != IV_LEN {
            return Err(Error::InvalidIvLength {
                got: iv.len(),
                want: IV_LEN,
            });
        }
        let derived = derive_ctr_key(key);
        let ctr = Ctr128BE::<Aes256>::new(
            GenericArray::from_slice(&derived),
            GenericArray::from_slice(iv),
        );
        Ok(Self {
            ctr,
            skip: 0,
            header: Vec::with_capacity(RECORD_HEADER_LEN),
            poisoned: false,
        })
    }

    fn fail(&mut self, error: Error) -> Error {
        self.poisoned = true;
        self.skip = 0;
        self.header.clear();
        error
    }

    /// 参照 `xor.go` 的 `Write` 掩蔽循环，对 `wire` 原地掩蔽（明文 → 线上）。
    fn mask(&mut self, wire: &mut [u8]) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let mut pos = 0usize;
        loop {
            let remaining = wire.len() - pos;
            if remaining <= self.skip {
                // 整段落在跳过区（上一条记录体），不掩蔽、不耗密钥流。
                self.skip -= remaining;
                return Ok(());
            }
            pos += self.skip;
            self.skip = 0;
            let need = RECORD_HEADER_LEN - self.header.len();
            let available = wire.len() - pos;
            if available < need {
                // 部分头部：明文入缓冲（供后续解码），线上字节按当前密钥流掩蔽。
                self.header.extend_from_slice(&wire[pos..]);
                self.ctr.apply_keystream(&mut wire[pos..]);
                return Ok(());
            }
            let mut full = std::mem::take(&mut self.header);
            full.extend_from_slice(&wire[pos..pos + need]);
            let decoded = match RecordHeader::decode(&full) {
                Ok(header) => header,
                Err(error) => return Err(self.fail(error)),
            };
            self.skip = decoded.body_len();
            self.ctr.apply_keystream(&mut wire[pos..pos + need]);
            pos += need;
        }
    }

    /// 参照 `xor.go` 的 `Read` 还原循环，对 `wire` 原地还原（线上 → 明文）。
    /// 与掩蔽方向唯一的顺序差异：先还原再解码（参考实现同样如此）。
    fn unmask(&mut self, wire: &mut [u8]) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let mut pos = 0usize;
        loop {
            let remaining = wire.len() - pos;
            if remaining <= self.skip {
                self.skip -= remaining;
                return Ok(());
            }
            pos += self.skip;
            self.skip = 0;
            let need = RECORD_HEADER_LEN - self.header.len();
            let available = wire.len() - pos;
            if available < need {
                self.ctr.apply_keystream(&mut wire[pos..]);
                self.header.extend_from_slice(&wire[pos..]);
                return Ok(());
            }
            self.ctr.apply_keystream(&mut wire[pos..pos + need]);
            let mut full = std::mem::take(&mut self.header);
            full.extend_from_slice(&wire[pos..pos + need]);
            let decoded = match RecordHeader::decode(&full) {
                Ok(header) => header,
                Err(error) => return Err(self.fail(error)),
            };
            self.skip = decoded.body_len();
            pos += need;
        }
    }
}

/// XOR 模式掩蔽器：持有本端发送与对端发送两条独立密钥流。
///
/// 与 [`super::frame::RecordFramer`] 配合使用：线上字节先经过本层
/// [`XorMask::unmask_incoming`]，再交给帧器；发送侧先用
/// [`XorMask::mask_outgoing`] 处理整段输出再上线。
pub struct XorMask {
    out: MaskDirection,
    inp: MaskDirection,
}

impl XorMask {
    /// 由注入密钥与 IV 建立双向掩蔽；IV 必须恰为 16 字节。
    pub fn new(
        out_key: &XelKey,
        out_iv: &[u8],
        in_key: &XelKey,
        in_iv: &[u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            out: MaskDirection::new(out_key, out_iv)?,
            inp: MaskDirection::new(in_key, in_iv)?,
        })
    }

    /// 发送方向原地掩蔽（明文 → 线上）。
    pub fn mask_outgoing(&mut self, wire: &mut [u8]) -> Result<(), Error> {
        self.out.mask(wire)
    }

    /// 接收方向原地还原（线上 → 明文）。
    pub fn unmask_incoming(&mut self, wire: &mut [u8]) -> Result<(), Error> {
        self.inp.unmask(wire)
    }

    pub fn is_poisoned(&self) -> bool {
        self.out.poisoned || self.inp.poisoned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一条 XOR 模式记录：头 5 字节（BE16 = 记录体长度）+ 记录体。
    fn record(body_len: usize, fill: u8) -> Vec<u8> {
        let header = RecordHeader::new(body_len).unwrap().encode();
        let mut bytes = header.to_vec();
        bytes.resize(bytes.len() + body_len, fill);
        bytes
    }

    fn mask_pair() -> (XorMask, XorMask) {
        let key = XelKey::new(&[0x2Au8; 32]).unwrap();
        // 双向各一条流：A 的发送密钥 = B 的接收密钥。
        let a = XorMask::new(&key, &[1u8; 16], &key, &[2u8; 16]).unwrap();
        let b = XorMask::new(&key, &[2u8; 16], &key, &[1u8; 16]).unwrap();
        (a, b)
    }

    #[test]
    fn iv_length_is_validated() {
        let key = XelKey::new(&[0u8; 32]).unwrap();
        for iv in [&[0u8; 15][..], &[0u8; 17][..], &[][..]] {
            for outcome in [
                XorMask::new(&key, iv, &key, &[0u8; 16]),
                XorMask::new(&key, &[0u8; 16], &key, iv),
            ] {
                match outcome {
                    Ok(_) => panic!("IV 长度 {} 应被拒绝", iv.len()),
                    Err(Error::InvalidIvLength { got, want }) => {
                        assert_eq!(got, iv.len());
                        assert_eq!(want, IV_LEN);
                    }
                    Err(other) => panic!("应报 IV 长度错误，实际 {other:?}"),
                }
            }
        }
    }

    #[test]
    fn bodies_are_left_in_clear_headers_are_masked() {
        let (mut a, mut b) = mask_pair();
        let mut wire = record(24, 0xAB);
        a.mask_outgoing(&mut wire).unwrap();
        // 头 5 字节被掩蔽（与明文不同），体保持原样。
        assert_ne!(&wire[..5], &[23, 3, 3, 0, 24]);
        assert!(wire[5..].iter().all(|&byte| byte == 0xAB));
        b.unmask_incoming(&mut wire).unwrap();
        assert_eq!(&wire[..5], &[23, 3, 3, 0, 24]);
        assert!(wire[5..].iter().all(|&byte| byte == 0xAB));
    }

    #[test]
    fn roundtrip_is_identical_at_every_chunk_split() {
        let plain_a = [record(17, 1), record(18, 2), record(19, 3)].concat();
        let plain_b = [record(20, 4), record(21, 5)].concat();
        let step_set = [1usize, 2, 3, 5, 7, 22, plain_a.len()];
        for step in step_set {
            // 掩蔽器有状态（密钥流随使用推进）：分块与一次性比较各用独立实例。
            let (mut a, mut b) = mask_pair();
            let mut wire_a = plain_a.clone();
            let mut wire_b = plain_b.clone();
            for chunk in wire_a.chunks_mut(step) {
                a.mask_outgoing(chunk).unwrap();
            }
            for chunk in wire_b.chunks_mut(step) {
                b.mask_outgoing(chunk).unwrap();
            }
            // 对端还原后必须逐字节回到明文。
            for chunk in wire_b.chunks_mut(step) {
                a.unmask_incoming(chunk).unwrap();
            }
            assert_eq!(wire_b, plain_b, "接收方向分块步长 {step}");
            let (mut one_shot_mask, mut one_shot_unmask) = mask_pair();
            let mut one_shot = plain_a.clone();
            one_shot_mask.mask_outgoing(&mut one_shot).unwrap();
            assert_eq!(
                wire_a, one_shot,
                "分块掩蔽必须与一次性掩蔽逐字节一致（步长 {step}）"
            );
            one_shot_unmask.unmask_incoming(&mut one_shot).unwrap();
            assert_eq!(one_shot, plain_a, "一次性还原必须与分块一致（步长 {step}）");
        }
    }

    #[test]
    fn xor_layer_does_not_authenticate_by_design() {
        // XOR 模式只是头部掩蔽（xor.go 语义）：错钥会**静默**产出垃圾——垃圾头
        // 可能偶然解码为合法头（无认证可检测），记录体则始终原样透传。机密性与
        // 认证由底层 TLS 提供。本测试固定该语义，防止误以为本层有防护。
        let good = XelKey::new(&[0x11u8; 32]).unwrap();
        let evil = XelKey::new(&[0x99u8; 32]).unwrap();
        let mut sender = XorMask::new(&good, &[1u8; 16], &good, &[2u8; 16]).unwrap();
        let mut victim = XorMask::new(&evil, &[2u8; 16], &evil, &[1u8; 16]).unwrap();
        let mut wire = record(17, 0xAB);
        sender.mask_outgoing(&mut wire).unwrap();
        let outcome = victim.unmask_incoming(&mut wire);
        assert!(
            matches!(
                outcome,
                Ok(()) | Err(Error::InvalidHeader) | Err(Error::InvalidRecordLength { .. })
            ),
            "错钥结果只能是静默垃圾或头解码失败，不会 panic"
        );
        // 记录体在两种密钥下都原样透传（掩蔽只作用于头部）。
        assert!(wire[5..].iter().all(|&byte| byte == 0xAB));
    }

    #[test]
    fn tampered_header_is_rejected_and_poisons() {
        let (mut a, mut b) = mask_pair();
        let mut wire = record(30, 0x5A);
        a.mask_outgoing(&mut wire).unwrap();
        wire[0] ^= 0x01; // 掩蔽后的头部被篡改 ⇒ 明文魔数不再匹配
        assert_eq!(b.unmask_incoming(&mut wire), Err(Error::InvalidHeader));
        assert!(b.is_poisoned());
    }

    #[test]
    fn empty_stream_is_a_noop() {
        let (mut a, mut b) = mask_pair();
        let mut empty: [u8; 0] = [];
        a.mask_outgoing(&mut empty).unwrap();
        b.unmask_incoming(&mut empty).unwrap();
        assert!(!a.is_poisoned());
    }
}
