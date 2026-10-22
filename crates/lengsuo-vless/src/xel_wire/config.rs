//! XEL 记录层出站原语的配置与错误类型。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）。

use std::io;

use crate::xel::{
    aead::XelCipher,
    record::{RecordReader, RecordWriter},
    xor::XorMask,
    Error as XelError, XelKey,
};

use super::endpoint::{XelReceiver, XelSender};

/// 单条记录的明文上限（参考 `common.go:55` `CommonConn.Write` 的
/// `if len(b) > 8192 { b = b[:8192] }`）。
pub const MAX_PLAINTEXT_PER_RECORD: usize = 8192;

/// XOR 掩蔽层 CTR IV 长度（AES 块长，参考 `xor.go:12` `NewCTR` 的 IV）。
pub const XOR_IV_LEN: usize = 16;

/// XEL 记录层出站原语的错误。全部 fail-closed。
///
/// 消息只含长度／序号／状态，不含密钥、明文或密文字节（与
/// [`crate::xel::Error`] 的脱敏纪律一致）。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 记录层失败（认证、序号、头部、长度、截断、poison）。
    #[error("XEL 记录层失败：{0}")]
    Record(#[from] XelError),
    /// 底层 I/O 失败。
    #[error("XEL: I/O 失败")]
    Io(#[from] io::Error),
    /// I/O 超时。
    #[error("XEL: 操作超时")]
    Timeout,
}

/// XOR 头部掩蔽层配置（参考 `xor.go` `NewCTR` + `NewXorConn`）。
///
/// **命名以端点为基准**（`send` = 本端发出，`recv` = 本端收到）：客户端的
/// `send` 是上行、服务端的 `send` 是下行，两端因此可以对调同一份配置。
///
/// **密钥材料与 AEAD 密钥不是同一份**：参考用 `blake3.DeriveKey("VLESS", UnitedKey)`
/// 作 AES-256-CTR 密钥（`xor.go:13`），而 AEAD 侧用 `blake3.DeriveKey(ctx, UnitedKey)`
/// （`common.go:159`）。本仓把派生结果与 IV 都交给调用方注入，因此这里给的是
/// **未派生的 UnitedKey 材料**，掩蔽层内部再派生一次（`src/xel/xor.rs:34`）。
#[derive(Debug)]
pub struct XorLayer {
    /// 本端**发送**方向的掩蔽密钥材料。
    pub send_key: XelKey,
    /// 本端发送方向的 CTR IV。
    pub send_iv: [u8; XOR_IV_LEN],
    /// 本端**接收**方向的掩蔽密钥材料。
    pub recv_key: XelKey,
    /// 本端接收方向的 CTR IV。
    pub recv_iv: [u8; XOR_IV_LEN],
}

impl XorLayer {
    /// 构造掩蔽层配置；IV 长度必须恰为 [`XOR_IV_LEN`]，否则 fail-closed 拒绝。
    pub fn new(
        send_key: XelKey,
        send_iv: &[u8],
        recv_key: XelKey,
        recv_iv: &[u8],
    ) -> Result<Self, Error> {
        let send_iv = fixed_iv(send_iv)?;
        let recv_iv = fixed_iv(recv_iv)?;
        Ok(Self {
            send_key,
            send_iv,
            recv_key,
            recv_iv,
        })
    }
}

/// 定长 IV 的 fail-closed 校验（错误只报长度）。
fn fixed_iv(iv: &[u8]) -> Result<[u8; XOR_IV_LEN], Error> {
    if iv.len() != XOR_IV_LEN {
        return Err(Error::Record(XelError::InvalidIvLength {
            got: iv.len(),
            want: XOR_IV_LEN,
        }));
    }
    let mut out = [0u8; XOR_IV_LEN];
    out.copy_from_slice(iv);
    Ok(out)
}

/// XEL 记录层配置。密钥与 IV 全部由调用方注入（握手/KEM 不在本模块范围）。
///
/// **命名以端点为基准**：`uplink_key` = 本端**发送**方向的 AEAD 记录密钥，
/// `downlink_key` = 本端**接收**方向的 AEAD 记录密钥。客户端与服务端因此可以
/// 对调同一份配置（客户端的 `uplink` = 服务端的 `downlink`）。
#[derive(Debug)]
pub struct XelWireConfig {
    /// AEAD 套件（两个方向相同；参考 `common.go:157` 的 `useAES` 二选一）。
    pub cipher: XelCipher,
    /// 本端**发送**方向的 AEAD 记录密钥（客户端视角 = 上行）。
    pub uplink_key: XelKey,
    /// 本端**接收**方向的 AEAD 记录密钥（客户端视角 = 下行）。
    pub downlink_key: XelKey,
    /// 可选的 XOR 头部掩蔽层（参考 `client.go:123` / `server.go:231` 的
    /// `XorMode == 2`；`XorMode == 1` 时置 `None`）。
    pub xor: Option<XorLayer>,
}

impl XelWireConfig {
    /// 拆成发送端与接收端（同步调用方与 [`crate::xel_wire::XelStream`] 共用）。
    pub fn split(self) -> Result<(XelSender, XelReceiver), Error> {
        let XelWireConfig {
            cipher,
            uplink_key,
            downlink_key,
            xor,
        } = self;
        // 掩蔽器分两个实例：发送端只用 `mask_outgoing`（掩蔽本端发出的头），
        // 接收端只用 `unmask_incoming`（还原本端收到的头）。方向状态不能共用。
        // 逻辑全在既有 `XorMask` 内，本模块不重复实现。
        let (out_mask, in_mask) = match xor {
            Some(layer) => {
                let out = XorMask::new(
                    &layer.send_key,
                    &layer.send_iv,
                    &layer.recv_key,
                    &layer.recv_iv,
                )?;
                let inbound = XorMask::new(
                    &layer.send_key,
                    &layer.send_iv,
                    &layer.recv_key,
                    &layer.recv_iv,
                )?;
                (Some(out), Some(inbound))
            }
            None => (None, None),
        };
        Ok((
            XelSender {
                writer: RecordWriter::new(cipher, uplink_key),
                mask: out_mask,
            },
            XelReceiver {
                reader: RecordReader::new(cipher, downlink_key),
                mask: in_mask,
            },
        ))
    }
}
