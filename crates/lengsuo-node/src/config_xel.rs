//! VLESS **XEL 记录层**配置段（`xel`）。
//!
//! 从 `config.rs` 拆出（`config.rs` 已超 400 行软目标），`config.rs` 只留
//! `pub use` 转发；公共路径仍是 `crate::config::NodeXelSettings`。
//!
//! # 对应的参考字段
//!
//! 参考 `infra/conf/vless.go:311-363` 的 outbound `Encryption` 字段
//! （`mlkem768x25519plus.{native|xorpub|random}.{1rtt|0rtt}.<padding>.<key>`）与
//! `proxy/vless/outbound/outbound.go:86-97`（非 `""` / `"none"` 即启用）。
//! 参考把「模式 / 0-RTT / padding / 非对称公钥」编进一个字符串，会话密钥由
//! `mlkem768x25519plus` 握手协商得出。
//!
//! ⚠️ **与参考的有意偏离**（与 `config_vision` 的记录层同口径）：本仓没有 ML-KEM
//! ⇒ 本段从「**会话密钥与 IV 已就绪**」这一层接，密钥 / IV 由配置直接给出（十六进制），
//! 参考的 `native/xorpub/random` 与 `1rtt/0rtt` 两个维度映射为：
//!
//! | 参考 `Encryption` 位置 | 本段字段 |
//! |---|---|
//! | `xorpub` / `random`（`XorMode` 1 / 2） | `xor` 段是否给出（`None` ⇒ 不掩蔽） |
//! | `1rtt` / `0rtt` | 无对应（会话恢复属握手层，不在本仓） |
//! | `<padding>` | 无对应（padding 属握手报文） |
//!
//! # fail-closed
//!
//! - 只**允许**出现在 `protocol = vless` 的节点上；
//! - 未知套件 / 非法十六进制 / 长度不符 ⇒ 配置加载阶段显式报错；
//! - 与 `vision.encryption` **不得同时给出**：参考里二者都作用在 VLESS 记录层，
//!   叠两层会让对端解不开（显式拒绝而非静默择一）。

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, NodeConfig, Protocol};

/// XEL 的 XOR 头部掩蔽层（参考 `XorMode == 2`，`proxy/vless/encryption/client.go:123`
/// 的 `NewXorConn(conn, NewCTR(UnitedKey, iv), nil, ..., 16)`）。
///
/// 密钥方向以**本端**为基准（`send` = 本端发出，`recv` = 本端收到）；对端对调。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeXelXorSettings {
    /// 本端发送方向的掩蔽密钥材料（32 字节十六进制）。
    pub send_key: String,
    /// 本端发送方向的 CTR IV（16 字节十六进制；参考等于会话 IV）。
    pub send_iv: String,
    /// 本端接收方向的掩蔽密钥材料。
    pub recv_key: String,
    /// 本端接收方向的 CTR IV。
    pub recv_iv: String,
}

impl fmt::Debug for NodeXelXorSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 密钥与 IV 都是会话材料 ⇒ 只报是否给出。
        f.debug_struct("NodeXelXorSettings")
            .field("send_key", &crate::config::redacted(&self.send_key))
            .field("send_iv", &crate::config::redacted(&self.send_iv))
            .field("recv_key", &crate::config::redacted(&self.recv_key))
            .field("recv_iv", &crate::config::redacted(&self.recv_iv))
            .finish()
    }
}

/// VLESS **XEL 记录层**配置（**仅 vless**）。
///
/// 密钥材料全部是凭据 ⇒ 不进 Debug 输出。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeXelSettings {
    /// AEAD 套件：`aes-256-gcm` / `chacha20-poly1305`（参考 `useAES` 二选一）。
    pub cipher: String,
    /// 本端发送方向的 AEAD 记录密钥（32 字节十六进制）。
    pub uplink_key: String,
    /// 本端接收方向的 AEAD 记录密钥（32 字节十六进制）。
    pub downlink_key: String,
    /// 可选的 XOR 头部掩蔽层（参考 `XorMode == 2`）。
    #[serde(default)]
    pub xor: Option<NodeXelXorSettings>,
}

impl fmt::Debug for NodeXelSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeXelSettings")
            .field("cipher", &self.cipher)
            .field("uplink_key", &crate::config::redacted(&self.uplink_key))
            .field("downlink_key", &crate::config::redacted(&self.downlink_key))
            .field("xor", &self.xor)
            .finish()
    }
}

/// 十六进制文本 → 字节数校验（大小写不敏感；只给长度，不回显内容）。
pub(crate) fn hex_len(
    text: &str,
    field: &str,
    want: usize,
    invalid: &impl Fn(&str) -> ConfigError,
) -> Result<(), ConfigError> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.len().is_multiple_of(2) || !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(&format!("{field} 不是合法十六进制文本")));
    }
    let got = compact.len() / 2;
    if got != want {
        return Err(invalid(&format!(
            "{field} 长度非法：{got} 字节，需要 {want} 字节"
        )));
    }
    Ok(())
}

impl NodeConfig {
    /// `xel` 段的协议范围与取值校验（fail-closed）。
    pub(crate) fn validate_xel(
        &self,
        invalid: &impl Fn(&str) -> ConfigError,
    ) -> Result<(), ConfigError> {
        let Some(xel) = &self.xel else {
            return Ok(());
        };
        if self.protocol != Protocol::Vless {
            return Err(invalid("xel 配置段只允许用于 vless 协议"));
        }
        if self.encryption.is_some() {
            return Err(invalid(
                "xel 与 vision.encryption 不能同时给出（二者都作用于 VLESS 记录层）",
            ));
        }
        match xel.cipher.as_str() {
            "aes-256-gcm" | "chacha20-poly1305" => {}
            other => {
                return Err(invalid(&format!(
                    "xel.cipher 未知：{other}（只支持 aes-256-gcm / chacha20-poly1305）"
                )))
            }
        }
        hex_len(&xel.uplink_key, "xel.uplink_key", 32, invalid)?;
        hex_len(&xel.downlink_key, "xel.downlink_key", 32, invalid)?;
        if let Some(xor) = &xel.xor {
            hex_len(&xor.send_key, "xel.xor.send_key", 32, invalid)?;
            hex_len(&xor.recv_key, "xel.xor.recv_key", 32, invalid)?;
            hex_len(&xor.send_iv, "xel.xor.send_iv", 16, invalid)?;
            hex_len(&xor.recv_iv, "xel.xor.recv_iv", 16, invalid)?;
        }
        Ok(())
    }
}
