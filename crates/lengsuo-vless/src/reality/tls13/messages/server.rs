//! ServerHello 的解析（RFC 8446 §4.1.3）。
//!
//! 参考实现：`xtls/reality` 的 `handshake_messages.go`
//! （`serverHelloMsg.unmarshal` / `serverHelloMsg.marshal`）。
//!
//! 从 [`super`] 拆出以符合 400 行软目标；公开 API 不变。

use super::{extension, take_ext, Cursor, MessageError, GROUP_X25519};

/// 服务端从 ServerHello 里解出的关键字段（客户端用）。
#[derive(Debug, Clone)]
pub struct ServerHelloInfo {
    /// `server_random`。
    pub random: [u8; 32],
    /// `legacy_session_id_echo`（必须与客户端发出的一致）。
    pub session_id: Vec<u8>,
    /// 选中的密码套件。
    pub cipher_suite: u16,
    /// 服务端的 X25519 key_share 公钥。
    pub x25519_key_share: Option<[u8; 32]>,
    /// `supported_versions` 扩展里的协商版本。
    pub supported_version: Option<u16>,
}

/// ServerHello 的 `key_share` 扩展解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerKeyShare {
    /// 正常形态：`group(2) + key_exchange(uint16 长度前缀)`。
    Share {
        /// 选中的命名组。
        group: u16,
        /// 对端的 `key_exchange` 字节（X25519 为 32 字节）。
        key: Vec<u8>,
    },
    /// HelloRetryRequest 形态：只有 `selected_group(2)`。
    HelloRetryRequest {
        /// 服务端要求客户端重发的组。
        selected_group: u16,
    },
}

/// 解析 **ServerHello** 的 `key_share` 扩展。
///
/// **与 ClientHello 的 `key_share` 布局不同**（RFC 8446 §4.2.8）：
///
/// * ClientHello：`client_shares`（uint16 长度前缀的**列表**）+ 若干
///   `KeyShareEntry`；
/// * ServerHello：**直接**是一条 `KeyShareEntry`，**没有**外层列表。
///
/// 对齐参考 `xtls/reality` `handshake_messages.go:952-964`
/// （`serverHelloMsg.unmarshal` 的 `case extensionKeyShare`）：
///
/// ```go
/// if len(extData) == 2 {
///     // HelloRetryRequest 格式：只有 selectedGroup
///     extData.ReadUint16(&m.selectedGroup)
/// } else {
///     extData.ReadUint16(&m.serverShare.group)
///     readUint16LengthPrefixed(&extData, &m.serverShare.data)
/// }
/// ```
pub fn parse_server_key_share(data: &[u8]) -> Result<ServerKeyShare, MessageError> {
    if data.len() == 2 {
        let mut cursor = Cursor::new(data);
        let selected_group = cursor.u16()?;
        return Ok(ServerKeyShare::HelloRetryRequest { selected_group });
    }
    let mut cursor = Cursor::new(data);
    let group = cursor.u16()?;
    let key = cursor.u16_vec()?;
    Ok(ServerKeyShare::Share {
        group,
        key: key.to_vec(),
    })
}

/// 解析 ServerHello 的握手消息载荷。
///
/// 对齐参考 `xtls/reality` 的 `serverHelloMsg.unmarshal`
/// （`handshake_messages.go:871`）。
pub fn parse_server_hello(body: &[u8]) -> Result<ServerHelloInfo, MessageError> {
    let mut cursor = Cursor::new(body);
    let _legacy_version = cursor.u16()?;
    let random_bytes = cursor.take(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_bytes);
    let session_id = cursor.u8_vec()?.to_vec();
    let cipher_suite = cursor.u16()?;
    let _compression = cursor.u8()?;
    let mut info = ServerHelloInfo {
        random,
        session_id,
        cipher_suite,
        x25519_key_share: None,
        supported_version: None,
    };
    if cursor.is_empty() {
        return Ok(info);
    }
    let exts = cursor.u16_vec()?;
    let mut exts = exts;
    while !exts.is_empty() {
        let (kind, data, rest) = take_ext(exts)?;
        exts = rest;
        match kind {
            extension::SUPPORTED_VERSIONS => {
                if data.len() >= 2 {
                    info.supported_version = Some(u16::from_be_bytes([data[0], data[1]]));
                }
            }
            extension::KEY_SHARE => {
                // ⛔ ServerHello 的 `key_share` **没有**外层 `client_shares`
                // 列表，必须走 ServerHello 专用的解析（参考
                // `handshake_messages.go:952-964`）。
                match parse_server_key_share(data)? {
                    ServerKeyShare::Share { group, key } => {
                        if group == GROUP_X25519 && key.len() == 32 {
                            let mut out = [0u8; 32];
                            out.copy_from_slice(&key);
                            info.x25519_key_share = Some(out);
                        }
                    }
                    ServerKeyShare::HelloRetryRequest { .. } => {
                        // 本仓不实现 HelloRetryRequest（见模块文档的「不实现」清单）。
                        // 参考的客户端在 `processServerHello` 里对
                        // `selectedGroup != 0` 会走 HRR 分支；本仓直接视为
                        // 「没有可用的 key_share」，由调用方报
                        // `KeyAgreementFailed`（fail-closed）。
                    }
                }
            }
            _ => {}
        }
    }
    Ok(info)
}
