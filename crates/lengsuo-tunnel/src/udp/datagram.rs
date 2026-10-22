//! 入站数据报的**首字节分流**（纯函数，不碰 IO）。
//!
//! # 为什么按首字节分流
//!
//! 同一个 UDP 端口上跑着两种线上格式：
//!
//! | 首字节 | 是什么 | 怎么解 |
//! |---|---|---|
//! | `0x01` | WireGuard 握手 initiation（148B） | **裸报文**，⛔ 不套 L3 帧头 |
//! | `0x02` | WireGuard 握手 response（92B） | 同上 |
//! | `0x03` | WireGuard cookie reply（64B） | 同上 |
//! | `0x4C` | L3 密文帧（魔数 `0x4C53` 大端 ⇒ 首字节 `0x4C`） | `decode_exact` |
//!
//! 对照参考 **wireguard-go**（MIT）`device/receive.go` 的 `RoutineHandshake`：
//! 它按报文**首字节的类型字段**分流（`MessageInitiationType` /
//! `MessageResponseType` / `MessageCookieReplyType` / `MessageTransportType`）。
//! 本模块只借这个**结构**，⛔ 不复制它的 IP/TUN 封装。
//!
//! # fail-closed
//!
//! - 空数据报 ⇒ [`DatagramError::Empty`]（连首字节都没有，**不猜**）；
//! - 未知首字节 ⇒ [`DatagramError::UnknownType`]（⛔ 不「尽力猜」，⛔ 不静默丢弃）；
//! - 判为 L3 帧但解不开 ⇒ [`DatagramError::Frame`]（**单包级**：只丢这一包）。
//!
//! ⛔ 裸握手**不**塞进 [`Frame`]：`Frame` 是 L3 结构，握手报文没有帧序号。

use lengsuo_link_core::frame::{decode_exact, Frame, FrameError, FRAME_HEADER_LEN, FRAME_MAGIC};

/// 帧头魔数的首字节（`0x4C53` 大端 ⇒ `0x4C`）。
const FRAME_MAGIC_FIRST: u8 = FRAME_MAGIC.to_be_bytes()[0];

/// 握手报文的种类（由首字节判定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    /// 握手 initiation（148 字节，首字节 `0x01`）。
    Initiation,
    /// 握手 response（92 字节，首字节 `0x02`）。
    Response,
    /// Cookie reply（64 字节，首字节 `0x03`）。
    Cookie,
}

impl HandshakeKind {
    /// 该种类的线上首字节。
    #[must_use]
    pub const fn first_byte(self) -> u8 {
        match self {
            Self::Initiation => 0x01,
            Self::Response => 0x02,
            Self::Cookie => 0x03,
        }
    }
}

/// 一个入站数据报的分类结果。
#[derive(Debug)]
pub enum Datagram {
    /// WireGuard 握手报文——**未**做 L3 帧解码。
    Handshake {
        /// 报文种类（由首字节判定）。
        kind: HandshakeKind,
    },
    /// L3 密文帧（已解码）。
    Frame(Frame),
}

/// 首字节分流失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DatagramError {
    /// 空数据报：连首字节都没有。
    #[error("数据报为空：无法按首字节分流")]
    Empty,
    /// 首字节既不是握手类型，也不是 L3 帧魔数。
    #[error("未知首字节 {first:#04x}：既不是握手类型也不是 L3 帧（{reason}）")]
    UnknownType {
        /// 数据报首字节。
        first: u8,
        /// 帧层给出的判词。
        reason: FrameError,
    },
    /// 判为 L3 帧但解不开（**单包级**）。
    #[error("L3 帧解码失败：{0}")]
    Frame(#[from] FrameError),
}

impl DatagramError {
    /// 帧层的判词（供上层把它包成「坏数据报」上报，**单包级**）。
    #[must_use]
    pub fn reason(&self) -> FrameError {
        match self {
            Self::Empty => FrameError::Incomplete {
                needed: FRAME_HEADER_LEN,
                available: 0,
            },
            Self::UnknownType { reason, .. } | Self::Frame(reason) => reason.clone(),
        }
    }
}

/// 按首字节给入站数据报分类（纯函数，不碰 IO）。
///
/// # Errors
/// - 空数据报 ⇒ [`DatagramError::Empty`]；
/// - 未知首字节 ⇒ [`DatagramError::UnknownType`]；
/// - 判为 L3 帧但解不开 ⇒ [`DatagramError::Frame`]（**单包级**，只丢这一包）。
pub fn classify(bytes: &[u8]) -> Result<Datagram, DatagramError> {
    let Some(&first) = bytes.first() else {
        return Err(DatagramError::Empty);
    };
    let kind = match first {
        0x01 => HandshakeKind::Initiation,
        0x02 => HandshakeKind::Response,
        0x03 => HandshakeKind::Cookie,
        FRAME_MAGIC_FIRST => {
            return decode_exact(bytes)
                .map(Datagram::Frame)
                .map_err(DatagramError::Frame);
        }
        _ => {
            return Err(DatagramError::UnknownType {
                first,
                reason: unknown_type_reason(bytes),
            });
        }
    };
    Ok(Datagram::Handshake { kind })
}

/// 未知首字节时的判词：与帧层同序（先看长度，再看魔数）。
fn unknown_type_reason(bytes: &[u8]) -> FrameError {
    if bytes.len() < FRAME_HEADER_LEN {
        FrameError::Incomplete {
            needed: FRAME_HEADER_LEN,
            available: bytes.len(),
        }
    } else {
        FrameError::BadMagic {
            expected: FRAME_MAGIC,
            got: u16::from_be_bytes([bytes[0], bytes[1]]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, Datagram, DatagramError, HandshakeKind};
    use lengsuo_link_core::frame::{Frame, FrameError, FrameType};

    #[test]
    fn initiation_first_byte_maps_to_initiation() {
        let bytes = [0x01u8; 148];
        assert!(matches!(
            classify(&bytes),
            Ok(Datagram::Handshake {
                kind: HandshakeKind::Initiation
            })
        ));
    }

    #[test]
    fn response_first_byte_maps_to_response() {
        let bytes = [0x02u8; 92];
        assert!(matches!(
            classify(&bytes),
            Ok(Datagram::Handshake {
                kind: HandshakeKind::Response
            })
        ));
    }

    #[test]
    fn cookie_first_byte_maps_to_cookie() {
        let bytes = [0x03u8; 64];
        assert!(matches!(
            classify(&bytes),
            Ok(Datagram::Handshake {
                kind: HandshakeKind::Cookie
            })
        ));
    }

    #[test]
    fn frame_magic_first_byte_decodes_to_frame() {
        let frame = Frame::new(FrameType::Data, 7, b"payload".to_vec());
        let bytes = frame.encode().expect("帧应当能编码");
        match classify(&bytes) {
            Ok(Datagram::Frame(got)) => {
                assert_eq!(got.seq, 7);
                assert_eq!(got.payload, b"payload");
            }
            other => panic!("应当解成帧，实际 {other:?}"),
        }
    }

    #[test]
    fn handshake_datagram_is_not_decoded_as_a_frame() {
        // 148 字节的握手**不**当帧解（长度差得远，若走 decode_exact 必然失败）。
        let bytes = [0x01u8; 148];
        assert!(!matches!(classify(&bytes), Ok(Datagram::Frame(_))));
    }

    #[test]
    fn unknown_first_byte_is_an_explicit_error() {
        let bytes = [0x99u8; 40];
        match classify(&bytes) {
            Err(DatagramError::UnknownType { first, reason }) => {
                assert_eq!(first, 0x99);
                assert!(
                    matches!(reason, FrameError::BadMagic { .. }),
                    "非魔数首字节的判词应当是 BadMagic，实际 {reason:?}"
                );
            }
            other => panic!("未知首字节必须明确报错，实际 {other:?}"),
        }
    }

    #[test]
    fn empty_datagram_is_an_explicit_error() {
        assert!(matches!(classify(&[]), Err(DatagramError::Empty)));
    }
}
