//! 同源说明：本文件与 `crates/lengsuo-trojan/src/transport/ws/frame/read.rs` 同源
//! （逐字复制），后续应收敛到共享 crate。
//!
//! WebSocket 帧层的**读侧**状态机：帧头 → 扩展长度 → 掩码键 → 载荷。
//!
//! 方向语义由 `expect_masked` 决定：客户端读服务端（不掩码）；服务端读客户端
//! （掩码）。掩码键在载荷装配后逐字节 XOR 剥离（RFC 6455 §5.3）。

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

use super::super::{
    FIN, LEN_16, LEN_64, MASK_BIT, MAX_FRAME_PAYLOAD, OPCODE_MASK, OP_BINARY, OP_CLOSE,
    OP_CONTINUATION, OP_PING, OP_PONG, OP_TEXT,
};

/// 读侧状态机：`Header` 累积 2 字节帧头，`Extended` 读扩展长度，`Mask` 读掩码键
/// （仅在对端应掩码时），`Payload` 读载荷。
pub(super) enum ReadState {
    Header {
        got: [u8; 2],
        filled: usize,
    },
    Extended {
        header: [u8; 2],
        extra: usize,
        got: Vec<u8>,
        masked: bool,
    },
    Mask {
        header: [u8; 2],
        length: usize,
        masked: bool,
        got: [u8; 4],
        filled: usize,
    },
    Payload {
        header: [u8; 2],
        length: usize,
        got: Vec<u8>,
        mask: Option<[u8; 4]>,
    },
}

/// 驱动一帧的读取状态机；返回完整帧或 `Pending`。
pub(super) fn poll_read_state<R: AsyncRead + Unpin>(
    inner: &mut R,
    state: &mut ReadState,
    expect_masked: bool,
    cx: &mut Context<'_>,
) -> std::io::Result<Poll<Frame>> {
    loop {
        match state {
            ReadState::Header { got, filled } => {
                let mut temp = ReadBuf::new(&mut got[*filled..]);
                match Pin::new(&mut *inner).poll_read(cx, &mut temp)? {
                    Poll::Pending => return Ok(Poll::Pending),
                    Poll::Ready(()) => {
                        let read = temp.filled().len();
                        if read == 0 {
                            return Err(eof("帧头"));
                        }
                        *filled += read;
                        if *filled < 2 {
                            continue;
                        }
                        let header = *got;
                        let masked = header[1] & MASK_BIT != 0;
                        if masked != expect_masked {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                if expect_masked {
                                    "对端帧未掩码"
                                } else {
                                    "对端帧不得掩码"
                                },
                            ));
                        }
                        match header[1] & 0x7f {
                            LEN_16 => {
                                *state = ReadState::Extended {
                                    header,
                                    extra: 2,
                                    got: Vec::with_capacity(2),
                                    masked,
                                }
                            }
                            LEN_64 => {
                                *state = ReadState::Extended {
                                    header,
                                    extra: 8,
                                    got: Vec::with_capacity(8),
                                    masked,
                                }
                            }
                            small => {
                                *state = ReadState::Mask {
                                    header,
                                    length: small as usize,
                                    masked,
                                    got: [0u8; 4],
                                    filled: 0,
                                }
                            }
                        }
                    }
                }
            }
            ReadState::Extended {
                header,
                extra,
                got,
                masked,
            } => {
                let mut buf = [0u8; 8];
                let want = *extra - got.len();
                let mut temp = ReadBuf::new(&mut buf[..want]);
                match Pin::new(&mut *inner).poll_read(cx, &mut temp)? {
                    Poll::Pending => return Ok(Poll::Pending),
                    Poll::Ready(()) => {
                        let read = temp.filled().len();
                        if read == 0 {
                            return Err(eof("扩展长度"));
                        }
                        got.extend_from_slice(&buf[..read]);
                        if got.len() < *extra {
                            continue;
                        }
                        let length = if *extra == 2 {
                            u16::from_be_bytes([got[0], got[1]]) as usize
                        } else {
                            let mut bytes = [0u8; 8];
                            bytes.copy_from_slice(&got[..8]);
                            let value = u64::from_be_bytes(bytes);
                            if value > MAX_FRAME_PAYLOAD as u64 {
                                return Err(frame_too_large());
                            }
                            value as usize
                        };
                        if length > MAX_FRAME_PAYLOAD {
                            return Err(frame_too_large());
                        }
                        *state = ReadState::Mask {
                            header: *header,
                            length,
                            masked: *masked,
                            got: [0u8; 4],
                            filled: 0,
                        };
                    }
                }
            }
            ReadState::Mask {
                header,
                length,
                masked,
                got,
                filled,
            } => {
                if *masked {
                    let mut temp = ReadBuf::new(&mut got[*filled..]);
                    match Pin::new(&mut *inner).poll_read(cx, &mut temp)? {
                        Poll::Pending => return Ok(Poll::Pending),
                        Poll::Ready(()) => {
                            let read = temp.filled().len();
                            if read == 0 {
                                return Err(eof("掩码键"));
                            }
                            *filled += read;
                            if *filled < 4 {
                                continue;
                            }
                        }
                    }
                }
                let mask = if *masked { Some(*got) } else { None };
                *state = ReadState::Payload {
                    header: *header,
                    length: *length,
                    got: Vec::with_capacity(*length),
                    mask,
                };
            }
            ReadState::Payload {
                header,
                length,
                got,
                mask,
            } => {
                // 零长度载荷（如 Close/Ping/Pong 控制帧）：不触碰底层，直接装配。
                if got.len() < *length {
                    let remaining = *length - got.len();
                    let mut stash = vec![0u8; remaining];
                    let mut temp = ReadBuf::new(&mut stash);
                    match Pin::new(&mut *inner).poll_read(cx, &mut temp)? {
                        Poll::Pending => return Ok(Poll::Pending),
                        Poll::Ready(()) => {
                            let read = temp.filled().len();
                            if read == 0 {
                                return Err(eof("载荷"));
                            }
                            got.extend_from_slice(&stash[..read]);
                            if got.len() < *length {
                                continue;
                            }
                        }
                    }
                }
                let mut payload = std::mem::take(got);
                if let Some(mask) = mask {
                    for (index, byte) in payload.iter_mut().enumerate() {
                        *byte ^= mask[index % 4];
                    }
                }
                let frame = finish_frame(*header, payload, mask.is_some())?;
                *state = ReadState::Header {
                    got: [0u8; 2],
                    filled: 0,
                };
                return Ok(Poll::Ready(frame));
            }
        }
    }
}

fn eof(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        format!("{what}读尽（EOF）"),
    )
}

fn frame_too_large() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "帧超长")
}

/// 由帧头与（已解掩码的）载荷装配语义化 `Frame`；opcode 非法即拒绝。
fn finish_frame(header: [u8; 2], payload: Vec<u8>, _masked: bool) -> std::io::Result<Frame> {
    let fin = header[0] & FIN != 0;
    match header[0] & OPCODE_MASK {
        OP_BINARY | OP_TEXT | OP_CONTINUATION => Ok(Frame::Data { fin, payload }),
        OP_CLOSE => Ok(Frame::Close),
        OP_PING => Ok(Frame::Ping),
        OP_PONG => Ok(Frame::Pong),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "未知 opcode",
        )),
    }
}

pub(super) enum Frame {
    Data {
        fin: bool,
        payload: Vec<u8>,
    },
    Close,
    /// Ping/Pong 控制帧：载荷不参与应用数据（参考默认读循环自动回 Pong；
    /// VLESS 客户端不使用 Ping，服务端 heartbeat 默认关闭）。
    Ping,
    Pong,
}
