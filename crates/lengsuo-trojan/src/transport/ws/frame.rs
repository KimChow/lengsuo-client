//! WebSocket 帧层（RFC 6455）：`Frames<S>` 状态机与读写方向语义。
//!
//! 从 `ws/mod.rs` 拆出以满足单文件行数上限（软 400 / 硬 700）。
//! 方向由构造时的 `client` 决定；详见 `ws` 模块文档。
//!
//! 行数说明：本文件 502 行，略高于 400 软目标但远低于 700 硬上限。读侧状态机
//! （帧头→扩展长度→掩码键→载荷）、写侧状态机与方向语义**同属一个内聚单元**——
//! 读写两侧共享 `FIN/opcode/掩码` 常量与同一 `Frame` 语义，再拆会把常量与类型
//! 跨文件重复导出、反而降低可读性。`Connection`/`ServerConnection` 两个包装已拆
//! 到 `ws/mod.rs`。

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    random_key, FIN, LEN_16, LEN_64, MASK_BIT, MAX_FRAME_PAYLOAD, OPCODE_MASK, OP_BINARY, OP_CLOSE,
    OP_CONTINUATION, OP_PING, OP_PONG, OP_TEXT,
};

/// WebSocket 帧层核心：一个把字节流包成 RFC 6455 帧的双向适配器。
///
/// 方向由 `masked` 决定：客户端**发出掩码帧、收到不掩码帧**；服务端**收到掩码
/// 帧、发出不掩码帧**。读侧的掩码键剥离与写侧的掩码施加都按该标志执行，
/// 与参考 `connection`（客户端）和 gorilla `Upgrader`（服务端）一致。
pub struct Frames<S> {
    inner: S,
    /// 本端是否为“客户端方向”（发掩码 / 收不掩码）。
    client: bool,
    /// 当前帧剩余未读载荷。
    frame: Vec<u8>,
    frame_pos: usize,
    /// 分片拼接缓冲（continuation 帧）。
    fragments: Vec<u8>,
    /// 已收到 `Close`：读侧到此为止（EOF），不再读底层。
    closed: bool,
    read_state: ReadState,
    write_state: WriteState,
}

impl<S> Frames<S> {
    pub(crate) fn new(inner: S, client: bool) -> Self {
        Self {
            inner,
            client,
            frame: Vec::new(),
            frame_pos: 0,
            fragments: Vec::new(),
            closed: false,
            read_state: ReadState::Header {
                got: [0u8; 2],
                filled: 0,
            },
            write_state: WriteState::Idle,
        }
    }

    /// 对端是否应当掩码：客户端读服务端（不掩码）；服务端读客户端（掩码）。
    fn expect_masked(&self) -> bool {
        !self.client
    }

    /// 本端写出的帧是否掩码：客户端掩码，服务端不掩码。
    fn write_masked(&self) -> bool {
        self.client
    }
}

/// 读侧状态机：`Header` 累积 2 字节帧头，`Extended` 读扩展长度，`Mask` 读掩码键
/// （仅在对端应掩码时），`Payload` 读载荷。
enum ReadState {
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

/// 写侧状态机：一次 `poll_write` 的目标是把 `frame`（头 + 载荷）全部写完。
enum WriteState {
    Idle,
    Writing {
        frame: Vec<u8>,
        offset: usize,
        user: usize,
    },
}

/// 把 `src[offset..]` 写进 `inner`，返回是否全部写完；`Poll::Pending` 原样上抛。
fn poll_write_rest<W: AsyncWrite + Unpin>(
    inner: &mut W,
    src: &[u8],
    offset: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<std::io::Result<()>> {
    while *offset < src.len() {
        match Pin::new(&mut *inner).poll_write(cx, &src[*offset..]) {
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "底层写入返回 0",
                )))
            }
            Poll::Ready(Ok(written)) => *offset += written,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

impl<S: AsyncRead + Unpin> AsyncRead for Frames<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1) 优先交付当前帧剩余载荷。
            if this.frame_pos < this.frame.len() {
                let take = (this.frame.len() - this.frame_pos).min(buf.remaining());
                buf.put_slice(&this.frame[this.frame_pos..this.frame_pos + take]);
                this.frame_pos += take;
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            // 2) 推进读状态机。
            let expect_masked = this.expect_masked();
            match poll_read_state(&mut this.inner, &mut this.read_state, expect_masked, cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(frame) => match frame {
                    Frame::Data { fin, payload } => {
                        this.fragments.extend_from_slice(&payload);
                        if fin {
                            this.frame = std::mem::take(&mut this.fragments);
                            this.frame_pos = 0;
                        } // 未 fin：继续读下一分片（循环回状态机）。
                    }
                    Frame::Close => {
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    // Ping/Pong 不携带应用数据：忽略（参考默认读循环亦不把它们
                    // 交给上层）。服务端不会主动 Ping（heartbeat 默认关闭）。
                    Frame::Ping | Frame::Pong => {}
                },
            }
        }
    }
}

/// 驱动一帧的读取状态机；返回完整帧或 `Pending`。
fn poll_read_state<R: AsyncRead + Unpin>(
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

enum Frame {
    Data {
        fin: bool,
        payload: Vec<u8>,
    },
    Close,
    /// Ping/Pong 控制帧：载荷不参与应用数据（参考默认读循环自动回 Pong；
    /// trojan 客户端不使用 Ping，服务端 heartbeat 默认关闭）。
    Ping,
    Pong,
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Frames<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if !matches!(this.write_state, WriteState::Idle) {
            match advance_write(&mut this.inner, &mut this.write_state, cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(user) => return Poll::Ready(Ok(user)),
            }
        }
        let masked = this.write_masked();
        this.write_state = encode_frame(OP_BINARY, data, masked);
        match advance_write(&mut this.inner, &mut this.write_state, cx)? {
            Poll::Pending => Poll::Pending,
            Poll::Ready(user) => Poll::Ready(Ok(user)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !matches!(this.write_state, WriteState::Idle) {
            match advance_write(&mut this.inner, &mut this.write_state, cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(_) => {}
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 参考 `connection.Close`：先发 Close 帧，再关底层写侧。
        let this = self.get_mut();
        if !matches!(this.write_state, WriteState::Idle) {
            match advance_write(&mut this.inner, &mut this.write_state, cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(_) => {}
            }
        }
        let masked = this.write_masked();
        this.write_state = encode_frame(OP_CLOSE, &[], masked);
        match advance_write(&mut this.inner, &mut this.write_state, cx)? {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(_) => {}
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// 构造一个帧：FIN + opcode；`masked` 时掩码位置 1 并逐字节 XOR 掩码（客户端），
/// 否则不掩码（服务端）。掩码键 4 字节（RFC 6455 §5.3）。
fn encode_frame(opcode: u8, data: &[u8], masked: bool) -> WriteState {
    let key = random_key();
    let mask = [key[0], key[1], key[2], key[3]];
    let mut header = Vec::with_capacity(14);
    header.push(FIN | opcode);
    let len = data.len();
    let mask_flag = if masked { MASK_BIT } else { 0 };
    if len < LEN_16 as usize {
        header.push(mask_flag | len as u8);
    } else if len <= u16::MAX as usize {
        header.push(mask_flag | LEN_16);
        header.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        header.push(mask_flag | LEN_64);
        header.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mut frame = header;
    if masked {
        frame.extend_from_slice(&mask);
        frame.extend(
            data.iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
    } else {
        frame.extend_from_slice(data);
    }
    WriteState::Writing {
        frame,
        offset: 0,
        user: data.len(),
    }
}

/// 推进帧写出，写完整个 `frame` 后回到 `Idle` 并返回本次用户字节数。
fn advance_write<W: AsyncWrite + Unpin>(
    inner: &mut W,
    state: &mut WriteState,
    cx: &mut Context<'_>,
) -> Poll<std::io::Result<usize>> {
    let WriteState::Writing {
        frame,
        offset,
        user,
    } = state
    else {
        return Poll::Ready(Ok(0));
    };
    match poll_write_rest(inner, frame, offset, cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => {}
    }
    let user = *user;
    *state = WriteState::Idle;
    Poll::Ready(Ok(user))
}
