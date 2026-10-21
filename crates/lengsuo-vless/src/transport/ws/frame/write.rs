//! 同源说明：本文件与 `crates/lengsuo-trojan/src/transport/ws/frame/write.rs` 同源
//! （逐字复制），后续应收敛到共享 crate。
//!
//! WebSocket 帧层的**写侧**：帧构造与分步写出。
//!
//! 一次 `poll_write` 的目标是把一整个帧（头 + 载荷）写完；`Pending` 时不丢
//! 字节。客户端方向**掩码**（RFC 6455 §5.3，4 字节随机掩码键逐字节 XOR），
//! 服务端方向不掩码。

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

use super::super::{random_key, FIN, LEN_16, LEN_64, MASK_BIT};

/// 写侧状态机：一次 `poll_write` 的目标是把 `frame`（头 + 载荷）全部写完。
pub(super) enum WriteState {
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

/// 构造一个帧：FIN + opcode；`masked` 时掩码位置 1 并逐字节 XOR 掩码（客户端），
/// 否则不掩码（服务端）。掩码键 4 字节（RFC 6455 §5.3）。
pub(super) fn encode_frame(opcode: u8, data: &[u8], masked: bool) -> WriteState {
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
pub(super) fn advance_write<W: AsyncWrite + Unpin>(
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
