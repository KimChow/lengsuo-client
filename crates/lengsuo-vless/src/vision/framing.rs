//! VLESS Vision 流量层共用纯函数：`IsCompleteRecord` 与 `ReshapeMultiBuffer` 的
//! 扁平单缓冲等价物，以及它们共享的 framing 常量。无状态、不触碰
//! [`super::client::TrafficState`]，供 [`super::client::VisionClient`] 上行写使用。

use super::client::BUF_SIZE;

/// 参考 `XtlsPadding`：16 字节 UUID + 5 字节块头。
pub(crate) const PADDING_OVERHEAD: usize = 21;
/// 参考 `proxy.go` 的 `TlsApplicationDataStart`。
pub(crate) const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

/// 参考 `IsCompleteRecord`（作用于单块扁平字节）。
pub fn is_complete_record(buffer: &[u8]) -> bool {
    let total_len = buffer.len();
    let mut header_len = 5usize;
    let mut record_len = 0usize;
    let mut i = 0usize;
    while i < total_len {
        if header_len > 0 {
            let data = buffer[i];
            i += 1;
            match header_len {
                5 => {
                    if data != 0x17 {
                        return false;
                    }
                }
                4 => {
                    if data != 0x03 {
                        return false;
                    }
                }
                3 => {
                    if data != 0x03 {
                        return false;
                    }
                }
                2 => record_len = usize::from(data) << 8,
                1 => record_len |= usize::from(data),
                _ => {}
            }
            header_len -= 1;
        } else if record_len > 0 {
            let remaining = total_len - i;
            if remaining < record_len {
                return false;
            }
            i += record_len;
            record_len = 0;
            header_len = 5;
        } else {
            return false;
        }
    }
    header_len == 5 && record_len == 0
}

/// 参考 `ReshapeMultiBuffer`（单 buffer 扁平等价）：`len >= buf.Size-21`（8171）的
/// 缓冲在最后一次 TLS 应用数据记录起点、否则在 `buf.Size/2`（4096）处拆段，保证每段
/// `contentLen <= 8171` 后 `paddingLen` 不会跌到负。参考假定缓冲本身 `<= buf.Size`
/// 因而只拆一次；本实现对超长扁平入参循环拆分，纯防御（正常 `buf.Writer` 语义下到不了），
/// 不影响 `<= 8192` 的行为。
pub(crate) fn reshape_payload(payload: &[u8]) -> Vec<&[u8]> {
    let mut pieces = vec![payload];
    let mut index = 0usize;
    while index < pieces.len() {
        let piece = pieces[index];
        if piece.len() < BUF_SIZE - PADDING_OVERHEAD {
            index += 1;
            continue;
        }
        let mut split = BUF_SIZE / 2;
        if let Some(start) = piece
            .windows(TLS_APPLICATION_DATA_START.len())
            .rposition(|window| window == TLS_APPLICATION_DATA_START)
        {
            if (PADDING_OVERHEAD..=BUF_SIZE - PADDING_OVERHEAD).contains(&start) {
                split = start;
            }
        }
        let (left, right) = piece.split_at(split);
        pieces[index] = left;
        pieces.insert(index + 1, right);
        index += 1;
    }
    pieces
}
