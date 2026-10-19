//! Trojan UDP 关联（UDP ASSOCIATE）报文编解码，纯函数、不触网、可独立单测。
//!
//! 线上格式与参考实现一致（Xray v26.3.27，完整 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，`proxy/trojan/protocol.go`）：
//! 请求头里 `command=0x03` 表示 UDP 关联；关联建立后，每个数据报在流上按
//!
//! ```text
//! SOCKS 地址+端口(ATYP 长度可变) 长度(2 字节大端) CRLF 载荷
//! ```
//!
//! 成帧。地址复用 `ss_core::target::TargetAddr` 的 `encode_checked` / `decode`，
//! 不复制地址实现；一个数据包一个地址，不缓存任何“首包地址”。
//!
//! 安全边界：所有输入都按不可信处理。长度前缀与实际字节不符、地址类型非法、
//! 地址长度越界、UTF-8 非法域名一律 fail-closed（返回错误而非截断转发），
//! 全程无 panic / unwrap / 越界索引；`decode_packet` 以在缓冲区上划分切片的方式
//! 解析，不复制载荷。

use ss_core::target::TargetAddr;

/// 两处 CRLF 分隔符，与线上格式一致。
pub const CRLF: [u8; 2] = *b"\r\n";

/// 载荷长度前缀宽度（2 字节大端）。
pub const LENGTH_PREFIX: usize = 2;

/// 线上长度字段可表示的最大载荷字节数（`u16::MAX`）。
/// 参考 `protocol.go` 的 `maxLength = 8192` 是**服务端入站策略**，不在 codec 强制，
/// 由转发侧按需施加（见 `udp_relay` 与 `crate::stream::REFERENCE_MAX_DATAGRAM_PAYLOAD`）。
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

/// UDP 报文编解码错误。地址格式错误透传 `ss_core::Error`，故不派生 `PartialEq`。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("报文缓冲需要 {need} 字节，实际 {got}")]
    Truncated { need: usize, got: usize },

    #[error("载荷长度 {0} 超过 2 字节大端上限")]
    Oversize(usize),

    #[error("长度前缀与实际字节不符：声明 {declared}，实到 {available}")]
    LengthMismatch { declared: usize, available: usize },

    #[error("偏移 {offset} 处缺少 CRLF")]
    InvalidCrlf { offset: usize },

    #[error("目标地址非法：{0}")]
    Address(#[from] ss_core::Error),
}

/// 编码一个 UDP 数据报：地址 + 2 字节大端长度 + CRLF + 载荷。
///
/// 载荷超过 `MAX_PAYLOAD_LEN`（65535）在分配前拒绝，fail-closed，不截断。
/// `encode_checked` 在写入任何字节前拒绝空/超长/含 NUL 的域名。
pub fn encode_packet(target: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(Error::Oversize(payload.len()));
    }
    let total = target
        .encoded_len()
        .checked_add(LENGTH_PREFIX + CRLF.len() + payload.len())
        .ok_or(Error::Oversize(payload.len()))?;
    let mut frame = Vec::with_capacity(total);
    target.encode_checked(&mut frame)?;
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&CRLF);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// 解码一个 UDP 数据报报文。
///
/// 成功返回 `((目标地址, 载荷切片), 报文消耗字节数)`，载荷是 `input` 的切片，
/// 不复制；`input` 尾部可以粘着后续报文（多帧背靠背）或该关联的收尾字节。
/// 返回的消耗长度**恰等于**声明长度加前缀，因此解码器知道流上还剩多少。
///
/// 解析顺序刻意对齐参考 `PacketReader.ReadMultiBuffer`：地址 → 长度 → CRLF → 载荷。
/// 长度前缀超过 `max_payload` 立即拒绝（不读载荷、不回退）；长度超出实际可用字节
/// 报 `LengthMismatch`（区别于“缓冲还不够”的 `Truncated`）。
pub fn decode_packet(
    input: &[u8],
    max_payload: usize,
) -> Result<((TargetAddr, &[u8]), usize), Error> {
    let (target, addr_len) = decode_address(input)?;
    let cursor = addr_len;
    let word = input
        .get(cursor..cursor + LENGTH_PREFIX)
        .ok_or_else(|| truncated(input, cursor + LENGTH_PREFIX))?;
    let declared = usize::from(u16::from_be_bytes([word[0], word[1]]));
    // 容量/策略上限先于任何载荷寻址判断。
    if declared > max_payload {
        return Err(Error::Oversize(declared));
    }
    let crlf_at = cursor + LENGTH_PREFIX;
    let crlf = input
        .get(crlf_at..crlf_at + CRLF.len())
        .ok_or_else(|| truncated(input, crlf_at + CRLF.len()))?;
    if crlf != CRLF {
        return Err(Error::InvalidCrlf { offset: crlf_at });
    }
    let payload_at = crlf_at + CRLF.len();
    let end = payload_at
        .checked_add(declared)
        .ok_or(Error::Oversize(declared))?;
    if input.len() < end {
        return Err(Error::LengthMismatch {
            declared,
            available: input.len().saturating_sub(payload_at),
        });
    }
    Ok(((target, &input[payload_at..end]), end))
}

/// 解析 SOCKS 地址，返回（地址，地址部分消耗字节数）。
fn decode_address(input: &[u8]) -> Result<(TargetAddr, usize), Error> {
    TargetAddr::decode(input).map_err(|error| match error {
        ss_core::Error::TooShort { need, .. } => truncated(input, need),
        other => Error::Address(other),
    })
}

/// 缓冲不足错误：`need` 为完成当前结构所需的最小字节数。
fn truncated(input: &[u8], need: usize) -> Error {
    Error::Truncated {
        need,
        got: input.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 不经被测实现手工拼帧，用于固定字节与损坏用例；地址均为已构造的合法值。
    fn raw(target: &TargetAddr, declared: u16, payload: &[u8], crlf: [u8; 2]) -> Vec<u8> {
        let mut buf = Vec::new();
        target.encode_into(&mut buf);
        buf.extend_from_slice(&declared.to_be_bytes());
        buf.extend_from_slice(&crlf);
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn ipv4_roundtrip() {
        let target = TargetAddr::V4([192, 0, 2, 1], 53);
        let frame = encode_packet(&target, b"ping").unwrap();
        assert_eq!(
            frame,
            vec![0x01, 192, 0, 2, 1, 0, 53, 0, 4, b'\r', b'\n', b'p', b'i', b'n', b'g']
        );
        let ((addr, payload), used) = decode_packet(&frame, MAX_PAYLOAD_LEN).unwrap();
        assert_eq!(addr, target);
        assert_eq!(payload, b"ping");
        assert_eq!(used, frame.len());
    }

    #[test]
    fn ipv6_roundtrip() {
        let target = TargetAddr::V6(
            [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            443,
        );
        let frame = encode_packet(&target, b"\x00\xff\x7f").unwrap();
        let ((addr, payload), used) = decode_packet(&frame, MAX_PAYLOAD_LEN).unwrap();
        assert_eq!(addr, target);
        assert_eq!(payload, b"\x00\xff\x7f");
        assert_eq!(used, frame.len());
    }

    #[test]
    fn domain_roundtrip() {
        let target = TargetAddr::Domain("example.com".to_owned(), 8080);
        let frame = encode_packet(&target, b"query").unwrap();
        // ATYP 0x03 + 长度 11 + 域名 + 端口 8080(0x1F90)。
        assert_eq!(frame[0], 0x03);
        assert_eq!(frame[1], 11);
        assert_eq!(&frame[2..13], b"example.com");
        assert_eq!(&frame[13..15], &8080u16.to_be_bytes());
        let ((addr, payload), used) = decode_packet(&frame, MAX_PAYLOAD_LEN).unwrap();
        assert_eq!(addr, target);
        assert_eq!(payload, b"query");
        assert_eq!(used, frame.len());
    }

    #[test]
    fn zero_length_packet_roundtrip() {
        // 零长度是 keepalive 语义：合法，载荷为空，仍带地址。
        let target = TargetAddr::V4([127, 0, 0, 1], 9);
        let frame = encode_packet(&target, b"").unwrap();
        assert_eq!(frame.len(), target.encoded_len() + 2 + 2);
        let ((addr, payload), used) = decode_packet(&frame, MAX_PAYLOAD_LEN).unwrap();
        assert_eq!(addr, target);
        assert!(payload.is_empty());
        assert_eq!(used, frame.len());
    }

    #[test]
    fn max_length_packet_roundtrip() {
        let target = TargetAddr::V4([10, 0, 0, 1], 53);
        let payload = vec![0x5a; MAX_PAYLOAD_LEN];
        let frame = encode_packet(&target, &payload).unwrap();
        assert_eq!(
            &frame[target.encoded_len()..target.encoded_len() + 2],
            &[0xff, 0xff]
        );
        let ((addr, decoded), used) = decode_packet(&frame, MAX_PAYLOAD_LEN).unwrap();
        assert_eq!(addr, target);
        assert_eq!(decoded.len(), MAX_PAYLOAD_LEN);
        assert_eq!(used, frame.len());
    }

    #[test]
    fn send_oversize_rejected_before_alloc() {
        let target = TargetAddr::V4([10, 0, 0, 1], 53);
        let payload = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert!(matches!(
            encode_packet(&target, &payload),
            Err(Error::Oversize(_))
        ));
    }

    #[test]
    fn receive_over_limit_rejected() {
        let target = TargetAddr::V4([10, 0, 0, 1], 53);
        let frame = encode_packet(&target, &[0u8; 16]).unwrap();
        // 上限 15 < 声明 16：在触碰载荷前拒绝。
        assert!(matches!(
            decode_packet(&frame, 15),
            Err(Error::Oversize(16))
        ));
    }

    #[test]
    fn length_prefix_disagrees_with_bytes() {
        // 声明 8 字节载荷，实到 3 字节：fail-closed，不截断转发。
        let target = TargetAddr::V4([192, 0, 2, 9], 53);
        let frame = raw(&target, 8, b"abc", *b"\r\n");
        match decode_packet(&frame, MAX_PAYLOAD_LEN) {
            Err(Error::LengthMismatch {
                declared: 8,
                available: 3,
            }) => {}
            other => panic!("期望 LengthMismatch，得到 {other:?}"),
        }
    }

    #[test]
    fn invalid_address_type_rejected() {
        // ATYP 0x05 非法：立即拒绝，不猜长度。
        let frame = [0x05u8, 1, 2, 3, 4, 0, 53, 0, 1, b'\r', b'\n', 0x41];
        assert!(matches!(
            decode_packet(&frame, MAX_PAYLOAD_LEN),
            Err(Error::Address(ss_core::Error::InvalidAddressType(0x05)))
        ));
    }

    #[test]
    fn invalid_utf8_domain_rejected() {
        // 域名含非法 UTF-8 序列 0xff：地址解析阶段 fail-closed。
        let mut frame = vec![0x03u8, 3];
        frame.extend_from_slice(&[0xff, 0xfe, 0x00]);
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        assert!(matches!(
            decode_packet(&frame, MAX_PAYLOAD_LEN),
            Err(Error::Address(ss_core::Error::InvalidLength(3)))
        ));
    }

    #[test]
    fn address_length_overflow_rejected() {
        // 域名长度字段 16 字节，但缓冲只有 2 字节：地址长度越界 fail-closed。
        let frame = [0x03u8, 16];
        match decode_packet(&frame, MAX_PAYLOAD_LEN) {
            Err(Error::Truncated { need: 20, got: 2 }) => {}
            other => panic!("期望域名地址截断，得到 {other:?}"),
        }
    }

    #[test]
    fn truncated_length_and_crlf_rejected() {
        let target = TargetAddr::V4([192, 0, 2, 1], 53);
        // 只有地址 + 1 字节长度字段：缺第二字节。
        let mut short = Vec::new();
        target.encode_into(&mut short);
        short.push(0x00);
        let addr_len = target.encoded_len();
        assert!(matches!(
            decode_packet(&short, MAX_PAYLOAD_LEN),
            Err(Error::Truncated { need, got }) if need == addr_len + 2 && got == addr_len + 1
        ));
        // 缺 CRLF：长度字段之后不足 2 字节。
        let mut no_crlf = Vec::new();
        target.encode_into(&mut no_crlf);
        no_crlf.extend_from_slice(&1u16.to_be_bytes());
        no_crlf.push(b'\r');
        assert!(matches!(
            decode_packet(&no_crlf, MAX_PAYLOAD_LEN),
            Err(Error::Truncated { need, .. }) if need == addr_len + 2 + 2
        ));
    }

    #[test]
    fn bad_crlf_rejected() {
        let target = TargetAddr::V4([192, 0, 2, 1], 53);
        let frame = raw(&target, 1, b"A", *b"\n\r");
        assert!(matches!(
            decode_packet(&frame, MAX_PAYLOAD_LEN),
            Err(Error::InvalidCrlf { .. })
        ));
    }

    #[test]
    fn back_to_back_frames_advance_exactly() {
        // 同一关联里两个不同目标背靠背，解码器按返回长度精确推进，不缓存首包地址。
        let first = TargetAddr::V4([192, 0, 2, 1], 53);
        let second = TargetAddr::V4([198, 51, 100, 2], 4444);
        let mut stream = encode_packet(&first, b"one").unwrap();
        stream.extend_from_slice(&encode_packet(&second, b"two").unwrap());
        let ((a1, p1), used1) = decode_packet(&stream, MAX_PAYLOAD_LEN).unwrap();
        let ((a2, p2), used2) = decode_packet(&stream[used1..], MAX_PAYLOAD_LEN).unwrap();
        assert_eq!((a1, p1), (first, b"one".as_slice()));
        assert_eq!((a2, p2), (second, b"two".as_slice()));
        assert_eq!(used1 + used2, stream.len());
    }

    #[test]
    fn trailing_bytes_not_consumed() {
        // 一帧之后粘着下一个报文的起始字节：解码只消耗恰好本帧长度。
        let target = TargetAddr::Domain("a.example".to_owned(), 1);
        let mut stream = encode_packet(&target, b"xyz").unwrap();
        let frame_len = stream.len();
        stream.extend_from_slice(&[0x03, 0xff, 0xde]);
        let ((_, payload), used) = decode_packet(&stream, MAX_PAYLOAD_LEN).unwrap();
        assert_eq!(payload, b"xyz");
        assert_eq!(used, frame_len);
    }

    #[test]
    fn empty_input_truncated() {
        assert!(matches!(
            decode_packet(&[], MAX_PAYLOAD_LEN),
            Err(Error::Truncated { need: 1, got: 0 })
        ));
    }
}
