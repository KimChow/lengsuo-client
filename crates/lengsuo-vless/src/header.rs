//! 基线：Xray v26.3.27 / d2758a023cd7f4174a5a5fa4ff66e487d4342ba0。
//! VLESS 地址使用端口在前，IPv4=1、域名=2、IPv6=3。
use ss_core::target::TargetAddr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("报文尚未完整")]
    Incomplete,
    #[error("不支持的协议字段")]
    Unsupported,
    #[error("非法目标地址")]
    InvalidAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Tcp = 1,
    Udp = 2,
    Mux = 3,
}

/// 不包含凭据，避免派生 Debug 意外输出用户标识。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub target: TargetAddr,
}

/// 请求 addons 的 Flow 字段（`encoding.Addons`，protobuf `Addons.Flow`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// 不携带 addons（addons 长度 0）。
    None,
    /// `xtls-rprx-vision`。
    XtlsRprxVision,
}

const FLOW_XTLS_RPRX_VISION: &[u8] = b"xtls-rprx-vision";

/// 先完成校验再返回报文；调用方负责通过认证 TLS 发送。
pub fn encode(request: &Request, credential: &[u8; 16]) -> Result<Vec<u8>, Error> {
    encode_with_flow(request, credential, Flow::None)
}

/// 与 [`encode`] 相同，另支持 `flow=xtls-rprx-vision` 的请求 addons。
///
/// 参考 `EncodeHeaderAddons`：vision 时先写 addons 长度字节 `0x12`，再写
/// protobuf 载荷 `[0x0A, 0x10] + "xtls-rprx-vision"`（共 18 字节）。
pub fn encode_with_flow(
    request: &Request,
    credential: &[u8; 16],
    flow: Flow,
) -> Result<Vec<u8>, Error> {
    let mut result = Vec::with_capacity(280);
    result.push(0);
    result.extend_from_slice(credential);
    if flow == Flow::XtlsRprxVision {
        // 参考 `EncodeHeaderAddons`：先 addons 长度字节（= 载荷 18 字节），再载荷。
        let addons_len = 2 + FLOW_XTLS_RPRX_VISION.len(); // 0x0A, 0x10 + 16 字节 flow
        result.push(addons_len as u8);
        result.push(0x0A);
        result.push(FLOW_XTLS_RPRX_VISION.len() as u8);
        result.extend_from_slice(FLOW_XTLS_RPRX_VISION);
    } else {
        result.push(0);
    }
    result.push(request.command as u8);
    if request.command == Command::Mux {
        return Ok(result);
    }
    encode_address(&request.target, &mut result)?;
    Ok(result)
}

pub(crate) fn encode_address(target: &TargetAddr, result: &mut Vec<u8>) -> Result<(), Error> {
    match target {
        TargetAddr::V4(ip, port) => {
            result.extend_from_slice(&port.to_be_bytes());
            result.push(1);
            result.extend_from_slice(ip);
        }
        TargetAddr::Domain(host, port) => {
            validate_domain(host)?;
            result.extend_from_slice(&port.to_be_bytes());
            result.extend_from_slice(&[2, host.len() as u8]);
            result.extend_from_slice(host.as_bytes());
        }
        TargetAddr::V6(ip, port) => {
            result.extend_from_slice(&port.to_be_bytes());
            result.push(3);
            result.extend_from_slice(ip);
        }
    }
    Ok(())
}

fn validate_domain(host: &str) -> Result<(), Error> {
    if host.is_empty() || host.len() > 255 || host.contains('\0') {
        return Err(Error::InvalidAddress);
    }
    Ok(())
}

/// 只解析头部并返回消耗长度，不吞掉同一 TCP 分段中的应用数据。
/// 用户标识在返回值中单独交给认证层，禁止记录日志。
pub fn decode(input: &[u8]) -> Result<([u8; 16], Request, usize), Error> {
    let mut cursor = Cursor { input, offset: 0 };
    if cursor.byte()? != 0 {
        return Err(Error::Unsupported);
    }
    let credential = cursor.take(16)?.try_into().expect("固定长度");
    if cursor.byte()? != 0 {
        return Err(Error::Unsupported);
    }
    let command = match cursor.byte()? {
        1 => Command::Tcp,
        2 => Command::Udp,
        3 => Command::Mux,
        _ => return Err(Error::Unsupported),
    };
    if command == Command::Mux {
        return Ok((
            credential,
            Request {
                command,
                target: TargetAddr::Domain("v1.mux.cool".into(), 0),
            },
            cursor.offset,
        ));
    }
    let (target, consumed) = decode_address(&input[cursor.offset..])?;
    Ok((
        credential,
        Request { command, target },
        cursor.offset + consumed,
    ))
}

/// 与 [`decode`] 相同，但接受 `flow=xtls-rprx-vision` 的请求 addons。
///
/// 参考服务端 `proxy/vless/inbound/inbound.go`：uuid 之后是 addons 长度字节；vision
/// 时长度 = 18，载荷 `[0x0A, 0x10] + "xtls-rprx-vision"`，随后才是 command 与地址。
/// 本函数为该形态解析，返回 `(credential, request, 消费字节数)`，使调用方把剩余字节
/// 交给 Vision 流量层。
pub fn decode_vision(input: &[u8]) -> Result<([u8; 16], Request, usize), Error> {
    let mut cursor = Cursor { input, offset: 0 };
    if cursor.byte()? != 0 {
        return Err(Error::Unsupported);
    }
    let credential = cursor.take(16)?.try_into().expect("固定长度");
    let addons_len = cursor.byte()? as usize;
    if addons_len == 0 {
        return Err(Error::Unsupported);
    }
    let addons = cursor.take(addons_len)?;
    // 参考 `EncodeHeaderAddons`：`[0x0A, len(flow)] + flow`。
    if addons.len() != 2 + FLOW_XTLS_RPRX_VISION.len()
        || addons[0] != 0x0A
        || usize::from(addons[1]) != FLOW_XTLS_RPRX_VISION.len()
        || &addons[2..] != FLOW_XTLS_RPRX_VISION
    {
        return Err(Error::Unsupported);
    }
    let command = match cursor.byte()? {
        1 => Command::Tcp,
        2 => Command::Udp,
        3 => Command::Mux,
        _ => return Err(Error::Unsupported),
    };
    if command == Command::Mux {
        return Ok((
            credential,
            Request {
                command,
                target: TargetAddr::Domain("v1.mux.cool".into(), 0),
            },
            cursor.offset,
        ));
    }
    let (target, consumed) = decode_address(&input[cursor.offset..])?;
    Ok((
        credential,
        Request { command, target },
        cursor.offset + consumed,
    ))
}

pub(crate) fn decode_address(input: &[u8]) -> Result<(TargetAddr, usize), Error> {
    let mut cursor = Cursor { input, offset: 0 };
    let port = u16::from_be_bytes(cursor.take(2)?.try_into().expect("固定长度"));
    let target = match cursor.byte()? {
        1 => TargetAddr::V4(cursor.take(4)?.try_into().expect("固定长度"), port),
        2 => {
            let length = cursor.byte()? as usize;
            let host =
                std::str::from_utf8(cursor.take(length)?).map_err(|_| Error::InvalidAddress)?;
            validate_domain(host)?;
            TargetAddr::Domain(host.to_owned(), port)
        }
        3 => TargetAddr::V6(cursor.take(16)?.try_into().expect("固定长度"), port),
        _ => return Err(Error::InvalidAddress),
    };
    Ok((target, cursor.offset))
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(length).ok_or(Error::Incomplete)?;
        let bytes = self.input.get(self.offset..end).ok_or(Error::Incomplete)?;
        self.offset = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(target: TargetAddr) -> Request {
        Request {
            command: Command::Tcp,
            target,
        }
    }

    #[test]
    fn fixed_ipv4_vector_and_payload_boundary() {
        let mut expected = vec![0];
        expected.extend_from_slice(&[0x11; 16]);
        expected.extend_from_slice(&[0, 1, 1, 187, 1, 127, 0, 0, 1]);
        let req = request(TargetAddr::V4([127, 0, 0, 1], 443));
        assert_eq!(encode(&req, &[0x11; 16]).unwrap(), expected);
        let header_len = expected.len();
        expected.extend_from_slice(b"payload");
        assert_eq!(decode(&expected).unwrap(), ([0x11; 16], req, header_len));
    }

    #[test]
    fn domain_and_ipv6_use_vless_types() {
        let domain = request(TargetAddr::Domain("a.test".into(), 53));
        let encoded = encode(&domain, &[0; 16]).unwrap();
        assert_eq!(
            &encoded[19..],
            &[0, 53, 2, 6, b'a', b'.', b't', b'e', b's', b't']
        );
        assert_eq!(decode(&encoded).unwrap().1, domain);
        let ipv6 = request(TargetAddr::V6([0x22; 16], 8080));
        let encoded = encode(&ipv6, &[0; 16]).unwrap();
        assert_eq!(&encoded[19..22], &[31, 144, 3]);
        assert_eq!(decode(&encoded).unwrap().1, ipv6);
    }

    #[test]
    fn every_truncation_is_incomplete() {
        for target in [
            TargetAddr::V4([1; 4], 1),
            TargetAddr::V6([2; 16], 2),
            TargetAddr::Domain("x".repeat(255), 3),
        ] {
            let bytes = encode(&request(target), &[7; 16]).unwrap();
            for end in 0..bytes.len() {
                assert_eq!(
                    decode(&bytes[..end]),
                    Err(Error::Incomplete),
                    "截断位置 {end}"
                );
            }
        }
    }

    #[test]
    fn vision_flow_addons_encode_to_reference_bytes() {
        // 参考 `EncodeHeaderAddons`：addons 长度 0x12 + protobuf 0x0A 0x10 + 16 字节 flow。
        let req = request(TargetAddr::V4([127, 0, 0, 1], 443));
        let mut expected = vec![0];
        expected.extend_from_slice(&[0x11; 16]);
        expected.extend_from_slice(&[0x12, 0x0A, 0x10]);
        expected.extend_from_slice(b"xtls-rprx-vision");
        expected.extend_from_slice(&[1, 1, 187, 1, 127, 0, 0, 1]);
        assert_eq!(
            encode_with_flow(&req, &[0x11; 16], Flow::XtlsRprxVision).unwrap(),
            expected
        );
        // length 前缀 = 载荷 18 字节。
        assert_eq!(expected[17], 18);
        // 默认 encode 仍是无 addons。
        let mut plain = vec![0];
        plain.extend_from_slice(&[0x11; 16]);
        plain.extend_from_slice(&[0, 1, 1, 187, 1, 127, 0, 0, 1]);
        assert_eq!(encode(&req, &[0x11; 16]).unwrap(), plain);
    }

    #[test]
    fn reject_invalid_domains_and_fields() {
        for host in [String::new(), "x".repeat(256), "a\0b".into()] {
            assert_eq!(
                encode(&request(TargetAddr::Domain(host, 1)), &[0; 16]),
                Err(Error::InvalidAddress)
            );
        }
        let bytes = encode(&request(TargetAddr::V4([1; 4], 80)), &[0; 16]).unwrap();
        for (offset, value) in [(0, 1), (17, 1), (18, 4)] {
            let mut invalid = bytes.clone();
            invalid[offset] = value;
            assert_eq!(decode(&invalid), Err(Error::Unsupported));
        }
        let mut invalid = bytes;
        invalid[21] = 4;
        assert_eq!(decode(&invalid), Err(Error::InvalidAddress));
        invalid.truncate(21);
        invalid.extend_from_slice(&[2, 0]);
        assert_eq!(decode(&invalid), Err(Error::InvalidAddress));
    }
}
