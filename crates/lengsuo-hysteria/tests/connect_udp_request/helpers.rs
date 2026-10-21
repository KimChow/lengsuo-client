// 共享夹具：类型字节常量 + 独立实现的长度编码 / varint 解码 / 帧构造 / 错误取值。
/// `0x402` 的规范最短编码。
const TYPE_BYTES: [u8; 2] = [0x44, 0x02];

/// 独立实现的长度编码（本仓取值 <= 4096，只需 1/2 字节形式），
/// 避免用被测代码构造期望字节。
fn len_bytes(value: usize) -> Vec<u8> {
    if value <= 63 {
        vec![value as u8]
    } else {
        vec![((value >> 8) as u8) | 0x40, value as u8]
    }
}

/// 独立实现 QUIC varint 解码，只用于推导测试期望值。
fn prefix_value(prefix: &[u8]) -> u64 {
    match prefix.len() {
        4 => u64::from(u32::from_be_bytes(prefix.try_into().expect("4 字节"))) & 0x3FFF_FFFF,
        8 => u64::from_be_bytes(prefix.try_into().expect("8 字节")) & 0x3FFF_FFFF_FFFF_FFFF,
        other => unreachable!("测试只用 4/8 字节前缀，收到 {other}"),
    }
}

/// 参考布局：type + varint(addr_len) + addr + varint(pad_len) + pad。
fn frame(addr: &[u8], padding: &[u8]) -> Vec<u8> {
    let mut bytes = TYPE_BYTES.to_vec();
    bytes.extend_from_slice(&len_bytes(addr.len()));
    bytes.extend_from_slice(addr);
    bytes.extend_from_slice(&len_bytes(padding.len()));
    bytes.extend_from_slice(padding);
    bytes
}

fn request(address: &str, padding: &[u8]) -> ConnectUdpRequest {
    ConnectUdpRequest {
        address: address.to_string(),
        padding: padding.to_vec(),
    }
}

/// ConnectUdpRequest 故意不派生 Debug，失败路径先丢弃成功值再取错误。
fn request_error(input: &[u8]) -> Error {
    match ConnectUdpRequest::decode(input) {
        Ok((_, used)) => panic!("应 fail-closed，但解析出 {used} 字节"),
        Err(error) => error,
    }
}
