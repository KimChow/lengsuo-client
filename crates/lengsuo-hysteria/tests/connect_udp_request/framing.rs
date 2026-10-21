// 帧边界：不吞掉后续载荷 / 定界解码的长度一致性。
#[test]
fn request_decode_does_not_swallow_payload() {
    let bytes = frame(b"example.com:443", b"pad");
    let mut stream = bytes.clone();
    stream.extend_from_slice(b"\x00\x01later-datagram-body");
    let (decoded, used) = ConnectUdpRequest::decode(&stream).expect("解码");
    assert_eq!(used, bytes.len(), "只消耗帧本身");
    assert_eq!(decoded.address, "example.com:443");
    assert_eq!(
        &stream[used..],
        b"\x00\x01later-datagram-body",
        "帧后字节留给应用载荷"
    );

    // 相邻两帧可依次解析，消耗长度即下一帧起点。
    let second = frame(b"b:2", b"q");
    let mut two = bytes.clone();
    two.extend_from_slice(&second);
    let (first, first_used) = ConnectUdpRequest::decode(&two).expect("第一帧");
    assert_eq!(first_used, bytes.len());
    let (second_struct, second_used) =
        ConnectUdpRequest::decode(&two[first_used..]).expect("第二帧");
    assert_eq!(first_used + second_used, two.len(), "两帧首尾相接");
    assert_eq!(first, request("example.com:443", b"pad"));
    assert_eq!(second_struct, request("b:2", b"q"));
}

#[test]
fn request_decode_exact_rejects_length_mismatch() {
    // 外层声明的长度比消息实际长度多 1 字节：必须拒绝，不能吞掉尾部。
    let mut extra = frame(b"example.com:443", b"pad");
    extra.push(b'!');
    assert_eq!(
        ConnectUdpRequest::decode_exact(&extra).expect_err("长度不一致"),
        Error::LengthMismatch {
            declared: extra.len(),
            consumed: extra.len() - 1
        }
    );
    // 多出一整个后续帧同样拒绝。
    let mut two = frame(b"a:1", b"");
    two.extend_from_slice(&frame(b"b:2", b""));
    assert_eq!(
        ConnectUdpRequest::decode_exact(&two).expect_err("两帧concatenate"),
        Error::LengthMismatch {
            declared: two.len(),
            consumed: frame(b"a:1", b"").len()
        }
    );
    // 精确等长才通过。
    assert_eq!(
        ConnectUdpRequest::decode_exact(&frame(b"a:1", b"")).expect("定界解码"),
        request("a:1", b"")
    );
}
