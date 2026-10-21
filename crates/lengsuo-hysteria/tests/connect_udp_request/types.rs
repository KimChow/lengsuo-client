// 类型与空地址：错误请求类型 / 非最短类型前缀 / 空地址。
#[test]
fn request_rejects_wrong_request_type() {
    for (value, prefix) in [
        (0_u64, &[0x00][..]),
        (1, &[0x01]),
        (0x400, &[0x44, 0x00]),
        (0x401, &[0x44, 0x01]), // TCPRequest 类型不得当 CONNECT-UDP 接受
        (0x403, &[0x44, 0x03]),
        (2049, &[0x48, 0x01]),
        (MAX_VALUE, &[0xFF; 8]),
    ] {
        let mut input = prefix.to_vec();
        input.extend_from_slice(&[0x01, b'a', 0x00]);
        assert_eq!(
            request_error(&input),
            Error::InvalidFrameType { value },
            "类型 {value:#x}"
        );
    }
    // 非最短写法的 0x402 仍是合法类型前缀（QUIC 允许非最短解码）。
    for prefix in [
        [0x80, 0x00, 0x04, 0x02].as_slice(),
        [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02].as_slice(),
    ] {
        let mut input = prefix.to_vec();
        input.extend_from_slice(&[0x01, b'a', 0x01, b'p']);
        let (decoded, used) = ConnectUdpRequest::decode(&input).expect("解码");
        assert_eq!(used, input.len(), "非最短类型前缀 {prefix:02x?}");
        assert_eq!(decoded, request("a", b"p"));
    }
}

#[test]
fn request_rejects_empty_address() {
    let mut bytes = TYPE_BYTES.to_vec();
    bytes.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        request_error(&bytes),
        Error::EmptyField { field: "address" }
    );

    let (decoded, used) = ConnectUdpRequest::decode(&frame(b"z", b"")).expect("1 字节地址合法");
    assert_eq!((decoded.address.as_str(), used), ("z", 5));

    assert_eq!(
        request("", b"pad").encode().expect_err("空地址"),
        Error::EmptyField { field: "address" }
    );
}
