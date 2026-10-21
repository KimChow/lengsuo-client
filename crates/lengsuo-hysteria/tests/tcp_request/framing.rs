// 帧边界与编码：不吞掉后续载荷 / 编码侧拒绝非法字段 / 错误不泄漏内容。
#[test]
fn request_decode_does_not_swallow_payload() {
    let bytes = frame(b"example.com:443", b"pad");
    let mut stream = bytes.clone();
    stream.extend_from_slice(b"tail-payload");
    let (decoded, used) = TcpRequest::decode(&stream).expect("解码");
    assert_eq!(used, bytes.len(), "只消耗帧本身");
    assert_eq!(decoded.address, "example.com:443");
    assert_eq!(&stream[used..], b"tail-payload", "帧后字节留给应用载荷");
    assert_eq!(decoded.encode().expect("编码"), bytes);
}

#[test]
fn request_encode_rejects_invalid_struct_fields() {
    let too_long = "a".repeat((MAX_ADDRESS_LENGTH + 1) as usize);
    assert_eq!(
        request(&too_long, b"").encode().expect_err("地址超限"),
        Error::TooLong {
            field: "address",
            len: 2049,
            max: MAX_ADDRESS_LENGTH
        }
    );
    assert_eq!(
        request("a:1", &vec![0x20; 4097])
            .encode()
            .expect_err("padding 超限"),
        Error::TooLong {
            field: "padding",
            len: 4097,
            max: MAX_PADDING_LENGTH
        }
    );
    // encoded_len 与 encode 判定一致。
    let req = request("a:1", b"xyz");
    assert_eq!(
        req.encoded_len().ok(),
        Some(req.encode().expect("编码").len())
    );
}

#[test]
fn request_errors_do_not_leak_address_or_padding() {
    let secret = frame(b"private-target:22", b"sensitive-padding");
    let variants = [
        {
            // 篡改类型字节。
            let mut bytes = secret.clone();
            bytes[1] = 0x02;
            bytes
        },
        secret[..10].to_vec(), // 截断地址体
        {
            // 地址中注入 NUL。
            let mut bytes = secret.clone();
            bytes[5] = 0x00;
            bytes
        },
    ];
    for input in variants {
        let rendered = request_error(&input).to_string();
        assert!(!rendered.contains("private-target"), "{rendered}");
        assert!(!rendered.contains("sensitive-padding"), "{rendered}");
    }
}
