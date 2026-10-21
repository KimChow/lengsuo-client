// 基本路径：固定字节 / 空 padding / 长度上限与超限。
#[test]
fn fixed_request_bytes() {
    let expected: &[u8] = &[
        0x44, 0x01, 0x0F, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', b':',
        b'4', b'4', b'3', 0x03, b'p', b'a', b'd',
    ];
    assert_eq!(FRAME_TYPE_TCP_REQUEST, 0x401);
    assert_eq!(frame(b"example.com:443", b"pad"), expected.to_vec());

    let req = request("example.com:443", b"pad");
    assert_eq!(req.encoded_len().ok(), Some(expected.len()));
    assert_eq!(req.encode().expect("编码"), expected.to_vec());
    assert_eq!(
        TcpRequest::decode(expected).expect("解码"),
        (req.clone(), expected.len())
    );
}

#[test]
fn request_padding_may_be_empty() {
    let bytes = frame(b"1.1.1.1:53", b"");
    assert_eq!(
        bytes,
        vec![0x44, 0x01, 0x0A, b'1', b'.', b'1', b'.', b'1', b'.', b'1', b':', b'5', b'3', 0x00]
    );
    let (decoded, used) = TcpRequest::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded.address, "1.1.1.1:53");
    assert!(decoded.padding.is_empty());
    assert_eq!(decoded.encode().expect("回环编码"), bytes);
}

#[test]
fn request_accepts_maximum_lengths() {
    let address = "a".repeat(MAX_ADDRESS_LENGTH as usize);
    let padding = vec![0x7F_u8; MAX_PADDING_LENGTH as usize];
    let req = request(&address, &padding);
    let bytes = req.encode().expect("编码");
    assert_eq!(
        bytes.len(),
        2 + 2 + address.len() + 2 + padding.len(),
        "2048/4096 用 2 字节 varint"
    );
    assert_eq!(&bytes[2..4], &[0x48, 0x00], "地址长度 2048");
    assert_eq!(
        &bytes[4 + address.len()..6 + address.len()],
        &[0x50, 0x00],
        "padding 长度 4096"
    );
    let (decoded, used) = TcpRequest::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded, req);
}

#[test]
fn request_rejects_lengths_above_maximum() {
    // 长度字段在读取数据体前即按上限拒绝（与参考实现常量相同）。
    let bytes = frame(&vec![b'a'; (MAX_ADDRESS_LENGTH + 1) as usize], b"");
    assert_eq!(
        request_error(&bytes),
        Error::TooLong {
            field: "address",
            len: 2049,
            max: MAX_ADDRESS_LENGTH
        }
    );
    assert!(
        TcpRequest::decode(&frame(&vec![b'a'; MAX_ADDRESS_LENGTH as usize], b"")).is_ok(),
        "2048 应合法"
    );

    let bytes = frame(b"h", &vec![0x20; (MAX_PADDING_LENGTH + 1) as usize]);
    assert_eq!(
        request_error(&bytes),
        Error::TooLong {
            field: "padding",
            len: 4097,
            max: MAX_PADDING_LENGTH
        }
    );
    assert!(
        TcpRequest::decode(&frame(b"h", &vec![0x20; MAX_PADDING_LENGTH as usize])).is_ok(),
        "4096 应合法"
    );
}
