// 长度上限：恰好在上限 / 超过上限（地址与 padding 两侧）。
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
    let (decoded, used) = ConnectUdpRequest::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded, req);
    assert_eq!(
        ConnectUdpRequest::decode_exact(&bytes).expect("定界解码"),
        req
    );
}

#[test]
fn request_rejects_lengths_above_maximum() {
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
        ConnectUdpRequest::decode(&frame(&vec![b'a'; MAX_ADDRESS_LENGTH as usize], b"")).is_ok(),
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
        ConnectUdpRequest::decode(&frame(b"h", &vec![0x20; MAX_PADDING_LENGTH as usize])).is_ok(),
        "4096 应合法"
    );
}
