// 地址内容：NUL 与非法 UTF-8 / 非最短长度字段。
#[test]
fn request_rejects_nul_and_invalid_utf8_in_address() {
    // NUL 本身是合法 UTF-8，但地址一律禁止。
    assert_eq!(
        request_error(&frame(b"evil\x00host:1", b"")),
        Error::ContainsNul { field: "address" }
    );
    assert_eq!(
        request_error(&frame(&[0x61, 0x62, 0xFF], b"")),
        Error::InvalidUtf8 { field: "address" }
    );
    // 截断的多字节序列。
    assert_eq!(
        request_error(&frame(&[0xE4, 0xB8], b"")),
        Error::InvalidUtf8 { field: "address" }
    );
    // 合法非 ASCII 地址通过并字节回环。
    let idn = "例え.jp:8080";
    let bytes = frame(idn.as_bytes(), b"");
    let (decoded, used) = TcpRequest::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded.address, idn);
    assert_eq!(decoded.encode().expect("编码"), bytes);

    assert_eq!(
        request("bad\u{0}host", b"")
            .encode()
            .expect_err("结构体 NUL"),
        Error::ContainsNul { field: "address" }
    );
}

#[test]
fn request_accepts_non_shortest_length_fields() {
    // 地址长度 15 写成 2 字节、padding 长度 3 写成 4 字节的非最短形式。
    let mut bytes = TYPE_BYTES.to_vec();
    bytes.extend_from_slice(&[0x40, 0x0F]);
    bytes.extend_from_slice(b"example.com:443");
    bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x03]);
    bytes.extend_from_slice(b"pad");
    let (decoded, used) = TcpRequest::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len(), "消耗长度含非最短前缀");
    assert_eq!(decoded, request("example.com:443", b"pad"));
    // 编码侧永远输出最短形式。
    assert_eq!(
        decoded.encode().expect("编码"),
        frame(b"example.com:443", b"pad")
    );
}
