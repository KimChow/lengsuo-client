// 编码侧拒绝非法字段 + 错误与 Debug 不泄漏地址与 padding。
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
fn request_rejects_oversized_length_fields_without_panicking() {
    for prefix in [
        [0x80, 0xFF, 0xFF, 0xFF].as_slice(),
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].as_slice(),
    ] {
        let mut bytes = TYPE_BYTES.to_vec();
        bytes.extend_from_slice(prefix);
        let len = prefix_value(prefix);
        assert_eq!(
            request_error(&bytes),
            Error::TooLong {
                field: "address",
                len,
                max: MAX_ADDRESS_LENGTH
            },
            "地址长度前缀 {prefix:02x?}"
        );

        let mut bytes = frame(b"a", &[]);
        bytes.truncate(2 + len_bytes(1).len() + 1);
        bytes.extend_from_slice(prefix);
        assert_eq!(
            request_error(&bytes),
            Error::TooLong {
                field: "padding",
                len,
                max: MAX_PADDING_LENGTH
            },
            "padding 长度前缀 {prefix:02x?}"
        );
    }
}

#[test]
fn request_errors_and_debug_do_not_leak_address_or_padding() {
    let secret = frame(b"private-target:1", b"sensitive-padding");
    let variants = [
        {
            let mut bytes = secret.clone();
            bytes[1] = 0x03; // 篡改类型字节
            bytes
        },
        secret[..10].to_vec(), // 截断地址体
        {
            let mut bytes = secret.clone();
            bytes[5] = 0x00; // 地址中注入 NUL
            bytes
        },
    ];
    for input in variants {
        let rendered = request_error(&input).to_string();
        assert!(!rendered.contains("private-target"), "{rendered}");
        assert!(!rendered.contains("sensitive-padding"), "{rendered}");
    }
    // Debug 只报长度。
    let rendered = format!("{:?}", request("private-target:1", b"sensitive-padding"));
    assert!(!rendered.contains("private-target"), "{rendered}");
    assert!(!rendered.contains("sensitive-padding"), "{rendered}");
    assert!(rendered.contains("address_len"), "{rendered}");
}
