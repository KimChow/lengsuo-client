// 超长长度字段：按上限拒绝且不 panic / 上限内长度只声明自身。
#[test]
fn request_rejects_oversized_length_fields_without_panicking() {
    // 长度字段可表示到 2^62-1：必须按上限拒绝，且在读取数据体前失败。
    for prefix in [
        [0x80, 0xFF, 0xFF, 0xFF].as_slice(),
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].as_slice(),
    ] {
        let mut bytes = TYPE_BYTES.to_vec();
        bytes.extend_from_slice(prefix);
        // 期望值用独立解码推导：4 字节前缀与 8 字节前缀的取值不同。
        let len = prefix_value(prefix);
        // 地址长度字段即超限，不随可用字节数变成截断。
        assert_eq!(
            request_error(&bytes),
            Error::TooLong {
                field: "address",
                len,
                max: MAX_ADDRESS_LENGTH
            },
            "地址长度前缀 {prefix:02x?}"
        );

        // 同一超长值出现在 padding 长度字段上。
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
fn request_length_field_at_max_declares_never_arriving_body() {
    // 上限内的长度（4096 padding）只声明自身：need 恰为帧尾，不越过帧边界。
    let mut bytes = frame(b"a", &[]);
    // 替换原 padding 长度字段（不是追加）：帧里只有一个 padding 长度。
    bytes.truncate(bytes.len() - len_bytes(0).len());
    bytes.extend_from_slice(&len_bytes(MAX_PADDING_LENGTH as usize));
    assert_eq!(
        request_error(&bytes),
        Error::Truncated {
            need: bytes.len() + MAX_PADDING_LENGTH as usize,
            got: bytes.len()
        }
    );
}
