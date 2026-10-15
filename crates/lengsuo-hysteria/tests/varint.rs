//! QUIC varint 原语测试：固定字节、边界值、非最短、截断、越界。
//! 只证明本 crate 的 varint 实现，不证明 QUIC 连接或 Hysteria2 互通。

use lengsuo_hysteria::varint::{self, MAX_VALUE};
use lengsuo_hysteria::Error;

/// 断言取值同时满足「最短编码字节」与「解码消耗长度」。
fn canonical(value: u64, bytes: &[u8]) {
    let mut buf = [0xAA_u8; 8];
    let written = varint::encode(value, &mut buf).unwrap_or_else(|error| {
        panic!("编码 {value} 失败：{error}");
    });
    assert_eq!(written, bytes.len(), "{value} 编码长度");
    assert_eq!(&buf[..written], bytes, "{value} 编码字节");
    assert_eq!(varint::encoded_len(value), Some(bytes.len()));
    assert_eq!(varint::size(value), Ok(bytes.len()));
    assert_eq!(varint::prefix_len(bytes[0]), bytes.len());
    assert_eq!(
        varint::decode(bytes).unwrap_or_else(|error| panic!("解码 {value} 失败：{error}")),
        (value, bytes.len()),
        "{value} 解码"
    );
}

#[test]
fn canonical_shortest_vectors() {
    canonical(0, &[0x00]);
    canonical(1, &[0x01]);
    // 1 字节上界。
    canonical(63, &[0x3F]);
    // 2 字节下界与上界。
    canonical(64, &[0x40, 0x40]);
    canonical(1025, &[0x44, 0x01]);
    canonical(16_383, &[0x7F, 0xFF]);
    // 4 字节下界与上界。
    canonical(16_384, &[0x80, 0x00, 0x40, 0x00]);
    canonical((1 << 30) - 1, &[0xBF, 0xFF, 0xFF, 0xFF]);
    // 8 字节下界与上界 2^62-1。
    canonical(1 << 30, &[0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]);
    canonical(MAX_VALUE, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // 帧类型 0x401 落在 2 字节区间。
    canonical(0x401, &[0x44, 0x01]);
}

#[test]
fn non_shortest_encodings_are_accepted_on_decode() {
    // QUIC 规定长度前缀决定有效位数，非最短写法合法（quicvarint.Read 同样接受）。
    let cases: &[(&[u8], u64)] = &[
        (&[0x40, 0x00], 0),
        (&[0x40, 0x0A], 10),
        (&[0x80, 0x00, 0x00, 0x0F], 15),
        (&[0x80, 0x00, 0x00, 0x01], 1),
        (&[0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], 1),
    ];
    for (bytes, value) in cases {
        let used = bytes.len();
        assert_eq!(
            varint::decode(bytes).ok(),
            Some((*value, used)),
            "{bytes:02x?}"
        );
        // 同一取值的最短编码更短，因此回环字节与输入不同是预期。
        let shortest = varint::encoded_len(*value).expect("最短长度");
        assert!(shortest < used, "{value} 应为非最短输入");
    }
}

#[test]
fn every_truncation_reports_needed_length() {
    // 各长度前缀下缺少任意尾字节都按该前缀所需字节数报截断。
    let cases: [(&[u8], usize); 4] = [
        (&[0x01], 1),
        (&[0x44, 0x01], 2),
        (&[0x80, 0x00, 0x40, 0x00], 4),
        (&[0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00], 8),
    ];
    for (bytes, need) in cases {
        // 只有首字节可见时才谈得上该前缀所需长度；空输入统一报 need 1。
        for got in 1..need {
            assert_eq!(
                varint::decode(&bytes[..got]).expect_err("应截断"),
                Error::Truncated { need, got },
                "{bytes:02x?} 只剩 {got} 字节"
            );
        }
        let (decoded, used) = varint::decode(bytes).expect("完整输入应成功");
        assert_eq!(used, need, "{bytes:02x?} 完整");
        assert!(decoded <= MAX_VALUE, "{bytes:02x?} 应在界内");
    }
    assert_eq!(
        varint::decode(&[]).expect_err("空输入"),
        Error::Truncated { need: 1, got: 0 }
    );
    assert_eq!(varint::prefix_len(0x00), 1);
    assert_eq!(varint::prefix_len(0x40), 2);
    assert_eq!(varint::prefix_len(0x80), 4);
    assert_eq!(varint::prefix_len(0xC0), 8);
}

#[test]
fn values_above_max_are_rejected_without_writing() {
    for value in [MAX_VALUE + 1, 1 << 62, u64::MAX] {
        assert_eq!(varint::encoded_len(value), None);
        assert_eq!(
            varint::size(value).expect_err("应越界"),
            Error::VarIntOutOfRange { value }
        );

        let mut buf = [0x11_u8; 8];
        assert_eq!(
            varint::encode(value, &mut buf).expect_err("应越界"),
            Error::VarIntOutOfRange { value }
        );
        assert_eq!(buf, [0x11; 8], "越界不得写入");

        let mut vec = vec![0x22_u8];
        assert_eq!(
            varint::append(value, &mut vec).expect_err("应越界"),
            Error::VarIntOutOfRange { value }
        );
        assert_eq!(vec, vec![0x22], "越界不得追加");
    }
}

#[test]
fn encode_requires_exact_room() {
    for value in [64_u64, 16_384, 1 << 30, MAX_VALUE] {
        let need = varint::encoded_len(value).expect("长度");
        let mut buf = [0_u8; 8];
        for got in 0..need {
            assert_eq!(
                varint::encode(value, &mut buf[..got]).expect_err("空间不足"),
                Error::Truncated { need, got },
                "{value} 只剩 {got} 字节"
            );
            assert_eq!(buf[..got], vec![0_u8; got], "空间不足不得写入");
        }
    }
}

#[test]
fn append_matches_encode_and_roundtrips_boundaries() {
    let values = [
        0_u64,
        63,
        64,
        16_383,
        16_384,
        (1 << 30) - 1,
        1 << 30,
        MAX_VALUE - 1,
        MAX_VALUE,
    ];
    for value in values {
        let mut appended = Vec::new();
        assert_eq!(
            varint::append(value, &mut appended).ok(),
            Some(appended.len())
        );
        let mut direct = [0_u8; 8];
        let used = varint::encode(value, &mut direct).expect("编码");
        assert_eq!(appended, direct[..used], "{value} 追加等价");

        // 后随字节不属于 varint，decode 只消耗自身长度。
        let mut stream = appended.clone();
        stream.extend_from_slice(b"tail");
        let (decoded, used) = varint::decode(&stream).expect("解码");
        assert_eq!((decoded, used), (value, appended.len()));
        assert_eq!(&stream[used..], b"tail", "不得吞掉后续字节");
    }
}
