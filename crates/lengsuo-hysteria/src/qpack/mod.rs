//! QPACK（RFC 9204）最小完备实现：仅覆盖 Hysteria2 HTTP/3 认证交换所需。
//!
//! 背景：本 crate 无法新增 `http` 依赖（Cargo.toml 由基建卡独占），`h3` crate
//! 的客户端 API 需要 `http::Request` 且其 QPACK 子模块私有，因此认证交换在
//! quinn 流上手写 HTTP/3 帧，头部块由本模块编解码。
//!
//! - 请求侧编码：全部使用「Literal Field Line with Literal Name」（001 模式，
//!   明文不 Huffman），Required Insert Count=0、Base=0，任何合规解码器可解。
//! - 响应侧解码：完整实现 RFC 9204 字段区块解码（Indexed / Post-Base /
//!   Literal 各模式、动态表、RIC 回绕、Huffman 解码），并消费 encoder 流指令
//!   （SetCapacity / Insert / Duplicate）建表，能解 quic-go/qpack 的任意合规输出。
//! - decoder 流反馈：提供 Section Acknowledgment 与 Insert Count Increment 的
//!   编码，调用方在解完一个区块后发送，避免对端因驱逐阻塞。
//!
//! Huffman 码表与静态表见 `tables.rs`（生成文件，含出处说明）。
//!
//! ## 子模块
//!
//! | 子模块 | 职责 |
//! |---|---|
//! | [`error`] | [`QpackError`]（一律 fail-closed） |
//! | [`primitives`] | `prefix-int` 编解码、Huffman 解码、字符串字面量解码 |
//! | [`header`] | [`HeaderField`] 与动态表（RFC 9204 §3.2） |
//! | [`encode`] | 字段区块编码与 decoder 流反馈编码 |
//! | [`decoder`] | [`Decoder`]（encoder 流指令） |
//! | [`section`] | 字段区块解码（前缀 Base + 字段行模式） |

mod decoder;
mod encode;
mod error;
mod header;
mod primitives;
mod section;
mod tables;

pub use decoder::Decoder;
pub use encode::{append_insert_count_increment, append_section_acknowledgment, encode_field_block};
pub use error::QpackError;
pub use header::HeaderField;

#[cfg(test)]
mod tests {
    use super::*;
    use super::primitives::{append_prefix_int, huffman_decode, prefix_int};

    fn hf(name: &str, value: &str) -> HeaderField {
        HeaderField {
            name: name.as_bytes().to_vec(),
            value: value.as_bytes().to_vec(),
        }
    }

    #[test]
    fn prefix_int_roundtrip_boundaries() {
        for &(bits, pattern, val) in &[
            (3u32, 0b0010_0000u8, 6u64),
            (3, 0b0010_0000, 7), // 前缀打满，进入续字节
            (7, 0x00, 126),
            (7, 0x00, 1000),
            (6, 0x80, 63),
            (5, 0b0010_0000, 4000),
        ] {
            let mut buf = Vec::new();
            append_prefix_int(val, bits, pattern, &mut buf);
            assert_eq!(
                buf[0] & !((1 << bits) - 1) as u8,
                pattern & !((1 << bits) - 1) as u8
            );
            let (decoded, used) = prefix_int(&buf, bits).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(used, buf.len());
        }
    }

    #[test]
    fn huffman_known_symbols() {
        // RFC 7541 附录 B：'0'=0/5、'1'=0x1/5、'a'=0x3/5、' '=0x14/6。
        // 码流 "00000"+"00001"+"00011"+"010100" 共 21 位，补 3 个 1：
        // 00000000 01000110 10100111 = 00 46 a7。
        let decoded = huffman_decode(&[0x00, 0x46, 0xa7]).unwrap();
        assert_eq!(decoded, b"01a ".to_vec());
    }

    #[test]
    fn huffman_rejects_bad_padding() {
        assert!(huffman_decode(&[0x00]).is_err()); // 8 位零填充
        assert!(huffman_decode(&[0xff, 0xff, 0xff, 0xff]).is_err()); // 命中 EOS
    }

    #[test]
    fn literal_block_roundtrip() {
        let headers = vec![
            hf(":method", "POST"),
            hf(":scheme", "https"),
            hf(":authority", "hysteria"),
            hf(":path", "/auth"),
            hf("hysteria-auth", "secret-value"),
        ];
        let block = encode_field_block(&headers);
        let mut dec = Decoder::default();
        let decoded = dec.decode_field_section(&block).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn decodes_static_indexed_and_dynamic_entries() {
        // encoder 流：SetCapacity(0x100) + Insert With Literal Name（pong/pang，01 模式）
        let mut enc = Vec::new();
        append_prefix_int(0x100, 5, 0b0010_0000, &mut enc);
        append_prefix_int(4, 5, 0b0100_0000, &mut enc);
        enc.extend_from_slice(b"pong");
        append_prefix_int(4, 7, 0x00, &mut enc);
        enc.extend_from_slice(b"pang");

        let mut dec = Decoder::default();
        let consumed = dec.apply_encoder_stream(&enc).unwrap();
        assert_eq!(consumed, enc.len());
        assert_eq!(dec.insert_count(), 1);

        // 区块：required=1 → enc = 1%16+1 = 2（k=8）、S=0 delta=0 → base=1。
        // 字段 1：indexed static 17（:method GET）→ 0xC0|17 = 0xd1。
        // 字段 2：indexed dynamic rel=0 → abs = base-1-0 = 0 → pong/pang → 0x80|0 = 0x80。
        let block = vec![0x02, 0x00, 0xd1, 0x80];
        let fields = dec.decode_field_section(&block).unwrap();
        assert_eq!(fields[0], hf(":method", "GET"));
        assert_eq!(fields[1], hf("pong", "pang"));
    }

    #[test]
    fn post_base_index_resolves() {
        // 插入两条后，base 取 2（RIC=2、S=0、delta=0），post-base idx=0 → abs=2。
        let mut enc = Vec::new();
        append_prefix_int(0x100, 5, 0b0010_0000, &mut enc);
        for name in ["aa", "bb"] {
            append_prefix_int(name.len() as u64, 5, 0b0100_0000, &mut enc);
            enc.extend_from_slice(name.as_bytes());
            append_prefix_int(1, 7, 0x00, &mut enc);
            enc.push(b'v');
        }
        let mut dec = Decoder::default();
        dec.apply_encoder_stream(&enc).unwrap();
        // 区块：required=2 → enc = 2%16+1 = 3；S=1 delta=0 → base = 2-0-1 = 1；
        // post-base idx=0 → abs = base+0 = 1（后插入的 bb/v）。
        let block = vec![0x03, 0x80, 0x10];
        let fields = dec.decode_field_section(&block).unwrap();
        assert_eq!(fields, vec![hf("bb", "v")]);
    }

    #[test]
    fn ric_beyond_known_fails() {
        let mut dec = Decoder::default();
        assert!(matches!(
            dec.decode_field_section(&[0x01, 0x00]),
            Err(QpackError::InsertCount { .. })
        ));
    }

    #[test]
    fn decoder_stream_feedback_encoding() {
        let mut out = Vec::new();
        append_section_acknowledgment(0, &mut out);
        assert_eq!(out, vec![0x80]);
        out.clear();
        append_section_acknowledgment(5, &mut out);
        assert_eq!(out, vec![0x85]);
        out.clear();
        append_insert_count_increment(3, &mut out);
        assert_eq!(out, vec![0x03]);
    }
}
