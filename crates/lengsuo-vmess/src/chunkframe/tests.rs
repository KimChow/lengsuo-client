//! `chunkframe` 模块的单元测试（密钥扩展 / 掩码流 / 分帧往返 / 篡改与截断）。

use super::*;
use crate::chunkframe::cipher::cipher_overhead;
use crate::consts::{SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_NONE};
use crate::Error;

const KEY: [u8; 16] = *b"request-body-key";
const IV: [u8; 16] = *b"request-body-iv!";

#[test]
fn chacha_key_expansion_matches_go_algorithm() {
    // GenerateChacha20Poly1305Key：MD5(b) || MD5(MD5(b))。MD5 标准向量锁定。
    let key = generate_chacha20_poly1305_key(b"0123456789abcdef");
    let first = md5_digest(b"0123456789abcdef");
    assert_eq!(&key[..16], &first[..]);
    let second = md5_digest(&first);
    assert_eq!(&key[16..], &second[..]);
}

#[test]
fn size_parser_mask_is_streamed_and_invertible() {
    let mut encoder = DataSizeParser::new(&IV);
    let mut decoder = DataSizeParser::new(&IV);
    for size in [0u16, 1, 255, 256, 65535] {
        let wire = encoder.encode_size(size);
        assert_eq!(decoder.decode_size(wire), size);
    }
    // 掩码流连续：同一 size 两次编码的线上字节不同（掩码已推进）。
    let mut e2 = DataSizeParser::new(&IV);
    let a = e2.encode_size(1000);
    let b = e2.encode_size(1000);
    assert_ne!(a, b, "掩码必须随 chunk 推进");
}

#[test]
fn padding_len_within_64() {
    let mut parser = DataSizeParser::new(&IV);
    for _ in 0..64 {
        assert!(parser.next_padding_len() < DataSizeParser::max_padding_len());
    }
}

#[tokio::test]
async fn data_chunk_roundtrip_all_securities_with_masking() {
    for security in [
        SECURITY_NONE,
        SECURITY_AES_128_GCM,
        SECURITY_CHACHA20_POLY1305,
    ] {
        let mut seal_cipher = DataCipher::new(security, &KEY, &IV);
        let mut open_cipher = DataCipher::new(security, &KEY, &IV);
        let mut enc_mask = DataSizeParser::new(&IV);
        let mut dec_mask = DataSizeParser::new(&IV);
        let mut wire = Vec::new();
        seal_data_chunk(
            &mut seal_cipher,
            Some(&mut enc_mask),
            &mut wire,
            b"hello chunk",
        )
        .expect("可写");
        seal_data_chunk(
            &mut seal_cipher,
            Some(&mut enc_mask),
            &mut wire,
            &[0x77u8; 300],
        )
        .expect("可写");
        write_data_eof(&mut seal_cipher, Some(&mut enc_mask), &mut wire).expect("EOF 可写");

        let mut cursor = &wire[..];
        let first = read_data_chunk(&mut open_cipher, Some(&mut dec_mask), &mut cursor)
            .await
            .expect("可读")
            .expect("首帧");
        assert_eq!(first, b"hello chunk");
        let second = read_data_chunk(&mut open_cipher, Some(&mut dec_mask), &mut cursor)
            .await
            .expect("可读")
            .expect("次帧");
        assert_eq!(second, vec![0x77u8; 300]);
        let eof = read_data_chunk(&mut open_cipher, Some(&mut dec_mask), &mut cursor)
            .await
            .expect("可读");
        assert!(eof.is_none(), "终止帧应得到 None 而非空载荷");
        assert!(cursor.is_empty(), "不得吞尾部字节");
    }
}

#[tokio::test]
async fn tampered_chunk_fails_and_nonce_advances_per_chunk() {
    let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &KEY, &IV);
    let mut wire = Vec::new();
    seal_data_chunk(&mut cipher, None, &mut wire, b"payload-0").expect("可写");
    seal_data_chunk(&mut cipher, None, &mut wire, b"payload-1").expect("可写");
    assert_eq!(cipher.count(), 2, "每个 chunk 恰好消耗一个 nonce");

    wire[2 + 10] ^= 0x01; // 篡改首帧载荷
    let mut victim = DataCipher::new(SECURITY_AES_128_GCM, &KEY, &IV);
    let err = read_data_chunk(&mut victim, None, &mut &wire[..]).await;
    assert!(matches!(err, Err(Error::AuthFailed)), "实际 {err:?}");
}

#[tokio::test]
async fn truncated_chunk_reports_error_not_hang() {
    let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &KEY, &IV);
    let mut wire = Vec::new();
    seal_data_chunk(&mut cipher, None, &mut wire, b"payload").expect("可写");
    let mut broken = &wire[..2 + 5];
    let err = read_data_chunk(&mut cipher, None, &mut broken).await;
    assert!(matches!(
        err,
        Err(Error::Io(_)) | Err(Error::Truncated { .. })
    ));
}

#[test]
fn oversized_chunk_is_rejected_before_write() {
    let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &KEY, &IV);
    let mut wire = Vec::new();
    let err = seal_data_chunk(
        &mut cipher,
        None,
        &mut wire,
        &vec![0u8; MAX_CHUNK_PAYLOAD + 1],
    );
    assert!(matches!(err, Err(Error::BadLength { .. })));
    assert!(wire.is_empty(), "失败不得写任何字节");
}

#[test]
fn shake_mask_compat_export_is_stable() {
    let a = shake_mask(&IV, 0);
    let b = shake_mask(&IV, 0);
    assert_eq!(a, b, "确定性");
}

#[test]
fn padded_chunks_roundtrip_and_eof_declares_overhead_plus_padding() {
    for security in [
        SECURITY_NONE,
        SECURITY_AES_128_GCM,
        SECURITY_CHACHA20_POLY1305,
    ] {
        let mut seal_cipher = DataCipher::new(security, &KEY, &IV);
        let mut open_cipher = DataCipher::new(security, &KEY, &IV);
        let mut enc_mask = DataSizeParser::new(&IV);
        let mut dec_mask = DataSizeParser::new(&IV);
        let mut wire = Vec::new();
        seal_padded_chunk(&mut seal_cipher, &mut enc_mask, &mut wire, b"padded!").expect("可写");
        seal_padded_chunk(&mut seal_cipher, &mut enc_mask, &mut wire, &[0x33u8; 500])
            .expect("可写");
        seal_padded_chunk(&mut seal_cipher, &mut enc_mask, &mut wire, &[]).expect("EOF 可写");

        let mut cursor = 0usize;
        let mut frames = 0;
        loop {
            let size_wire: [u8; 2] = wire[cursor..cursor + 2].try_into().expect("size 段");
            cursor += 2;
            let (declared, padding) = read_padded_size(&mut dec_mask, size_wire);
            let body = &wire[cursor..cursor + declared as usize];
            cursor += declared as usize;
            match open_padded_chunk(&mut open_cipher, body, padding).expect("可解") {
                Some(plain) if frames == 0 => assert_eq!(plain, b"padded!"),
                Some(plain) if frames == 1 => assert_eq!(plain, vec![0x33u8; 500]),
                Some(_) => panic!("多出帧"),
                None => {
                    assert_eq!(
                        declared as usize,
                        cipher_overhead(&open_cipher) + padding as usize
                    );
                    break;
                }
            }
            frames += 1;
        }
        assert_eq!(frames, 2);
        assert_eq!(cursor, wire.len(), "不得吞尾部字节");
    }
}

#[test]
fn tampered_padded_chunk_fails_closed() {
    let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &KEY, &IV);
    let mut mask = DataSizeParser::new(&IV);
    let mut wire = Vec::new();
    seal_padded_chunk(&mut cipher, &mut mask, &mut wire, b"secret").expect("可写");
    let last = wire.len() - 1;
    wire[last] ^= 0x01; // 破坏 padding 末字节不影响认证；破坏密文/tag 才影响
                        // size 段占前 2 字节，密文紧随；篡改密文中部。
    wire[4] ^= 0x01;
    let mut victim = DataCipher::new(SECURITY_AES_128_GCM, &KEY, &IV);
    let mut dec_mask = DataSizeParser::new(&IV);
    let (declared, padding) = read_padded_size(&mut dec_mask, [wire[0], wire[1]]);
    let body = &wire[2..2 + declared as usize];
    let result = open_padded_chunk(&mut victim, body, padding);
    assert!(matches!(result, Err(Error::AuthFailed)), "实际 {result:?}");
}
