// 基本路径：固定字节 / 往返 / 对抗输入 / 空 padding。
#[test]
fn fixed_request_bytes() {
    let expected: &[u8] = &[
        0x44, 0x02, 0x0F, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', b':',
        b'4', b'4', b'3', 0x03, b'p', b'a', b'd',
    ];
    assert_eq!(REQUEST_TYPE_CONNECT_UDP, 0x402);
    assert_eq!(frame(b"example.com:443", b"pad"), expected.to_vec());

    let req = request("example.com:443", b"pad");
    assert_eq!(req.encoded_len().ok(), Some(expected.len()));
    assert_eq!(req.encode().expect("编码"), expected.to_vec());
    assert_eq!(
        ConnectUdpRequest::decode(expected).expect("解码"),
        (req.clone(), expected.len())
    );
}

#[tokio::test]
async fn request_roundtrip_within_timeout() {
    // 纯字节层的编码/解码往返；用超时兜住任何 pathological 输入导致的停滞。
    let work = async {
        let req = request("udp.example.test:53", b"abcdefgh");
        let bytes = req.encode().expect("编码");
        let (decoded, used) = ConnectUdpRequest::decode(&bytes).expect("解码");
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, req);
        assert_eq!(decoded.encode().expect("回环编码"), bytes);
        assert_eq!(decoded.padding.len(), 8);
        bytes
    };
    let bytes = tokio::time::timeout(Duration::from_millis(2_000), work)
        .await
        .expect("往返应在超时内完成");
    assert_eq!(bytes.len(), 2 + 1 + 19 + 1 + 8);
}

#[tokio::test]
async fn request_decode_of_adversarial_input_fails_within_timeout() {
    // 篡改与超长声明都必须立刻返回错误，不得挂起或 panic。
    let work = async {
        let mut tampered = frame(b"target.example:7000", b"pad");
        tampered[1] = 0x03; // 类型字节改成 0x403
        assert_eq!(
            request_error(&tampered),
            Error::InvalidFrameType { value: 0x403 }
        );

        let mut declared = frame(b"h", &[]);
        declared.truncate(2 + len_bytes(1).len() + 1);
        declared.extend_from_slice(&len_bytes(MAX_PADDING_LENGTH as usize));
        assert_eq!(
            request_error(&declared),
            Error::Truncated {
                need: declared.len() + MAX_PADDING_LENGTH as usize,
                got: declared.len()
            }
        );
    };
    tokio::time::timeout(Duration::from_millis(2_000), work)
        .await
        .expect("错误路径应在超时内 fail-closed");
}

#[test]
fn request_padding_may_be_empty() {
    let bytes = frame(b"1.1.1.1:53", b"");
    assert_eq!(
        bytes,
        vec![0x44, 0x02, 0x0A, b'1', b'.', b'1', b'.', b'1', b'.', b'1', b':', b'5', b'3', 0x00]
    );
    let (decoded, used) = ConnectUdpRequest::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded.address, "1.1.1.1:53");
    assert!(decoded.padding.is_empty());
    assert_eq!(decoded.encode().expect("回环编码"), bytes);
}
