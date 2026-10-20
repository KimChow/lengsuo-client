//! TLS 1.3 握手消息的单元测试（从 `messages.rs` 拆出以符合 400 行软目标）。
//!
//! 覆盖：
//!
//! * ClientHello 的构造布局与往返解析；
//! * ServerHello 的解析（含 **`key_share` 布局**的回归用例）；
//! * 握手消息的分帧。

#[cfg(test)]
mod cases {
    use super::super::{
        build_client_hello, extension, handshake_type, parse_client_hello, parse_handshake,
        parse_server_hello, parse_server_key_share, push_ext, put_u16_vec, put_u8_vec,
        take_handshake, ClientHelloParams, MessageError, ServerKeyShare,
        CIPHER_SUITE_AES_128_GCM_SHA256, GROUP_X25519, LEGACY_VERSION, VERSION_TLS13,
    };

    fn params() -> ClientHelloParams {
        ClientHelloParams {
            random: [0x11; 32],
            session_id: [0u8; 32],
            server_name: "www.example.com".into(),
            key_share: [0x22; 32],
        }
    }

    #[test]
    fn client_hello_layout_matches_rfc8446() {
        let hello = build_client_hello(&params());
        // 消息头：type=1, 3 字节长度。
        assert_eq!(hello[0], handshake_type::CLIENT_HELLO);
        let len = u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize;
        assert_eq!(len, hello.len() - 4);
        // legacy_version(2) + random(32) + session_id_len(1) + session_id(32)
        assert_eq!(&hello[4..6], &[0x03, 0x03]);
        assert_eq!(&hello[38..39], &[32]);
        assert_eq!(&hello[39..71], &[0u8; 32]);
    }

    #[test]
    fn client_hello_roundtrips_through_parser() {
        let hello = build_client_hello(&params());
        let info = parse_client_hello(&hello[4..]).unwrap();
        assert_eq!(info.random, [0x11; 32]);
        assert_eq!(info.session_id.len(), 32);
        assert_eq!(info.server_name.as_deref(), Some("www.example.com"));
        assert_eq!(info.x25519_key_share, Some([0x22; 32]));
        assert_eq!(info.alpn_protocols, vec!["http/1.1".to_string()]);
    }

    #[test]
    fn truncated_client_hello_is_rejected() {
        let hello = build_client_hello(&params());
        // 刚过完 compression_methods、还没进扩展区的那一个截断点，
        // 是一个**合法**的「无扩展 ClientHello」，故从扩展区之后开始检查。
        //
        // body 布局：version(2) + random(32) + session_id_len(1) + session_id(32)
        //          + suites_len(2) + suites(6) + compression_len(1) + compression(1)
        let extensions_start = 4 + 2 + 32 + 1 + 32 + 2 + 6 + 1 + 1;
        for end in extensions_start + 1..hello.len() {
            assert!(
                parse_client_hello(&hello[4..end]).is_err(),
                "截断位置 {end}"
            );
        }
        // 无扩展的 ClientHello 必须能解析（此时没有扩展区）。
        let no_ext = parse_client_hello(&hello[4..extensions_start]).unwrap();
        assert_eq!(no_ext.server_name, None);
        assert_eq!(no_ext.x25519_key_share, None);
    }

    #[test]
    fn take_handshake_needs_full_message() {
        let hello = build_client_hello(&params());
        let mut buffer = hello[..10].to_vec();
        assert_eq!(take_handshake(&mut buffer).unwrap(), None);
        buffer.extend_from_slice(&hello[10..]);
        let (kind, payload) = take_handshake(&mut buffer).unwrap().unwrap();
        assert_eq!(kind, handshake_type::CLIENT_HELLO);
        assert_eq!(payload, hello[4..].to_vec());
        assert!(buffer.is_empty());
    }

    #[test]
    fn server_hello_roundtrip() {
        // 构造一条最小 ServerHello 载荷并解析。
        //
        // ⛔ `key_share` 扩展的数据是 `group(2) + key_exchange(uint16 长度前缀)`，
        // **没有** ClientHello 那层 `client_shares` 列表前缀。
        // 对齐参考 `xtls/reality` `handshake_messages.go:797-805`
        // （`serverHelloMsg.marshal`）：
        //
        // ```go
        // exts.AddUint16(extensionKeyShare)
        // exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
        //     exts.AddUint16(uint16(m.serverShare.group))
        //     exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
        //         exts.AddBytes(m.serverShare.data)
        //     })
        // })
        // ```
        let mut body = Vec::new();
        body.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        put_u8_vec(&mut body, &[0u8; 32]);
        body.extend_from_slice(&CIPHER_SUITE_AES_128_GCM_SHA256.to_be_bytes());
        body.push(0);
        let mut exts = Vec::new();
        let mut ext = Vec::new();
        ext.extend_from_slice(&VERSION_TLS13.to_be_bytes());
        push_ext(&mut exts, extension::SUPPORTED_VERSIONS, &ext);
        let mut ext = Vec::new();
        ext.extend_from_slice(&GROUP_X25519.to_be_bytes());
        put_u16_vec(&mut ext, &[0x44; 32]);
        push_ext(&mut exts, extension::KEY_SHARE, &ext);
        put_u16_vec(&mut body, &exts);

        let info = parse_server_hello(&body).unwrap();
        assert_eq!(info.cipher_suite, CIPHER_SUITE_AES_128_GCM_SHA256);
        assert_eq!(info.supported_version, Some(VERSION_TLS13));
        assert_eq!(info.x25519_key_share, Some([0x44; 32]));
        assert_eq!(info.session_id.len(), 32);
    }

    /// **回归**：ServerHello 与 ClientHello 的 `key_share` 布局**不同**。
    ///
    /// ClientHello：`client_shares`（uint16 长度前缀的列表）+ 若干
    /// `KeyShareEntry`；ServerHello：**直接**一条 `KeyShareEntry`，无列表前缀。
    ///
    /// 本仓曾用 ClientHello 的解析器去解 ServerHello，导致真实握手在
    /// 「解析 ServerHello」这一步报 `MalformedMessage`。本用例把两种布局
    /// 摆在一起对照，确保解析器不会再混用。
    #[test]
    fn server_and_client_key_share_layouts_differ() {
        let key = [0x44u8; 32];

        // ClientHello 布局：列表长度前缀 + 一条 entry。
        let mut client_ext = Vec::new();
        let mut entry = Vec::new();
        entry.extend_from_slice(&GROUP_X25519.to_be_bytes());
        put_u16_vec(&mut entry, &key);
        put_u16_vec(&mut client_ext, &entry);

        // ServerHello 布局：**没有**列表长度前缀。
        let mut server_ext = Vec::new();
        server_ext.extend_from_slice(&GROUP_X25519.to_be_bytes());
        put_u16_vec(&mut server_ext, &key);

        // ClientHello 的解析器只认列表布局。
        assert_eq!(parse_client_key_share(&client_ext), Some(key));
        // 把 ServerHello 布局喂给 ClientHello 解析器，解不出 x25519
        // （要么报错，要么解出错误的 group——两种都不算成功）。
        assert_ne!(parse_client_key_share(&server_ext), Some(key));

        // ServerHello 的解析器只认无列表布局。
        assert_eq!(
            parse_server_key_share(&server_ext).unwrap(),
            ServerKeyShare::Share {
                group: GROUP_X25519,
                key: key.to_vec(),
            }
        );
        // 把 ClientHello 的布局喂给 ServerHello 解析器，解不出 x25519。
        match parse_server_key_share(&client_ext).unwrap() {
            ServerKeyShare::Share { group, .. } => {
                assert_ne!(group, GROUP_X25519, "列表长度被误当成 group");
            }
            ServerKeyShare::HelloRetryRequest { .. } => {
                panic!("列表布局不应被当成 HelloRetryRequest")
            }
        }
    }

    /// ServerHello 的 `key_share` 只有 2 字节时是 HelloRetryRequest 形态。
    ///
    /// 对齐参考 `handshake_messages.go:955-958`：
    /// `if len(extData) == 2 { extData.ReadUint16(&m.selectedGroup) }`。
    #[test]
    fn server_hello_key_share_hello_retry_request_form() {
        let data = GROUP_X25519.to_be_bytes();
        assert_eq!(
            parse_server_key_share(&data).unwrap(),
            ServerKeyShare::HelloRetryRequest {
                selected_group: GROUP_X25519
            }
        );
    }

    /// ClientHello 的 `key_share` 扩展解析（列表布局）。
    ///
    /// `messages::client` 里的解析器是私有的，这里通过**构造一条带
    /// `key_share` 的 ClientHello 再解析**来间接覆盖它。
    fn parse_client_key_share(ext_data: &[u8]) -> Option<[u8; 32]> {
        // 手搓一条最小 ClientHello，只带 `key_share` 扩展。
        let mut body = Vec::new();
        body.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        put_u8_vec(&mut body, &[0u8; 32]);
        put_u16_vec(&mut body, &CIPHER_SUITE_AES_128_GCM_SHA256.to_be_bytes());
        put_u8_vec(&mut body, &[0]);
        let mut exts = Vec::new();
        push_ext(&mut exts, extension::KEY_SHARE, ext_data);
        put_u16_vec(&mut body, &exts);
        parse_client_hello(&body)
            .ok()
            .and_then(|info| info.x25519_key_share)
    }

    /// 分帧：截断的握手消息必须报 `Truncated`。
    #[test]
    fn parse_handshake_rejects_truncated_input() {
        let mut message = Vec::new();
        message.push(handshake_type::FINISHED);
        message.extend_from_slice(&[0, 0, 32]);
        message.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            parse_handshake(&message[..10]).unwrap_err(),
            MessageError::Truncated
        );
        assert_eq!(
            parse_handshake(&message[..3]).unwrap_err(),
            MessageError::Truncated
        );
    }
}
