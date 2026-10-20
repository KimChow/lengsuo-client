//! REALITY 服务端认证逻辑层测试。
//!
//! ⚠️ **这些是自洽用例（本仓客户端 seal → 本仓服务端 `accept_hello`），
//! 不是与 Xray REALITY 服务端的参考互通**。互通未实跑、不声称。
//!
//! ClientHello 由本文件按 RFC 8446 4.1.2 布局手工拼装（含 SNI 与
//! key_share 扩展），认证载荷用本仓客户端侧 `auth.rs` 封装——只借用其
//! 已由独立黄金向量锁定的 AEAD 语义，不调用服务端实现自证。

#[cfg(test)]
mod cases {
    use super::super::*;
    use crate::reality::auth::{
        build_auth_plaintext, seal_auth_payload, RealityClientKeys, SESSION_ID_LEN,
        SESSION_ID_OFFSET,
    };
    use crate::reality::x25519::x25519_base;
    use aes_gcm::aead::rand_core::{CryptoRng, Error as RngError, RngCore};
    use core::time::Duration;

    /// 确定性 RNG：字节序列 0,1,2,…，跨调用连续。
    struct SeqRng(u8);
    impl RngCore for SeqRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for d in dest.iter_mut() {
                *d = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for SeqRng {}

    const SNI: &str = "example.com";
    const NOW: u32 = 1_700_000_000;

    fn cfg(secret: [u8; 32], short_ids: Vec<[u8; 8]>) -> RealityServerConfig {
        RealityServerConfig {
            private_key: secret,
            short_ids,
            server_names: vec![SNI.to_string()],
            max_time_diff: Duration::from_secs(60),
        }
    }

    /// 拼一个 RFC 8446 布局的 ClientHello（SessionId 区先清零）。
    fn build_hello(keys: &RealityClientKeys, sni: &str) -> Vec<u8> {
        let mut exts = Vec::new();
        // server_name: list_len(2) + type(1) + name_len(2) + name
        let name = sni.as_bytes();
        let mut sn = Vec::new();
        sn.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sn.push(0);
        sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sn.extend_from_slice(name);
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sn.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sn);
        // key_share: client_shares_len(2) + group(2) + key_len(2) + key(32)
        let mut ks = Vec::new();
        ks.extend_from_slice(&36u16.to_be_bytes());
        ks.extend_from_slice(&0x001du16.to_be_bytes());
        ks.extend_from_slice(&32u16.to_be_bytes());
        ks.extend_from_slice(&keys.ephemeral_public());
        exts.extend_from_slice(&0x0033u16.to_be_bytes());
        exts.extend_from_slice(&(ks.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ks);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        let mut rng = SeqRng(0x40);
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);
        body.extend_from_slice(&random);
        body.push(32); // session_id len
        body.extend_from_slice(&[0u8; 32]); // SessionId 区（AAD 中为零）
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1); // compression
        body.push(0);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut raw = Vec::new();
        raw.push(0x01); // ClientHello
        let len = body.len() as u32;
        raw.extend_from_slice(&len.to_be_bytes()[1..]);
        raw.extend_from_slice(&body);
        raw
    }

    /// 客户端侧：生成临时密钥、seal 认证载荷并写回 SessionId。
    /// 返回 `(完整 ClientHello, 客户端临时公钥)`。
    fn sealed_hello(
        server_secret: [u8; 32],
        version: ClientVersion,
        ts: u32,
        short_id: [u8; 8],
    ) -> (Vec<u8>, [u8; 32]) {
        let server_public = x25519_base(&server_secret);
        let mut rng = SeqRng(0);
        let keys = RealityClientKeys::generate(&server_public, &mut rng).unwrap();
        let mut raw = build_hello(&keys, SNI);
        let random: [u8; 32] = raw[6..38].try_into().unwrap();
        let ak = keys.derive_auth_key(&random).unwrap();
        let plain = build_auth_plaintext(version, ts, &short_id);
        let ct = seal_auth_payload(&ak, &plain, &raw).unwrap();
        raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&ct);
        (raw, keys.ephemeral_public())
    }

    fn accept(
        c: &RealityServerConfig,
        raw: &[u8],
        now: u32,
    ) -> Result<RealityAccept, RealityReject> {
        accept_hello(c, raw, now)
    }

    #[test]
    fn positive_client_seal_roundtrip() {
        let secret = [7u8; 32];
        let sid = [0xaa, 0xbb, 0, 0, 0, 0, 0, 0];
        let v = ClientVersion { x: 26, y: 3, z: 27 };
        let (raw, _) = sealed_hello(secret, v, NOW, sid);
        let got = accept(&cfg(secret, vec![sid]), &raw, NOW).unwrap();
        assert_eq!(got.client_version, v);
        assert_eq!(got.timestamp, NOW);
        assert_eq!(got.short_id, sid);
    }

    #[test]
    fn rejects_wrong_private_key() {
        let sid = [1u8; 8];
        let (raw, _) = sealed_hello([7u8; 32], ClientVersion { x: 1, y: 2, z: 3 }, NOW, sid);
        assert_eq!(
            accept(&cfg([8u8; 32], vec![sid]), &raw, NOW),
            Err(RealityReject::AuthRejected)
        );
    }

    #[test]
    fn rejects_wrong_aad_byte() {
        let sid = [2u8; 8];
        let secret = [7u8; 32];
        let (mut raw, _) = sealed_hello(secret, ClientVersion { x: 1, y: 2, z: 3 }, NOW, sid);
        // 篡改扩展区（AAD 覆盖全 ClientHello）。
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert_eq!(
            accept(&cfg(secret, vec![sid]), &raw, NOW),
            Err(RealityReject::AuthRejected)
        );
    }

    #[test]
    fn rejects_shifted_nonce() {
        let sid = [3u8; 8];
        let secret = [7u8; 32];
        let (mut raw, _) = sealed_hello(secret, ClientVersion { x: 1, y: 2, z: 3 }, NOW, sid);
        // nonce = random[20..32]，即 raw[26..38]；改一个 bit。
        raw[6 + 20] ^= 1;
        assert_eq!(
            accept(&cfg(secret, vec![sid]), &raw, NOW),
            Err(RealityReject::AuthRejected)
        );
    }

    #[test]
    fn rejects_short_id_mismatch() {
        let secret = [7u8; 32];
        let (raw, _) = sealed_hello(secret, ClientVersion { x: 1, y: 2, z: 3 }, NOW, [9u8; 8]);
        assert_eq!(
            accept(&cfg(secret, vec![[8u8; 8]]), &raw, NOW),
            Err(RealityReject::ShortIdNotAllowed)
        );
    }

    #[test]
    fn empty_short_id_requires_explicit_allow() {
        let secret = [7u8; 32];
        // 客户端用空短 ID（全零）。
        let (raw, _) = sealed_hello(secret, ClientVersion { x: 1, y: 2, z: 3 }, NOW, [0u8; 8]);
        // 白名单里有别项 → 拒绝（不得默认放行空 ID）。
        assert_eq!(
            accept(&cfg(secret, vec![[1u8; 8]]), &raw, NOW),
            Err(RealityReject::ShortIdNotAllowed)
        );
        // 白名单为空 → 同样拒绝。
        assert_eq!(
            accept(&cfg(secret, vec![]), &raw, NOW),
            Err(RealityReject::ShortIdNotAllowed)
        );
        // 显式列入全零 → 接受（对齐参考 map[[8]byte]bool 查表）。
        assert!(accept(&cfg(secret, vec![[0u8; 8]]), &raw, NOW).is_ok());
    }

    #[test]
    fn rejects_timestamp_both_sides_of_window() {
        let secret = [7u8; 32];
        let sid = [4u8; 8];
        let v = ClientVersion { x: 1, y: 2, z: 3 };
        let c = cfg(secret, vec![sid]); // 窗口 60s
        for delta in [61u32, 120, 10_000] {
            let (past, _) = sealed_hello(secret, v, NOW.checked_sub(delta).unwrap(), sid);
            assert_eq!(
                accept(&c, &past, NOW),
                Err(RealityReject::TimeOutOfRange),
                "past {delta}"
            );
            let (future, _) = sealed_hello(secret, v, NOW + delta, sid);
            assert_eq!(
                accept(&c, &future, NOW),
                Err(RealityReject::TimeOutOfRange),
                "future {delta}"
            );
        }
        // 边界：恰好 60s 必须接受（参考 `<= MaxTimeDiff`）。
        let (edge, _) = sealed_hello(secret, v, NOW - 60, sid);
        assert!(accept(&c, &edge, NOW).is_ok());
        // MaxTimeDiff == 0 表示不校验（参考短路语义）。
        let mut c0 = cfg(secret, vec![sid]);
        c0.max_time_diff = Duration::ZERO;
        assert!(accept(&c0, &edge, 1).is_ok());
    }

    #[test]
    fn rejects_truncation_at_key_offsets() {
        let secret = [7u8; 32];
        let sid = [5u8; 8];
        let (raw, _) = sealed_hello(secret, ClientVersion { x: 1, y: 2, z: 3 }, NOW, sid);
        let c = cfg(secret, vec![sid]);
        // 任务书点名的偏移：39/40/55/71/87。
        for cut in [39usize, 40, 55] {
            assert_eq!(
                accept(&c, &raw[..cut], NOW),
                Err(RealityReject::BufferTooShort { need: 71, got: cut }),
                "cut {cut}"
            );
        }
        // 71 起固定前缀已齐，改由结构走查拒绝（AEAD 之前 fail-closed）。
        assert_eq!(
            accept(&c, &raw[..71], NOW),
            Err(RealityReject::MalformedHello)
        );
        // 87：结构完整但认证载荷被截断，必须拒绝。
        assert!(accept(&c, &raw[..87], NOW).is_err());
        // 逐字节全切点：任何 <71 都必须拒绝且不 panic。
        for cut in 0..71 {
            assert!(accept(&c, &raw[..cut], NOW).is_err(), "cut {cut}");
        }
    }

    #[test]
    fn rejects_every_tag_byte_tamper() {
        let secret = [7u8; 32];
        let sid = [6u8; 8];
        let (raw, _) = sealed_hello(secret, ClientVersion { x: 1, y: 2, z: 3 }, NOW, sid);
        let c = cfg(secret, vec![sid]);
        // tag 位于 SessionId 末 16 字节：raw[55..71]。
        for i in SESSION_ID_OFFSET + 16..SESSION_ID_OFFSET + 32 {
            let mut t = raw.clone();
            t[i] ^= 0x01;
            assert_eq!(
                accept(&c, &t, NOW),
                Err(RealityReject::AuthRejected),
                "tag byte {i}"
            );
        }
    }

    #[test]
    fn rejects_sni_not_allowed_and_missing() {
        let secret = [7u8; 32];
        let sid = [7u8; 8];
        let (raw, _) = sealed_hello(secret, ClientVersion { x: 1, y: 2, z: 3 }, NOW, sid);
        let mut c = cfg(secret, vec![sid]);
        c.server_names = vec!["other.example".to_string()];
        assert_eq!(
            accept(&c, &raw, NOW),
            Err(RealityReject::ServerNameNotAllowed)
        );
        // 空 SNI 白名单同样拒绝。
        c.server_names.clear();
        assert_eq!(
            accept(&c, &raw, NOW),
            Err(RealityReject::ServerNameNotAllowed)
        );
    }

    #[test]
    fn rejects_not_client_hello() {
        let secret = [7u8; 32];
        let sid = [8u8; 8];
        let (mut raw, _) = sealed_hello(secret, ClientVersion { x: 1, y: 2, z: 3 }, NOW, sid);
        raw[0] = 0x02; // ServerHello
        assert_eq!(
            accept(&cfg(secret, vec![sid]), &raw, NOW),
            Err(RealityReject::NotClientHello)
        );
    }

    #[test]
    fn rejects_malformed_extensions() {
        let secret = [7u8; 32];
        let sid = [9u8; 8];
        let (raw, _) = sealed_hello(secret, ClientVersion { x: 1, y: 2, z: 3 }, NOW, sid);
        let c = cfg(secret, vec![sid]);
        // 扩展总长字段改大 → 结构不完整。
        let ext_len_pos = SESSION_ID_OFFSET + 32 + 2 + 2 + 1 + 1;
        let mut t = raw.clone();
        t[ext_len_pos] = 0xff;
        t[ext_len_pos + 1] = 0xff;
        assert_eq!(accept(&c, &t, NOW), Err(RealityReject::MalformedHello));
        // SessionId 长度字段不是 32 → 定长布局不成立。
        let mut t = raw.clone();
        t[SESSION_ID_OFFSET - 1] = 16;
        assert_eq!(accept(&c, &t, NOW), Err(RealityReject::MalformedHello));
    }

    #[test]
    fn rejects_low_order_key_share() {
        let secret = [7u8; 32];
        let sid = [0x11u8; 8];
        let (raw, _) = sealed_hello(secret, ClientVersion { x: 1, y: 2, z: 3 }, NOW, sid);
        // 把 key_share 的公钥改成全零（低阶点）。
        let mut t = raw.clone();
        let ks_start = t.len() - 32;
        t[ks_start..].fill(0);
        assert_eq!(
            accept(&cfg(secret, vec![sid]), &t, NOW),
            Err(RealityReject::KeyAgreementRejected)
        );
    }

    #[test]
    fn reject_and_config_debug_do_not_leak_secrets() {
        let secret = [0x5au8; 32];
        let sid = [0xc3u8; 8];
        let c = cfg(secret, vec![sid]);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(&"5a".repeat(32)));
        assert!(!dbg.contains("c3c3c3c3"), "short id leaked: {dbg}");
        // 拒绝值本身也不携带短 ID/密钥字节。
        let d = format!("{:?}", RealityReject::ShortIdNotAllowed);
        assert!(!d.contains("c3"));
    }
}
