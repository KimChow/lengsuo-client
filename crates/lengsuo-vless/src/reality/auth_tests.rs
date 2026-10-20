//! REALITY 认证层测试（从 `auth.rs` 拆出以符合 400 行软目标）。

#[cfg(test)]
mod cases {
    use super::super::*;
    use crate::reality::x25519::x25519_base;
    use aes_gcm::aead::rand_core::{CryptoRng, RngCore};

    /// 确定性 RNG：`fill_bytes` 依次写入 0,1,2,…（跨调用连续），
    /// 保证同一 seed 下向量逐字节可复现。
    use aes_gcm::aead::rand_core::Error as RngError;

    pub(crate) struct SeqRng {
        next: u8,
    }

    impl SeqRng {
        pub(crate) fn new() -> Self {
            Self { next: 0 }
        }
    }

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
                *d = self.next;
                self.next = self.next.wrapping_add(1);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for SeqRng {}

    /// 构造一个最小但布局正确的 ClientHello 前缀（到 SessionId 末尾）。
    fn fake_hello(random_seed: u8, session_id: [u8; 32]) -> Vec<u8> {
        let mut raw = vec![0u8; SESSION_ID_OFFSET + SESSION_ID_LEN + 16];
        raw[0] = 0x01; // ClientHello
                       // embedded length 不参与本层，随意填。
        raw[4] = 0x03;
        raw[5] = 0x03; // TLS 1.2 legacy version
        for (i, b) in raw[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN]
            .iter_mut()
            .enumerate()
        {
            *b = random_seed.wrapping_add(i as u8);
        }
        raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&session_id);
        raw
    }

    #[test]
    fn plaintext_layout_is_exact() {
        let v = ClientVersion { x: 26, y: 3, z: 27 };
        let sid = [0xaa, 0xbb, 0, 0, 0, 0, 0, 0];
        let p = build_auth_plaintext(v, 0x6500_0000, &sid);
        // 逐字节：版本三元组 + 保留 0 + BE 时间戳 + 左对齐短 ID。
        assert_eq!(p.len(), AUTH_PAYLOAD_LEN);
        assert_eq!(&p[..3], &[26, 3, 27]);
        assert_eq!(p[3], 0);
        assert_eq!(&p[4..8], &[0x65, 0x00, 0x00, 0x00]);
        assert_eq!(&p[8..16], &[0xaa, 0xbb, 0, 0, 0, 0, 0, 0]);
        let parsed = AuthPlaintext::parse(&p);
        assert_eq!(parsed.version, v);
        assert_eq!(parsed.reserved, 0);
        assert_eq!(parsed.unix_time, 0x6500_0000);
        assert_eq!(parsed.short_id_key(), [0xaa, 0xbb, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn plaintext_short_id_left_aligns_and_truncates() {
        // 正好 8 字节短 ID 全填。
        let full = [0x11u8; 8];
        let p = build_auth_plaintext(ClientVersion { x: 0, y: 0, z: 0 }, 0, &full);
        assert_eq!(&p[8..16], &[0x11u8; 8]);
        // 超长（24 字节）只写前 8 字节，对齐 Go `copy(dst, src)`。
        let over = [0x22u8; 24];
        let p = build_auth_plaintext(ClientVersion { x: 0, y: 0, z: 0 }, 0, &over);
        assert_eq!(&p[8..16], &[0x22u8; 8]);
    }

    #[test]
    fn deterministic_vector_seal_and_open_roundtrip() {
        // 固定随机源 → 固定临时私钥；固定 server 公钥与 random。
        let mut rng = SeqRng::new();
        let server_secret = [7u8; 32];
        let server_public = x25519_base(&server_secret);

        let keys = RealityClientKeys::generate(&server_public, &mut rng).unwrap();
        let mut raw = fake_hello(0x10, [0u8; 32]);
        let random: [u8; 32] = raw[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN]
            .try_into()
            .unwrap();

        // 客户端派生 auth_key。
        let auth_key = keys.derive_auth_key(&random).unwrap();
        // 服务端用同一份材料独立推导，必须一致。
        let peer_public = keys.ephemeral_public();
        let server_key = derive_auth_key_server(&[7u8; 32], &peer_public, &random).unwrap();
        assert_eq!(auth_key, server_key, "client/server auth_key must agree");

        // 构造明文并 seal；返回值即整段 SessionId（32 字节）。
        let plain = build_auth_plaintext(
            ClientVersion { x: 26, y: 3, z: 27 },
            0x6500_0000,
            &[0xaa, 0xbb],
        );
        let ct = seal_auth_payload(&auth_key, &plain, &raw).unwrap();
        raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&ct);

        // 服务端 open 得到明文。
        let parsed = open_auth_payload(&server_key, &raw).unwrap();
        assert_eq!(parsed.version, ClientVersion { x: 26, y: 3, z: 27 });
        assert_eq!(parsed.unix_time, 0x6500_0000);
        assert_eq!(parsed.short_id_key(), [0xaa, 0xbb, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn deterministic_vector_is_byte_stable() {
        // 同一固定 seed 两次运行，密文字节必须完全相同（无隐藏随机性）。
        let server_secret = [9u8; 32];
        let server_public = x25519_base(&server_secret);
        let run = || {
            let mut rng = SeqRng::new();
            let keys = RealityClientKeys::generate(&server_public, &mut rng).unwrap();
            let raw = fake_hello(0x20, [0u8; 32]);
            let random: [u8; 32] = raw[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN]
                .try_into()
                .unwrap();
            let ak = keys.derive_auth_key(&random).unwrap();
            let plain = build_auth_plaintext(
                ClientVersion { x: 26, y: 3, z: 27 },
                0x6500_0000,
                &[1, 2, 3, 4, 5, 6, 7, 8],
            );
            (
                keys.ephemeral_public(),
                ak,
                seal_auth_payload(&ak, &plain, &raw).unwrap(),
            )
        };
        let (p1, k1, c1) = run();
        let (p2, k2, c2) = run();
        assert_eq!(p1, p2);
        assert_eq!(k1, k2);
        assert_eq!(c1, c2);
        // 打印一次作为文档化向量（--nocapture 可见）。
        println!("ephemeral_pub = {p1:02x?}");
        println!("auth_key      = {k1:02x?}");
        println!("ciphertext    = {c1:02x?}");
    }

    /// 独立实现交叉校验的黄金向量（`cryptography` Python 库复算，
    /// 非本仓 roundtrip）：
    ///
    /// * ephemeral seed = 0x00..0x1f（SeqRng 连续填充）
    /// * server_secret = [9u8; 32]、random[i] = 0x20 + i
    /// * short_id = 01..08、版本 26.3.27、时间 0x65000000
    ///
    /// 逐字节锁定 X25519 → HKDF-SHA256 → AES-256-GCM 全链。
    #[test]
    fn golden_vector_matches_independent_implementation() {
        let mut rng = SeqRng::new();
        let server_secret = [9u8; 32];
        let server_public = x25519_base(&server_secret);
        let keys = RealityClientKeys::generate(&server_public, &mut rng).unwrap();

        let raw = fake_hello(0x20, [0u8; 32]);
        let random: [u8; 32] = raw[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN]
            .try_into()
            .unwrap();
        let ak = keys.derive_auth_key(&random).unwrap();
        let plain = build_auth_plaintext(
            ClientVersion { x: 26, y: 3, z: 27 },
            0x6500_0000,
            &[1, 2, 3, 4, 5, 6, 7, 8],
        );
        let ct = seal_auth_payload(&ak, &plain, &raw).unwrap();

        assert_eq!(
            hex(&keys.ephemeral_public()),
            "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
        );
        assert_eq!(
            hex(&ak),
            "779600b924f71edae6e5bce53d8cfea2e59342e6b100b8dae0152c62f13bdc6f"
        );
        assert_eq!(
            hex(&ct),
            "bd97296647a0b282b3e029966ac6fe279cb18c1068795ce12663aec291de3988"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn open_rejects_wrong_key() {
        let server_secret = [1u8; 32];
        let server_public = x25519_base(&server_secret);
        let mut rng = SeqRng::new();
        let keys = RealityClientKeys::generate(&server_public, &mut rng).unwrap();
        let mut raw = fake_hello(0x30, [0u8; 32]);
        let random: [u8; 32] = raw[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN]
            .try_into()
            .unwrap();
        let ak = keys.derive_auth_key(&random).unwrap();
        let plain = build_auth_plaintext(ClientVersion { x: 26, y: 3, z: 27 }, 1, &[0u8; 8]);
        let ct = seal_auth_payload(&ak, &plain, &raw).unwrap();
        raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&ct);

        // 错误 auth_key → fail-closed。
        let mut wrong = ak;
        wrong[0] ^= 0x01;
        assert_eq!(
            open_auth_payload(&wrong, &raw),
            Err(AuthError::AuthRejected)
        );
    }

    #[test]
    fn open_rejects_tampered_random_and_aad() {
        let server_secret = [2u8; 32];
        let server_public = x25519_base(&server_secret);
        let mut rng = SeqRng::new();
        let keys = RealityClientKeys::generate(&server_public, &mut rng).unwrap();
        let mut raw = fake_hello(0x40, [0u8; 32]);
        let random: [u8; 32] = raw[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN]
            .try_into()
            .unwrap();
        let ak = keys.derive_auth_key(&random).unwrap();
        let plain = build_auth_plaintext(ClientVersion { x: 26, y: 3, z: 27 }, 1, &[0u8; 8]);
        let ct = seal_auth_payload(&ak, &plain, &raw).unwrap();
        raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&ct);

        // 篡改 AAD（ClientHello 其他字节）→ 拒绝。
        let mut tampered = raw.clone();
        tampered[0] ^= 0xff;
        assert_eq!(
            open_auth_payload(&ak, &tampered),
            Err(AuthError::AuthRejected)
        );

        // 篡改 nonce（random[20..32]）→ 拒绝。
        let mut tampered = raw.clone();
        tampered[RANDOM_OFFSET + HKDF_SALT_LEN] ^= 0x01;
        assert_eq!(
            open_auth_payload(&ak, &tampered),
            Err(AuthError::AuthRejected)
        );
    }

    #[test]
    fn full_truncation_rejected() {
        let mut rng = SeqRng::new();
        let server_secret = [3u8; 32];
        let keys = RealityClientKeys::generate(&x25519_base(&server_secret), &mut rng).unwrap();
        for cut in 0..(SESSION_ID_OFFSET + SESSION_ID_LEN) {
            let raw = vec![0u8; cut];
            assert!(
                matches!(
                    ClientHelloAuthView::new(&raw),
                    Err(AuthError::BufferTooShort { .. })
                ),
                "len {cut} must be too short"
            );
        }
        // 正好够长则通过。
        let raw = vec![0u8; SESSION_ID_OFFSET + SESSION_ID_LEN];
        assert!(ClientHelloAuthView::new(&raw).is_ok());
        let _ = keys;
    }

    #[test]
    fn low_order_public_key_rejected() {
        // X25519 全零公钥是低阶点，共享密钥为全零 → 参考报错，这里 fail-closed。
        let mut rng = SeqRng::new();
        assert_eq!(
            RealityClientKeys::generate(&[0u8; 32], &mut rng).unwrap_err(),
            AuthError::InvalidPublicKey
        );
        // 服务端侧同样拒绝。
        assert_eq!(
            derive_auth_key_server(&[7u8; 32], &[0u8; 32], &[0u8; 32]).unwrap_err(),
            AuthError::InvalidPublicKey
        );
    }

    #[test]
    fn cert_tag_verifies_and_rejects() {
        let auth_key = [0x5au8; 32];
        let ed_pub = [0x3cu8; 32];
        let tag = cert_auth_tag(&auth_key, &ed_pub);
        assert!(verify_cert_tag(&auth_key, &ed_pub, &tag).is_ok());

        // 错公钥 → 拒绝。
        let mut wrong_pub = ed_pub;
        wrong_pub[0] ^= 1;
        assert_eq!(
            verify_cert_tag(&auth_key, &wrong_pub, &tag),
            Err(AuthError::CertificateMismatch)
        );
        // 错 auth_key → 拒绝。
        let mut wrong_key = auth_key;
        wrong_key[31] ^= 1;
        assert_eq!(
            verify_cert_tag(&wrong_key, &ed_pub, &tag),
            Err(AuthError::CertificateMismatch)
        );
        // 截断签名 → 拒绝。
        assert_eq!(
            verify_cert_tag(&auth_key, &ed_pub, &tag[..63]),
            Err(AuthError::CertificateMismatch)
        );
        // 非 32 字节公钥 → 拒绝。
        assert_eq!(
            verify_cert_tag(&auth_key, &ed_pub[..31], &tag),
            Err(AuthError::NotEd25519)
        );
    }

    #[test]
    fn cert_tag_matches_hmac_sha512_definition() {
        // `cert_auth_tag` 就是 `hmac_sha512(auth_key, msg)`；
        // 后者的 RFC 4231 向量已在 `hash::hmac` 测试中校验。
        let key = [0x11u8; 32];
        let msg = [0x22u8; 32];
        assert_eq!(
            cert_auth_tag(&key, &msg),
            crate::reality::hash::hmac_sha512(&key, &msg)
        );
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let server_secret = [4u8; 32];
        let mut rng = SeqRng::new();
        let keys = RealityClientKeys::generate(&x25519_base(&server_secret), &mut rng).unwrap();
        let dbg = format!("{keys:?}");
        assert!(dbg.contains("<redacted>"));
        // 私钥字节不得出现（seed 为 [4u8;32]，公钥是它的变换，不会是全 04）。
        let secret_hex = "04".repeat(32);
        assert!(!dbg.contains(&secret_hex), "secret leaked: {dbg}");
    }
}
