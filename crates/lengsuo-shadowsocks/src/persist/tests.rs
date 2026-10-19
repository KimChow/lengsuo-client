use super::*;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
fn sha256_matches_fips_vectors() {
    // FIPS 180-4 公开测试向量。
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // 跨块边界（55/56/64 字节附近）与多块输入。
    let long = vec![b'a'; 1000];
    assert_eq!(
        hex(&sha256(&long)),
        "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
    );
}

#[test]
fn sha256_streaming_matches_one_shot() {
    let data = vec![0x5Au8; 200];
    let mut hasher = Sha256::new();
    for chunk in data.chunks(7) {
        hasher.update(chunk);
    }
    let streamed = hasher.finish();
    assert_eq!(streamed, sha256(&data));
}

#[test]
fn hmac_sha256_matches_rfc_4231_vectors() {
    // RFC 4231 测试向量（HMAC-SHA256）。
    let key = [0x0bu8; 20];
    assert_eq!(
        hex(&hmac_sha256(&key, b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // 密钥长于块长（64 字节）触发先哈希路径。
    let long_key = [0xaau8; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    assert_eq!(
        hex(&hmac_sha256(&long_key, data)),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn constant_time_eq_matches_semantics() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"abcd"));
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn mac_key_rotation_accepts_previous_and_flags_upgrade() {
    let dir = std::env::temp_dir().join(format!("lengsuo-ss-mac-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.bin");
    let old = MacKey::new(b"old-key".to_vec());
    let new = MacKey::new(b"new-key".to_vec());
    std::fs::write(&path, b"").ok();

    save_with_key(&path, b"payload", &old).unwrap();
    // 用新密钥（当前）+ 旧密钥（上一代）加载 → 命中上一代并标记需要升级。
    let loaded = load_with_keys(&path, &new, Some(&old)).unwrap().unwrap();
    assert!(loaded.key_rotated, "应以旧密钥命中并标记升级");
    assert_eq!(loaded.body, b"payload");

    // 升级后仅旧密钥不再可用。
    save_with_key(&path, &loaded.body, &new).unwrap();
    assert!(
        !load_with_keys(&path, &new, Some(&old))
            .unwrap()
            .unwrap()
            .key_rotated,
        "升级后不应再标记为需要轮换"
    );
    let only_old = load_with_keys(&path, &old, None).unwrap_err();
    assert!(matches!(only_old, Error::MacMismatch));
    let _ = std::fs::remove_dir_all(&dir);
}
