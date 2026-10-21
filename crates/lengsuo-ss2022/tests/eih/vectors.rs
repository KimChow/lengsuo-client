// 固定向量与身份头解析：单层解析、链式解析、逐层顺序。
//
// 本文件由 `tests/eih.rs` 用 `include!` 文本并入同一模块；
// 共享助手在 `tests/eih.rs` 入口文件，`use` 全部写在入口文件。
#[test]
fn identity_headers_match_go_reference_vectors() {
    // Go: blake3.Sum512(psk)[:16]；aes.NewCipher(blake3.DeriveKey(iPSK||salt))。
    let identity128 = key(Method::Aes128, 0x11);
    let user128 = key(Method::Aes128, 0x22);
    let chain = IdentityChain::new(vec![identity128], user128).expect("AES-128 链");
    assert_eq!(
        to_hex(&chain.headers(&[0u8; 16]).expect("可编码")),
        "5c0477dfa5593697e65ed8d41dc1d482"
    );

    let identity256 = key(Method::Aes256, 0x11);
    let user256 = key(Method::Aes256, 0x22);
    let chain = IdentityChain::new(vec![identity256], user256).expect("AES-256 链");
    assert_eq!(
        to_hex(&chain.headers(&[0u8; 32]).expect("可编码")),
        "917dd2469bd4046323f5f88523d7a3aa"
    );

    // 两层链：第一层指纹指向 iPSK1，第二层指向 uPSK（0x33）。
    let chain = IdentityChain::new(
        vec![key(Method::Aes256, 0x11), key(Method::Aes256, 0x22)],
        key(Method::Aes256, 0x33),
    )
    .expect("两层链");
    let headers = chain.headers(&[0u8; 32]).expect("可编码");
    assert_eq!(headers.len(), 2 * IDENTITY_HEADER_LEN);
    assert_eq!(
        to_hex(&headers),
        "917dd2469bd4046323f5f88523d7a3aa61dcdc089942d9edb64a274907ee832e"
    );
}

#[test]
fn decoding_one_layer_resolves_the_local_uid() {
    let identity = key(Method::Aes256, 0x11);
    let user = key(Method::Aes256, 0x22);
    let salt = [0u8; 32];
    let headers = IdentityChain::new(vec![identity.clone()], user.clone())
        .expect("链")
        .headers(&salt)
        .expect("可编码");
    let resolved = decode_header(&identity, &table(user.clone(), 42), &salt, &headers)
        .expect("应能解析出用户");
    assert_eq!(resolved.uid, 42);
    // 解出的密钥必须能重新生成同一身份头（证明拿到的正是用户 PSK）。
    let again = IdentityChain::new(vec![identity], resolved.key)
        .expect("链")
        .headers(&salt)
        .expect("可编码");
    assert_eq!(again, headers);
}

#[test]
fn chained_decoding_reports_every_layer_in_order() {
    let identity = key(Method::Aes256, 0x11);
    let relay_user = key(Method::Aes256, 0x22);
    let user = key(Method::Aes256, 0x33);
    let salt = [0u8; 32];
    let headers = IdentityChain::new(vec![identity.clone(), relay_user.clone()], user.clone())
        .expect("链")
        .headers(&salt)
        .expect("可编码");
    let users = UserTable::new(vec![
        User {
            uid: 1,
            key: relay_user,
        },
        User { uid: 2, key: user },
    ])
    .expect("用户表");
    let (chain, consumed) = decode_chain(&identity, &users, &salt, &headers, 2).expect("可解析");
    assert_eq!(consumed, 2 * IDENTITY_HEADER_LEN);
    assert_eq!(chain.uids(), vec![1, 2]);
    assert_eq!(chain.next.as_deref().map(|next| next.uid), Some(2));
    assert_eq!(chain.len(), 2);
    // 解析结果可按本地 uid 链重新编码，逐字节回到同一线格式。
    assert_eq!(
        chain.encode(&identity, &users, &salt).expect("可编码"),
        headers
    );
    assert!(matches!(
        chain.encode(&identity, &table(key(Method::Aes256, 0x44), 1), &salt),
        Err(Error::IdentityUnknown)
    ));

    // 只解一层时只消费 16 字节，余下留给中继。
    let (first, consumed) = decode_chain(&identity, &users, &salt, &headers, 1).expect("可解析");
    assert_eq!(consumed, IDENTITY_HEADER_LEN);
    assert_eq!(first.uids(), vec![1]);
}
