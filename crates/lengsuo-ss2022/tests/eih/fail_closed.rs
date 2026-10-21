// 拒绝路径：截断 / 未知身份 / 错误 salt / 链长与形态边界。
//
// 本文件由 `tests/eih.rs` 用 `include!` 文本并入同一模块；
// 共享助手在 `tests/eih.rs` 入口文件，`use` 全部写在入口文件。
#[test]
fn truncated_unknown_and_wrong_salt_are_fail_closed() {
    let identity = key(Method::Aes256, 0x11);
    let user = key(Method::Aes256, 0x22);
    let salt = [0x5Au8; 32];
    let users = table(user.clone(), 7);
    let headers = IdentityChain::new(vec![identity.clone()], user)
        .expect("链")
        .headers(&salt)
        .expect("可编码");

    // 截断：不足一个 AES 块。
    assert!(matches!(
        decode_header(
            &identity,
            &users,
            &salt,
            &headers[..IDENTITY_HEADER_LEN - 1]
        ),
        Err(Error::EihTruncated)
    ));
    // 指纹不在表中（未知身份）。
    let stranger = key(Method::Aes256, 0x99);
    let unknown = IdentityChain::new(vec![identity.clone()], stranger)
        .expect("链")
        .headers(&salt)
        .expect("可编码");
    assert!(matches!(
        decode_header(&identity, &users, &salt, &unknown),
        Err(Error::IdentityUnknown)
    ));
    // salt 不匹配 → 解出的指纹是伪随机值 → 未知身份，绝不回退单用户。
    assert!(matches!(
        decode_header(&identity, &users, &[0x77; 32], &headers),
        Err(Error::IdentityUnknown)
    ));
    // 长度不符的 salt 直接拒绝。
    assert!(matches!(
        decode_header(&identity, &users, &[0x77; 16], &headers),
        Err(Error::KeyLength)
    ));
}

#[test]
fn chain_bounds_and_shape_are_enforced() {
    let identity = key(Method::Aes128, 0x11);
    let user = key(Method::Aes128, 0x22);
    let users = table(user.clone(), 1);
    let salt = [0u8; 16];
    let headers = IdentityChain::new(vec![identity.clone()], user.clone())
        .expect("链")
        .headers(&salt)
        .expect("可编码");

    assert!(matches!(
        decode_chain(&identity, &users, &salt, &headers, 0),
        Err(Error::EihMissing)
    ));
    assert!(matches!(
        decode_chain(&identity, &users, &salt, &headers, MAX_IDENTITY_LAYERS + 1),
        Err(Error::EihChainTooLong)
    ));
    assert!(matches!(
        decode_chain(&identity, &users, &salt, &headers, 2),
        Err(Error::EihTruncated)
    ));

    // 客户端链同样受限；空身份列表是合法的单用户形态（不写身份头）。
    let mut too_many = Vec::new();
    for byte in 0..=MAX_IDENTITY_LAYERS {
        too_many.push(key(Method::Aes128, byte as u8));
    }
    assert!(matches!(
        IdentityChain::new(too_many, user.clone()),
        Err(Error::EihChainTooLong)
    ));
    let single = IdentityChain::new(Vec::new(), user).expect("单用户链");
    assert_eq!(single.layers(), 0);
    assert!(single.headers(&salt).expect("可编码").is_empty());

    // 混合套件在构造期拒绝。
    assert!(matches!(
        IdentityChain::new(vec![key(Method::Aes256, 0x11)], key(Method::Aes128, 0x22)),
        Err(Error::KeyLength)
    ));
    // 参考 MultiService 明确只支持 AES；ChaCha 身份链拒绝。
    assert!(matches!(
        IdentityChain::new(Vec::new(), key(Method::ChaCha20, 0x22)),
        Err(Error::Unsupported)
    ));
}
