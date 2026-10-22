// 承接自孤儿用例 `crates/ss-cli/tests/config/url.rs` 中**唯一有真实实现可承接**的两条。
//
// 孤儿用例针对的是从未落地的 `ss_cli::config::SsUrl`（`ss://` URL 解析），
// 而仓内**没有任何** `SsUrl`/`SsUrlError` 实现（`crates/` 全域搜索无命中）。
// 与「加密套件名 ↔ 实现」的对应关系在真实实现里落在
// `ss_core::crypto::CipherSuite::from_name`（`crates/ss-core/src/crypto.rs:29`），
// 生产调用方是 `crates/lengsuo-node/src/outbound_ss.rs:89`。
//
// 下面两条用例**用例名逐字保留**（见 `docs/ss-cli-orphan-tests.md` §3：改名点 = 无），
// 但断言按**真实实现**改写。

/// 真实实现支持的全部套件名都必须被接受。
///
/// 偏离 D1：孤儿用例期望的是「大小写**不**敏感 + 含 `aes-192-gcm`」。
/// 真实实现 `CipherSuite::from_name` 是**大小写敏感的精确匹配**，且只登记 4 个套件
/// （`aes-128-gcm`/`aes-256-gcm`/`chacha20-ietf-poly1305`/`xchacha20-ietf-poly1305`）——
/// 没有 `aes-192-gcm` 套件。故孤儿期望在真实实现中**不成立**，此处按真实契约断言。
#[test]
fn accepts_all_supported_cipher_names_case_insensitively() {
    for name in [
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
    ] {
        assert!(CipherSuite::from_name(name).is_some(), "{name} 应被支持");
    }

    // 大小写敏感：孤儿用例期望的「大小写不敏感」在真实实现中不成立。
    assert!(CipherSuite::from_name("AES-256-GCM").is_none());
    assert!(CipherSuite::from_name("Chacha20-IETF-Poly1305").is_none());

    // 真实实现没有 aes-192-gcm 套件（只有 aes-128 / aes-256）。
    assert!(CipherSuite::from_name("aes-192-gcm").is_none());
}

/// 未知套件名必须被拒绝，且失败路径有显式错误类型可表达。
#[test]
fn rejects_unknown_cipher() {
    // 真实实现：未知套件名解析不出 ⇒ 调用方必须走错误分支，不得静默降级。
    assert!(CipherSuite::from_name("rc4-md5").is_none());
    assert!(CipherSuite::from_name("aes-192-gcm").is_none());
    assert!(CipherSuite::from_name("").is_none());

    // `UnsupportedCipher` 是 `ss-core` 对外公开的错误变体（`crates/ss-core/src/error.rs:30`），
    // 用来把「不支持的套件」表达为显式错误；其 Display 文本不得泄露任何密钥材料。
    // 诚实说明：仓内**目前没有任何构造点**（全域搜索只有这一处声明）——生产侧的拒绝走的是
    // `crates/lengsuo-node/src/outbound_ss.rs:90` 的 `DialError::Rejected`。
    // 此处断言的是 `ss-core` 对外公开的错误契约本身（变体存在 + Display 文本稳定）。
    let err = SsCoreError::UnsupportedCipher("rc4-md5".to_owned());
    assert_eq!(err.to_string(), "unsupported cipher: rc4-md5");
}
