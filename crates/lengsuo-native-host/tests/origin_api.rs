//! 来源解析的 API 级用例。
//!
//! 覆盖：
//! - Chromium 的规范形式、防御性接受的尾斜杠形式；
//! - 大小写不敏感（照 `IdIsValid`）；
//! - **两个不同的合法 ID 都能通过** ⇒ 证明本卡不硬编码任何扩展 ID；
//! - scheme / 路径 / 查询 / 空主机 / 长度 / 字母表各类拒绝情形，
//!   且报错变体可区分。

use lengsuo_native_host::error::{IdFormatError, OriginError};
use lengsuo_native_host::origin::{parse_extension_id, EXTENSION_ID_LEN, EXTENSION_SCHEME_PREFIX};

/// 合成夹具：ID_A。
const ID_A: &str = "abcdefghijklmnopabcdefghijklmnop";
/// 合成夹具：ID_B。
const ID_B: &str = "ponmlkjihgfedcbaponmlkjihgfedcba";

/// 拼一个 origin。
fn origin(id: &str) -> String {
    format!("{EXTENSION_SCHEME_PREFIX}{id}")
}

#[test]
fn accepts_the_canonical_form() {
    assert_eq!(parse_extension_id(&origin(ID_A)), Ok(ID_A));
    assert_eq!(parse_extension_id(&origin(ID_B)), Ok(ID_B));
    // 两个不同的合法 ID 都通过 ⇒ 没有硬编码白名单。
    assert_ne!(ID_A, ID_B);
}

#[test]
fn accepts_the_trailing_slash_form() {
    // Chromium 的规范形式（标准 scheme ⇒ 空路径补成 '/' ⇒ spec() 带尾斜杠）。
    assert_eq!(parse_extension_id(&format!("{}/", origin(ID_A))), Ok(ID_A));
}

#[test]
fn accepts_the_form_without_trailing_slash() {
    // 防御性接受：万一日后 chrome-extension 不再登记为标准 scheme，
    // spec() 就会是这个形状。
    assert_eq!(parse_extension_id(&origin(ID_A)), Ok(ID_A));
}

#[test]
fn accepts_uppercase_ids() {
    // 照 Chromium `IdIsValid`（先 ToLowerASCII 再比）⇒ 大小写不敏感。
    let upper = ID_A.to_uppercase();
    assert_eq!(parse_extension_id(&origin(&upper)), Ok(upper.as_str()));
}

#[test]
fn rejects_wrong_or_missing_scheme() {
    for bad in [
        format!("https://{ID_A}"),
        format!("chrome-extension:/{ID_A}"),
        ID_A.to_owned(),
        String::new(),
    ] {
        match parse_extension_id(&bad) {
            Err(OriginError::NotExtensionOrigin(got)) => assert_eq!(got, bad),
            other => panic!("{:?} 应报 not_extension_origin，实际 {:?}", bad, other),
        }
    }
}

#[test]
fn rejects_paths_queries_and_fragments() {
    for bad in [
        format!("{}/foo", origin(ID_A)),
        format!("{}?x=1", origin(ID_A)),
        format!("{}#frag", origin(ID_A)),
        format!("{}//", origin(ID_A)),
    ] {
        match parse_extension_id(&bad) {
            Err(OriginError::NotExtensionOrigin(got)) => assert_eq!(got, bad),
            other => panic!("{:?} 应报 not_extension_origin，实际 {:?}", bad, other),
        }
    }
}

#[test]
fn rejects_wrong_id_length() {
    // 空主机：形状就不对（Chromium 只会传一个 32 字符的 host），不是长度错。
    assert_eq!(
        parse_extension_id(EXTENSION_SCHEME_PREFIX),
        Err(OriginError::NotExtensionOrigin(
            EXTENSION_SCHEME_PREFIX.to_owned()
        ))
    );

    // 16 个字符（旧契约里的 16 字符形状也算错：Chromium 的 ID 是 32 字符）。
    let short = &ID_A[..16];
    assert_eq!(
        parse_extension_id(&origin(short)),
        Err(OriginError::InvalidExtensionId {
            id: short.to_owned(),
            reason: IdFormatError::Length { actual: 16 },
        })
    );

    // 33 个字符。
    let long = format!("{ID_A}a");
    assert_eq!(
        parse_extension_id(&origin(&long)),
        Err(OriginError::InvalidExtensionId {
            id: long.clone(),
            reason: IdFormatError::Length { actual: 33 },
        })
    );
}

#[test]
fn rejects_characters_outside_the_a_to_p_alphabet() {
    // `q` 是字母表 `a`–`p` 之外最小的越界字符。
    let bad = "abcdefghijklmnopabcdefghijklmnoq";
    assert_eq!(
        parse_extension_id(&origin(bad)),
        Err(OriginError::InvalidExtensionId {
            id: bad.to_owned(),
            reason: IdFormatError::Char { char: 'q' },
        })
    );

    // 数字、大写以外的符号都不在字母表里。
    let bad = "0bcdefghijklmnopabcdefghijklmnop";
    assert_eq!(
        parse_extension_id(&origin(bad)),
        Err(OriginError::InvalidExtensionId {
            id: bad.to_owned(),
            reason: IdFormatError::Char { char: '0' },
        })
    );

    // 带端口：冒号不在字母表里（不是「长度不对」）。
    let with_port = format!("{}{}", origin(ID_A), ":123");
    assert_eq!(
        parse_extension_id(&with_port),
        Err(OriginError::InvalidExtensionId {
            id: format!("{ID_A}:123"),
            reason: IdFormatError::Char { char: ':' },
        })
    );
}

#[test]
fn rejects_multibyte_characters_by_char_not_by_byte() {
    // 32 个汉字 = 96 字节：若按字节长度判，会误报长度；这里必须报越界字符。
    let bad: String = "中".repeat(EXTENSION_ID_LEN);
    assert_eq!(
        parse_extension_id(&origin(&bad)),
        Err(OriginError::InvalidExtensionId {
            id: bad.clone(),
            reason: IdFormatError::Char { char: '中' },
        })
    );
}

#[test]
fn id_alphabet_boundaries_are_inclusive() {
    // `a` 与 `p` 必须接受（边界含在内）。
    let id = format!("{}p", "a".repeat(EXTENSION_ID_LEN - 1));
    assert_eq!(parse_extension_id(&origin(&id)), Ok(id.as_str()));

    // `o` 是字母表内最后一个「o-p 段」的前一个字符，必须接受。
    let id = format!("{}o", "a".repeat(EXTENSION_ID_LEN - 1));
    assert_eq!(parse_extension_id(&origin(&id)), Ok(id.as_str()));
}
