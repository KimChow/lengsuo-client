// URL 归一化与边界：scheme 缺省、query/fragment 剥离、非法 URL 拒绝、双侧归一化一致（原 L157-L231、L434-L448，顺序未改）。
use crate::fixtures::*;

#[test]
fn scheme_defaults_to_https_and_does_not_participate_in_matching() {
    // 规格 §2.5：scheme 归一化（缺省 https）；scheme 自身大小写不敏感。
    assert_eq!(parse("example.com/a").authority(), "example.com");
    assert_eq!(parse(&url("example.com/a")).as_str(), "example.com/a");
    assert_eq!(
        parse(&format!("{}example.com/a", HTTP)).as_str(),
        "example.com/a"
    );
    assert_eq!(parse("HTTPS://example.com/a").as_str(), "example.com/a");
    assert_eq!(parse("example.com").as_str(), "example.com/");
    assert_eq!(parse("example.com/").as_str(), "example.com/");
    // 端口属于 host 的一部分：模式需显式写出，不带端口不匹配带端口。
    assert_eq!(parse("example.com:8443/a").as_str(), "example.com:8443/a");
    assert!(hit("example.com:8443/a", "example.com:8443/a"));
    assert!(!hit("example.com/a", "example.com:8443/a"));
    assert!(!hit("example.com", "example.com:8443/"));
    assert!(hit("example.com:8443", "example.com:8443/"));
    // IPv6 字面量保留方括号，不参与通配折叠。
    assert_eq!(parse("[::1]:8443/a").as_str(), "[::1]:8443/a");
    assert!(hit("[::1]:8443/a", "[::1]:8443/a"));
}

#[test]
fn query_and_fragment_are_stripped_so_rules_cannot_be_evaded() {
    // 追加 `?q=` / `#frag` 不得绕过既有规则（黑名单不可逃逸）。
    assert_eq!(parse("example.com/a?q=1").as_str(), "example.com/a");
    assert!(hit("example.com/a", "example.com/a?q=1"));
    assert!(hit("example.com/a", "example.com/a#frag"));
    assert!(hit("example.com/*", "example.com/a?q=1&x=2#f"));
    // 参数改名/换值不能逃逸 `*` 通配（旁证，不参与 query 剥离断言本身）。
    assert!(hit("example.com/*", "example.com/b?x=1"));

    // 真正的防逃逸测试：字面量规则在剥离 query 后照常命中 —— 追加参数
    // 不能把已命中的规则洗成未命中（规格 §2.5，与上一条互为对照）。
    assert!(hit("example.com/b", "example.com/b?x=1"));
    assert_eq!(parse("example.com/?q=1").as_str(), "example.com/");
    assert_eq!(parse("example.com#frag").as_str(), "example.com/");
}

#[test]
fn invalid_urls_are_rejected_rather_than_loosely_parsed() {
    for bad in [
        "",
        "   ",
        "://example.com",
        "ftp://example.com/a",
        "javascript:alert(1)",
        "HTTPS://",
        "https:/example.com/a",
        "http:/x",
        "example.com/a b",
        "example.com/%zz",
        "example.com/%4",
        "ex ample.com/a",
        "example..com/a",
        "example.com/a\u{7f}",
        "example.com/a\u{1}",
    ] {
        let err = NormalizedUrl::parse(bad)
            .err()
            .unwrap_or_else(|| panic!("非法 URL {bad:?} 必须拒绝"));
        assert!(!err.to_string().is_empty(), "错误信息必须可展示：{err}");
    }
    // userinfo 在比较面上没有落点，出现即拒绝（不做「忽略凭据」的宽松解释）。
    assert!(NormalizedUrl::parse("https://admin@example.com/a").is_err());
    // 百分号转义只校验合法性，不解码：模式与 URL 以同一形态比较，避免二次解释。
    assert_eq!(parse("example.com/a%20b").as_str(), "example.com/a%20b");
    assert!(hit("example.com/a%20b", "example.com/a%20b"));
    // IP 字面量主机是合法 URL（内网系统常见），必须可归一化。
    assert_eq!(parse("192.168.0.1/login").as_str(), "192.168.0.1/login");
    assert!(hit("192.168.0.1/*", "192.168.0.1/login"));
    // 单标签主机（内网名）同样合法。
    assert_eq!(parse("intranet/a").as_str(), "intranet/a");
}

#[test]
fn pattern_and_url_are_normalized_identically() {
    // 模式侧与 URL 侧共用同一套归一化：不存在「模式宽松、URL 严格」的错配。
    let normalized_pattern = compile("example.com/a/").normalized_form().to_owned();
    assert_eq!(normalized_pattern, "example.com/a/");
    assert_eq!(parse("example.com/a/").as_str(), "example.com/a/");
    assert_eq!(
        compile("example.com").normalized_form(),
        parse("example.com").as_str()
    );
    // 模式侧空路径补 `/`，与 URL 侧一致。
    assert_eq!(compile("*.example.com").normalized_form(), "*.example.com/");
    // host 通配段的 `.` 边界与 URL 一致，不吞尾点。
    assert_eq!(compile("a.example.com").normalized_form(), "a.example.com/");
}
