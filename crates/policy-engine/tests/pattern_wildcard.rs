//! 规格 §2.5「URL 匹配」边界：通配符编译语义、scheme 归一化、大小写敏感。
//!
//! 本 crate 冻结的匹配语言（不依赖正则库：编译一次，匹配期只借用输入）：
//! - 比较面只有 **host + path**：scheme 归一化后丢弃，query/fragment 剥离；
//! - `*`：段内通配 —— host 区内不跨 `.`，path 区内不跨 `/`，至少吃掉一个字符；
//!   例外：host 段整体只写 `*` 或 `**` 时表示「任意主机」（可跨标签）；
//! - `**`：跨段通配 —— host 区内跨 `.` 且至少一个标签，path 区内跨 `/` 且允许零段；
//!   `**` 必须独占一段，禁止 `a**b` 这类混合写法；
//! - 纯通配模式（`*`、`**`、`*/**`、`**/**`）即「所有网页」模式；
//! - `?`：段内单字符；`{n}`/`{n..m}`/`{n..}` 只在路径尾部限定剩余段数（上界必须有界）；
//! - 其余字符一律字面量（无转义语言）；大小写敏感；百分号转义只校验合法性、不解码。

use policy_engine::pattern::{more_specific, CompileError, NormalizedUrl, Pattern, Specificity};

const HTTPS: &str = "https:";
const HTTP: &str = "http:";

/// 组装带 scheme 的完整 URL；规则文本与 URL 数据刻意分开写，读起来更贴近配置。
fn url(host_path: &str) -> String {
    format!("{}//{}", HTTPS, host_path)
}

fn parse(raw: &str) -> NormalizedUrl {
    NormalizedUrl::parse(raw).unwrap_or_else(|e| panic!("URL {raw:?} 应能归一化，实际失败：{e}"))
}

fn compile(pattern: &str) -> Pattern {
    Pattern::compile(pattern).unwrap_or_else(|e| panic!("模式 {pattern:?} 应能编译：{e}"))
}

fn compile_fail(pattern: &str) -> CompileError {
    Pattern::compile(pattern)
        .err()
        .unwrap_or_else(|| panic!("模式 {pattern:?} 必须编译失败"))
}

/// 模式 + host/path 的命中判定。
fn hit(pattern: &str, host_path: &str) -> bool {
    hit_raw(pattern, &url(host_path))
}

/// 原样 URL（含非法写法）的命中判定，用于测试拒绝路径。
fn hit_raw(pattern: &str, raw: &str) -> bool {
    let compiled = compile(pattern);
    match NormalizedUrl::parse(raw) {
        Ok(normalized) => compiled.is_match(&normalized),
        Err(e) => panic!("URL {raw:?} 应能归一化，实际失败：{e}"),
    }
}

#[test]
fn single_star_matches_within_one_segment_only() {
    assert!(hit("*.example.com/*", "admin.example.com/reports"));
    assert!(!hit("*.example.com/*", "admin.example.com/reports/q3"));
    assert!(!hit("example.com/*", "example.com/a/b"));
    assert!(hit("example.com/*", "example.com/a"));
    assert!(hit("example.com/*.pdf", "example.com/annual.pdf"));
    assert!(!hit("example.com/*.pdf", "example.com/annual.pdfx"));
    // `*` 至少吃掉一个字符，因此不会产生「空段也算命中」的意外。
    assert!(!hit("example.com/*", "example.com/"));
}

#[test]
fn question_mark_is_one_char_within_segment() {
    assert!(hit("example.com/a?c", "example.com/abc"));
    assert!(!hit("example.com/a?c", "example.com/ac"));
    assert!(!hit("example.com/a?c", "example.com/abbc"));
    assert!(!hit("example.com/a?c", "example.com/a/c"));
}

#[test]
fn double_star_crosses_path_segments() {
    // 规格 §3：需要跨段时模式必须写 `**`。
    assert!(hit("example.com/**", "example.com/a/b/c"));
    assert!(!hit("example.com/**", "other.com/a/b"));
    assert!(hit("example.com/**/edit", "example.com/a/b/edit"));
    assert!(hit("example.com/**/edit", "example.com/edit"));
    assert!(!hit("example.com/**/edit", "example.com/edit/force"));
    // 尾部 `**` 允许零段 ⇒ 前缀模式覆盖站点根。
    assert!(hit("example.com/**", "example.com/"));
}

#[test]
fn bare_wildcard_is_the_all_pages_pattern() {
    assert!(hit("*", "anything.test/x"));
    assert!(hit("*", "a.example.com/x/y"));
    assert!(hit("**", "a.b.c.d/e/f"));
    assert!(hit("*/**", "a.b.c.d/e/f"));
    assert!(compile("*").is_all_pages());
    assert!(compile("**").is_all_pages());
    assert!(compile("*/**").is_all_pages());
    assert_eq!(compile("*").specificity(), Specificity::AllPages);
}

#[test]
fn star_in_host_label_does_not_match_multilabel_subdomain() {
    // 规格 §3 明文要求：`*.example.com` 不匹配 `a.b.example.com`。
    assert!(hit("*.example.com", "a.example.com"));
    assert!(!hit("*.example.com", "a.b.example.com"));
    assert!(!hit("*.example.com", "example.com"));
    assert!(!hit("*.example.com", "a.other.com"));
    // 需要跨标签时显式写 `**`（规格 §3 括注）。
    assert!(hit("**.example.com", "a.b.example.com"));
    assert!(hit("**.example.com/**", "a.b.example.com/x/y"));
    // host 区 `**` 至少吃掉一个标签，不能退化成空标签。
    assert!(!hit("**.example.com", "example.com"));
    // 有字面锚点时 host 区 `*` 同样不跨 `.`。
    assert!(!hit("a.*.com", "a.b.c.com"));
    assert!(hit("a.*.com", "a.b.com"));
}

#[test]
fn whole_host_wildcard_matches_any_host() {
    // host 段整体只写 `*`/`**` ⇒ 任意主机（含多标签），这是「所有网页」写法的基础。
    assert!(hit("*/x", "a.b.c.test/x"));
    assert!(hit("**/x", "a.b.c.test/x"));
    assert!(!hit("*/x", "a.b.c.test/y"));
}

#[test]
fn pattern_without_path_only_covers_site_root() {
    // 模式不含 `/` ⇒ 只匹配站点根路径；覆盖整站必须显式写 `/**` 或 `/*`。
    assert!(hit("example.com", "example.com/"));
    assert!(!hit("example.com", "example.com/login"));
    assert!(hit("example.com/**", "example.com/login"));
}

#[test]
fn segment_count_patterns_match_and_bound() {
    assert!(hit("example.com/{1}", "example.com/a"));
    assert!(!hit("example.com/{1}", "example.com/a/b"));
    assert!(hit("example.com/{2}", "example.com/a/b"));
    assert!(hit("example.com/{1..3}", "example.com/a/b/c"));
    assert!(!hit("example.com/{1..3}", "example.com/a/b/c/d"));
    assert!(hit("example.com/{1..}", "example.com/a/b/c/d/e"));
    assert!(!hit("example.com/{1..}", "example.com/"));
    assert!(hit("example.com/admin/{1}", "example.com/admin/x"));
    assert!(!hit("example.com/admin/{1}", "example.com/admin"));
    assert!(hit("example.com/{0..2}", "example.com/"));
    assert!(hit("example.com/{0..2}", "example.com/a/b"));
    assert!(!hit("example.com/{0..2}", "example.com/a/b/c"));
    // 非数字花括号是字面量，不做展开解释。
    assert!(hit("example.com/{a}", "example.com/{a}"));
    assert!(!hit("example.com/{a}", "example.com/b"));
}

#[test]
fn matching_is_case_sensitive() {
    // 规格 §2.5：大小写敏感（host 与 path 都不折叠）。
    assert!(hit("example.com/Docs", "example.com/Docs"));
    assert!(!hit("example.com/Docs", "example.com/docs"));
    assert!(!hit("example.com/docs", "example.com/Docs"));
    assert!(!hit("EXAMPLE.com/a", "example.com/a"));
    assert!(hit("EXAMPLE.com/a", "EXAMPLE.com/a"));
}

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
fn pattern_compile_rejects_degenerate_and_oversized_input() {
    assert!(matches!(compile_fail(""), CompileError::EmptyPattern));
    assert!(matches!(compile_fail("   "), CompileError::EmptyPattern));
    assert!(matches!(
        compile_fail("example.com/{2..1}"),
        CompileError::InvertedSegmentRange { .. }
    ));
    assert!(matches!(
        compile_fail("example.com/{0..0}"),
        CompileError::EmptySegmentRange { .. }
    ));
    // 段计数上界必须有界：无界上界等价于隐式全通配，会绕过精度排序。
    assert!(compile_fail("example.com/{1..999999}")
        .to_string()
        .contains("上界"));
    assert!(matches!(
        compile_fail("example.com/{0..}"),
        CompileError::UnboundedAllWildcard { .. }
    ));
    // 跨段通配数量设上限：越多组合越爆炸，策略作者应拆成多条规则。
    let many = format!("example.com/{}", vec!["**"; 20].join("/"));
    assert!(matches!(
        Pattern::compile(&many),
        Err(CompileError::TooManyCrossWildcards { .. })
    ));
    let long = format!("{}*", "x".repeat(600));
    assert!(matches!(
        Pattern::compile(&long),
        Err(CompileError::PatternTooLong { .. })
    ));
    // 空白与控制字符一律拒绝：规则文本不该有隐形字符。
    assert!(Pattern::compile("example.com/a\nb").is_err());
    assert!(Pattern::compile("exam\tple.com").is_err());
    assert!(Pattern::compile("example.com/a b").is_err());
    assert!(Pattern::compile(" example.com/a").is_err());
    // 比较面不含 scheme，带 scheme 的模式永远不可能命中：
    // 编译期就拒绝，而不是留一条静默失效的黑名单规则。
    assert!(matches!(
        compile_fail(&url("example.com/a")),
        CompileError::SchemeInPattern
    ));
    assert!(matches!(
        compile_fail("http://example.com/a"),
        CompileError::SchemeInPattern
    ));
    // host 区出现 `?`/`{n}` 之外的段计数写法不合法。
    assert!(Pattern::compile("{1}example.com").is_err());
}

#[test]
fn illegal_wildcard_shapes_are_rejected_at_compile_time() {
    for bad in [
        "example.com/a**b",   // `**` 必须独占一段
        "**x.example.com",    // host 区内混字面量
        "example.com/{",      // 未闭合
        "example.com/{1",     // 未闭合
        "example.com/{-1}",   // 负数
        "example.com/{1..}x", // 段数限定只允许出现在尾部
        "example.com/*#frag", // 片段不属于比较面
        "example.com/a?q=1",  // 查询串不属于比较面
        "example.com//",      // 空段
        "a..b",               // host 空标签
    ] {
        assert!(Pattern::compile(bad).is_err(), "非法模式必须拒绝: {bad:?}");
    }
}

#[test]
fn literal_pattern_is_exact_and_uses_no_backtracking() {
    // 规格 §2.4：精确规则 > 通配规则 —— 精确形态必须走纯字面量比较。
    let exact = compile("example.com/login");
    assert!(exact.is_literal(), "无通配符即字面量模式");
    assert!(!exact.is_all_pages());
    assert_eq!(exact.wildcards(), 0);
    assert!(hit("example.com/login", "example.com/login"));
    assert!(!hit("example.com/login", "example.com/logi"));
    assert!(!hit("example.com/login", "example.com/login/"));
    // 字面量模式不解释转义与正则元字符：`.` 就是点，不是任意字符。
    assert!(hit("example.com/a.b", "example.com/a.b"));
    assert!(!hit("example.com/a.b", "example.com/axb"));
    assert!(hit("example.com/a+b", "example.com/a+b"));
    assert!(!hit("example.com/a+b", "example.com/axb"));
}

#[test]
fn all_pages_detection_only_accepts_true_universals() {
    for p in ["*", "**", "*/**", "**/**"] {
        assert!(compile(p).is_all_pages(), "{p:?} 必须是所有网页通配");
    }
    for p in [
        "*/*",
        "*.example.com",
        "example.com/*",
        "example.com/admin/**",
        "**/*.js",
        "example.com/{1..}",
        "example.com/**",
    ] {
        assert!(!compile(p).is_all_pages(), "{p:?} 不是所有网页通配");
    }
    // `*/*` 只覆盖单段路径，因此不是全网页通配。
    assert!(hit("*/*", "a.b.c/x"));
    assert!(!hit("*/*", "a.b.c/x/y"));
}

#[test]
fn specificity_orders_exact_above_host_anchored_above_all_pages() {
    let cases = [
        ("example.com/a/b", Specificity::Exact),
        ("example.com/login", Specificity::Exact),
        ("example.com/*", Specificity::HostAnchored),
        ("example.com/admin/*", Specificity::HostAnchored),
        ("example.com/**", Specificity::HostAnchored),
        ("example.com/*.js", Specificity::HostAnchored),
        ("example.com/{1..}", Specificity::HostAnchored),
        ("*.example.com/*", Specificity::HostWildcard),
        ("**.example.com/admin", Specificity::HostWildcard),
        ("**/*.js", Specificity::HostWildcard),
        ("*/x", Specificity::HostWildcard),
        ("*", Specificity::AllPages),
        ("**", Specificity::AllPages),
        ("*/**", Specificity::AllPages),
    ];
    for (pattern, expected) in cases {
        assert_eq!(
            compile(pattern).specificity(),
            expected,
            "模式 {pattern:?} 精度分级不符"
        );
    }
    assert!(Specificity::Exact > Specificity::HostAnchored);
    assert!(Specificity::HostAnchored > Specificity::HostWildcard);
    assert!(Specificity::HostWildcard > Specificity::AllPages);
    assert_eq!(Specificity::ALL.len(), 4);
}

#[test]
fn same_level_specificity_prefers_longer_literal_anchor() {
    // 规格 §2.4：精确 > 通配；同级之内再比字面锚点长度，长度相同才交给规则序。
    let broad = compile("example.com/*");
    let narrow = compile("example.com/admin/*");
    assert_eq!(broad.specificity(), narrow.specificity());
    assert!(
        more_specific(&narrow, &broad),
        "example.com/admin/* 应优先于 example.com/*"
    );
    assert!(!more_specific(&broad, &narrow));
    // 自反比较不得声称优先，否则排序不稳定、规则序失效。
    assert!(!more_specific(&broad, &broad));
    // 同级同长度 ⇒ 互不优先（按规则序裁决）。
    let left = compile("example.com/a/*");
    let right = compile("example.com/b/*");
    assert!(!more_specific(&left, &right));
    assert!(!more_specific(&right, &left));
    // 跨级比较只看级别，长度不得反超。
    assert!(more_specific(&compile("example.com/a/b"), &narrow));
    assert!(!more_specific(&narrow, &compile("example.com/a/b")));
    // 通配数量不参与优先判定（长度已足够区分，避免二义规则集）。
    assert_eq!(broad.wildcards(), 1);
    assert_eq!(narrow.wildcards(), 1);
    assert_eq!(compile("example.com/*/*").wildcards(), 2);
    assert_eq!(compile("example.com/**").cross_wildcards(), 1);
    assert_eq!(compile("example.com/*").cross_wildcards(), 0);
}

#[test]
fn compiled_pattern_is_reused_and_matching_borrows_input() {
    // 规格 §2.5：编译期一次，匹配期零分配优先 —— 匹配结果只借用输入。
    let compiled = compile("*.example.com/**/admin/*");
    let normalized = parse(&url("a.example.com/x/y/admin/edit"));
    assert!(compiled.is_match(&normalized));
    let borrowed: &str = compiled
        .matched_path(&normalized)
        .expect("命中时必须返回借用自输入的路径片段");
    let input = normalized.as_str();
    let base = input.as_ptr() as usize;
    let start = borrowed.as_ptr() as usize;
    assert!(
        start >= base && start + borrowed.len() <= base + input.len(),
        "返回值必须是输入里的借用片段，不能是新分配"
    );
    assert!(
        borrowed.starts_with('/'),
        "路径片段应以 / 开头: {borrowed:?}"
    );
    assert_eq!(compiled.url_pattern(), "*.example.com/**/admin/*");
    assert_eq!(compiled.cross_wildcards(), 1);
    // 未命中时无借用可返回。
    let miss = parse(&url("a.example.com/admin"));
    assert!(compiled.matched_path(&miss).is_none());
    assert!(!compiled.is_match(&miss));
    // 字面量模式的片段同样是整段路径。
    let exact = compile("example.com/login");
    assert_eq!(
        exact.matched_path(&parse(&url("example.com/login"))),
        Some("/login")
    );
    assert_eq!(exact.matched_path(&miss), None);
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
