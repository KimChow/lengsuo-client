// 精度分级与复用：字面量模式、所有网页检测、specificity 排序、借用匹配（原 L301-L432，顺序未改）。
use crate::fixtures::*;

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
