// 通配段匹配语义：`*`/`?`/`**`/段计数/大小写（原 L51-L155，顺序未改）。
use crate::fixtures::*;

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
