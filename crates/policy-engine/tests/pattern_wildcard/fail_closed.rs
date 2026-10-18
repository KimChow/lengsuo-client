// 拒绝与 fail-closed：退化/超限模式与非法通配写法编译期拒绝（原 L233-L299，顺序未改）。
use crate::fixtures::*;

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
