//! 极简 HTML → 文本的单元验收（不依赖网络）。

use agent_tools_exec::html::{extract_title, to_text};

#[test]
fn strips_tags_and_keeps_block_breaks() {
    let html = "<html><body><p>alpha</p><p>beta</p></body></html>";
    assert_eq!(to_text(html), "alpha\nbeta");
}

#[test]
fn headings_keep_a_markdown_prefix() {
    let html = "<h2>Section</h2><p>body text</p>";
    assert_eq!(to_text(html), "## Section\nbody text");
}

#[test]
fn inline_tags_are_dropped_without_a_break() {
    let html = "<p>hello <b>bold</b> and <i>italic</i></p>";
    assert_eq!(to_text(html), "hello bold and italic");
}

#[test]
fn script_style_head_and_comments_are_removed() {
    let html = "<head><title>ignored</title><style>p{color:red}</style></head>\
                <!-- secret note --><script>var x = '<p>nope</p>';</script><p>real</p>";
    assert_eq!(to_text(html), "real");
}

#[test]
fn collapsed_whitespace_and_entity_decoding() {
    let html = "<p>  a\n\t  b&nbsp;&amp;&lt;c&gt;&#65;&#x42;  </p>";
    assert_eq!(to_text(html), "a b &<c>AB");
}

#[test]
fn unknown_or_broken_markup_is_survivable() {
    // 未闭合标签与裸 `<`：不报错，按字面处理。
    assert_eq!(to_text("<p>unclosed"), "unclosed");
    assert_eq!(to_text("a < b"), "a < b");
    assert_eq!(to_text(""), "");
    assert_eq!(to_text("<!doctype html><p>hi</p>"), "hi");
}

#[test]
fn title_is_extracted_with_inner_markup_removed() {
    let html = "<html><head><title>  My <em>Page</em>  </title></head><body>x</body></html>";
    assert_eq!(extract_title(html).as_deref(), Some("My Page"));
}

#[test]
fn title_is_none_when_absent_or_empty() {
    assert_eq!(extract_title("<html><body>x</body></html>"), None);
    assert_eq!(extract_title("<title></title>"), None);
    assert_eq!(extract_title("<titleled>x</titleled>"), None);
}

#[test]
fn table_cells_become_separate_lines() {
    let html = "<table><tr><td>one</td><td>two</td></tr></table>";
    assert_eq!(to_text(html), "one\ntwo");
}
