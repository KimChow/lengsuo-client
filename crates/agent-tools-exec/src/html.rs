//! 手写极简 HTML → 文本：删脚本/样式/注释与全部标签，保留标题层级与块级换行。
//!
//! 不引入解析器依赖：只做「把网页正文交给模型」这一件事，不追求 HTML 语义完备。
//! 无法识别的结构（未闭合标签、属性里的 `>`）按字面文本处理，不报错。

/// 整体丢弃内容的元素。
fn is_dropped(name: &str) -> bool {
    matches!(
        name,
        "script" | "style" | "noscript" | "template" | "head" | "svg" | "canvas"
    )
}

/// 产生块级断行的元素；其余标签只被剥掉。
fn is_block(name: &str) -> bool {
    matches!(
        name,
        "p" | "div"
            | "section"
            | "article"
            | "header"
            | "footer"
            | "nav"
            | "aside"
            | "main"
            | "ul"
            | "ol"
            | "li"
            | "dl"
            | "dt"
            | "dd"
            | "table"
            | "tr"
            | "td"
            | "th"
            | "thead"
            | "tbody"
            | "tfoot"
            | "pre"
            | "blockquote"
            | "figure"
            | "figcaption"
            | "br"
            | "hr"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
    )
}

/// 标题元素 → Markdown 前缀。
fn heading_prefix(name: &str) -> Option<&'static str> {
    match name {
        "h1" => Some("# "),
        "h2" => Some("## "),
        "h3" => Some("### "),
        "h4" => Some("#### "),
        "h5" => Some("##### "),
        "h6" => Some("###### "),
        _ => None,
    }
}

/// 收集到的正文片段（延迟合并，便于收拢空行）。
enum Piece {
    Text(String),
    Break,
    Heading(&'static str),
}

/// HTML → 纯文本（Markdown 风格的标题前缀 + 块级换行）。
pub fn to_text(html: &str) -> String {
    let mut pieces: Vec<Piece> = Vec::new();
    let mut buf = String::new();
    let mut skip_depth = 0usize;
    let mut chars = html.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        if c != '<' {
            if skip_depth == 0 {
                buf.push(c);
            }
            continue;
        }
        // 注释 <!-- ... -->：整段跳过。
        if html[i..].starts_with("<!--") {
            if let Some(end) = html[i + 4..].find("-->") {
                for _ in html[i..i + 7 + end].chars().skip(1) {
                    chars.next();
                }
            }
            continue;
        }
        let Some(close) = html[i..].find('>') else {
            // 没有闭合的 `<`：按字面文本处理。
            if skip_depth == 0 {
                buf.push(c);
            }
            continue;
        };
        let tag = &html[i..i + close + 1];
        for _ in tag.chars().skip(1) {
            chars.next();
        }
        let (name, closing) = tag_name(tag);
        if name.is_empty() {
            continue; // <!doctype>、<?xml?>、</> 等：整段丢弃
        }
        if is_dropped(&name) {
            if closing {
                skip_depth = skip_depth.saturating_sub(1);
            } else {
                if skip_depth == 0 {
                    flush(&mut buf, &mut pieces);
                }
                skip_depth += 1;
            }
            continue;
        }
        if skip_depth > 0 {
            continue; // 被丢弃元素内部的标签不产生结构
        }
        flush(&mut buf, &mut pieces);
        if let Some(prefix) = heading_prefix(&name) {
            if !closing {
                pieces.push(Piece::Heading(prefix));
            }
        } else if is_block(&name) {
            pieces.push(Piece::Break);
        }
    }
    if skip_depth == 0 {
        flush(&mut buf, &mut pieces);
    }
    render(pieces)
}

/// 提取 `<title>` 文本；没有或为空则 `None`。
pub fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let open = find_tag(&lower, "title")?;
    let content_start = lower[open..].find('>')? + open + 1;
    let rest = &lower[content_start..];
    let end = rest.find("</title>")?;
    // 下标只用于切分 ASCII 小写副本，正文一律回到原串取，避免大小写折叠改变字节。
    // 标题内层标记（如 <em>）先剥除再折叠空白（规格：title_is_extracted_with_inner_markup_removed）。
    let text = collapse_ws(&to_text(&html[content_start..content_start + end]));
    (!text.is_empty()).then_some(text)
}

/// 在 `haystack`（ASCII 小写副本）中找开标签 `<name` 的 `<` 下标。
fn find_tag(haystack: &str, name: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = haystack[from..].find('<') {
        let open = from + rel;
        let word_end = open + 1 + name.len();
        let hit = word_end <= haystack.len()
            && haystack[open + 1..word_end] == *name
            && !matches!(haystack[word_end..].chars().next(), Some(c) if c.is_ascii_alphanumeric());
        if hit {
            return Some(open);
        }
        from = open + 1;
    }
    None
}

/// 标签名（ASCII 小写）与是否闭合标签。
///
/// 属性值里出现 `>` 会被提前截断，属极简实现的已知限制。
fn tag_name(tag: &str) -> (String, bool) {
    let inner = tag.trim_start_matches('<').trim_end_matches('>');
    let closing = inner.starts_with('/');
    let inner = inner.trim_start_matches('/').trim_start();
    let name: String = inner
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    (name, closing)
}

fn flush(buf: &mut String, pieces: &mut Vec<Piece>) {
    let text = decode_entities(buf);
    let text = collapse_ws(&text);
    if !text.is_empty() {
        pieces.push(Piece::Text(text));
    }
    buf.clear();
}

/// 折叠空白（含换行）为单个空格，并去掉首尾空白。
fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending = false;
    for c in s.chars() {
        if c.is_whitespace() {
            pending = !out.is_empty();
            continue;
        }
        if pending {
            out.push(' ');
            pending = false;
        }
        out.push(c);
    }
    out
}

/// 常见实体的最小解码：只处理命名实体与数字实体（十进制/十六进制）。
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos + 1..];
        let Some(end) = tail.find(';') else {
            out.push('&');
            rest = tail;
            continue;
        };
        // 实体名最长也就 8 字节，超出就不是实体，按字面保留。
        if end > 8 {
            out.push('&');
            rest = tail;
            continue;
        }
        let name = &tail[..end];
        let decoded = match name {
            "amp" => Some("&".to_string()),
            "lt" => Some("<".to_string()),
            "gt" => Some(">".to_string()),
            "quot" => Some("\"".to_string()),
            "apos" => Some("'".to_string()),
            "nbsp" => Some(" ".to_string()),
            _ if name.starts_with("#x") || name.starts_with("#X") => {
                u32::from_str_radix(&name[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
                    .map(|c| c.to_string())
            }
            _ if name.starts_with('#') => name[1..]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .map(|c| c.to_string()),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push_str(&c.to_string());
                rest = &tail[end + 1..];
            }
            None => {
                out.push('&');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// 片段 → 文本：块级换行，空片段自然消失。
fn render(pieces: Vec<Piece>) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prefix: Option<&'static str> = None;
    for piece in pieces {
        match piece {
            Piece::Text(t) => {
                if !cur.is_empty() {
                    cur.push(' ');
                }
                if let Some(p) = prefix.take() {
                    cur.push_str(p);
                }
                cur.push_str(&t);
            }
            Piece::Heading(p) => {
                close(&mut lines, &mut cur);
                prefix = Some(p);
            }
            Piece::Break => close(&mut lines, &mut cur),
        }
    }
    close(&mut lines, &mut cur);
    lines.join("\n")
}

fn close(lines: &mut Vec<String>, cur: &mut String) {
    if !cur.is_empty() {
        lines.push(std::mem::take(cur));
    }
}
