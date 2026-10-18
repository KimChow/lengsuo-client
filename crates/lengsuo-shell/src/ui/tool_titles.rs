//! 工具名 → 人话标题映射（纯逻辑，不依赖 gpui）。
//!
//! 产品约束（对照 参照平台 D4 主界面的工具卡片）：
//! - **工具英文名对用户不可见**：卡片标题一律中文；未知工具也绝不回显原始英文名，
//!   统一落进兜底文案。英文名仍是审批/RPC 的协议字段，只是不显示。
//! - **命令正文不进标题**：`exec.run` 只显示「执行命令」，命令行可能带凭据或极长，
//!   展开卡片时按引用（`args_ref`/`result_ref`）呈现。
//! - 参数缺失时降级为不带宾语的短标题，而不是渲染出 `{path}` 这类占位符残留。

use serde_json::Value;

/// 路径类参数的候选键（按优先级）。
const PATH_KEYS: [&str; 5] = ["path", "file_path", "file", "target", "filepath"];
/// 检索词的候选键。
const PATTERN_KEYS: [&str; 4] = ["pattern", "query", "keyword", "text"];
/// URL 的候选键。
const URL_KEYS: [&str; 2] = ["url", "uri"];

/// 从参数对象里按候选键取第一个非空字符串。
fn pick<'a>(args: Option<&'a Value>, keys: &[&str]) -> Option<&'a str> {
    let obj = args?.as_object()?;
    keys.iter().find_map(|k| {
        obj.get(*k)
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
    })
}

/// 单条工具标题模板：`needs_arg` 表示标题需要宾语；宾语缺失时用 [`Self::fallback`]。
struct Template {
    /// 工具全名（协议字段，仅用于匹配，不参与渲染）。
    name: &'static str,
    /// 有宾语时的中文模板，`{arg}` 为占位。
    with_arg: &'static str,
    /// 无宾语时的兜底文案。
    fallback: &'static str,
    /// 宾语取哪一类参数。
    kind: ArgKind,
}

/// 宾语类别。
#[derive(Clone, Copy, PartialEq, Eq)]
enum ArgKind {
    Path,
    Pattern,
    Url,
    /// 不需要宾语（标题恒定）。
    None,
}

/// 已知工具表。新增工具在此追加，禁止在视图里散落字符串字面量。
const TEMPLATES: &[Template] = &[
    Template {
        name: "fs.read",
        with_arg: "读取 {arg}",
        fallback: "读取文件",
        kind: ArgKind::Path,
    },
    Template {
        name: "fs.write",
        with_arg: "写入 {arg}",
        fallback: "写入文件",
        kind: ArgKind::Path,
    },
    Template {
        name: "fs.edit",
        with_arg: "编辑 {arg}",
        fallback: "编辑文件",
        kind: ArgKind::Path,
    },
    Template {
        name: "fs.search",
        with_arg: "搜索 \"{arg}\"",
        fallback: "搜索内容",
        kind: ArgKind::Pattern,
    },
    Template {
        name: "fs.list",
        with_arg: "列出目录 {arg}",
        fallback: "列出目录",
        kind: ArgKind::Path,
    },
    Template {
        name: "exec.run",
        with_arg: "执行命令",
        fallback: "执行命令",
        kind: ArgKind::None,
    },
    Template {
        name: "web.fetch",
        with_arg: "抓取网页 {arg}",
        fallback: "抓取网页",
        kind: ArgKind::Url,
    },
    Template {
        name: "browser.open",
        with_arg: "打开浏览器",
        fallback: "打开浏览器",
        kind: ArgKind::None,
    },
    Template {
        name: "memory.read",
        with_arg: "读取记忆",
        fallback: "读取记忆",
        kind: ArgKind::None,
    },
    Template {
        name: "memory.update",
        with_arg: "更新记忆",
        fallback: "更新记忆",
        kind: ArgKind::None,
    },
];

/// 未知工具的兜底标题：不含任何英文原名。
const UNKNOWN_TITLE: &str = "执行一项操作";

/// 按工具名查模板。
fn lookup(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.name == name)
}

/// 生成人话标题。`args` 为工具参数对象（可能缺失，例如只带了引用 `args_ref`）。
pub fn tool_title(name: &str, args: Option<&Value>) -> String {
    let Some(t) = lookup(name) else {
        return UNKNOWN_TITLE.to_string();
    };
    let arg = match t.kind {
        ArgKind::Path => pick(args, &PATH_KEYS),
        ArgKind::Pattern => pick(args, &PATTERN_KEYS),
        ArgKind::Url => pick(args, &URL_KEYS),
        ArgKind::None => None,
    };
    match arg {
        Some(v) => t.with_arg.replace("{arg}", v),
        None => t.fallback.to_string(),
    }
}

/// 只知工具名（无参数对象）时的标题。视图状态里的 `ToolRef` 常只有引用，走这条路径。
#[must_use]
pub fn tool_title_of(name: &str) -> String {
    tool_title(name, None)
}

/// 是否为已登记的工具名（用于测试与「英文名不得外显」的断言）。
#[must_use]
// 阶段二渲染层消费（工具卡片降级标题）。
#[allow(dead_code)]
pub fn is_known_tool(name: &str) -> bool {
    lookup(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fs_read_title_uses_path() {
        let args = json!({ "path": "src/main.rs" });
        assert_eq!(tool_title("fs.read", Some(&args)), "读取 src/main.rs");
        // 别名字段同样识别。
        let args = json!({ "file_path": "a/b.txt" });
        assert_eq!(tool_title("fs.read", Some(&args)), "读取 a/b.txt");
    }

    #[test]
    fn exec_run_title_never_leaks_command() {
        let args = json!({ "command": "curl -H 'token: sekret' https://example.com" });
        let title = tool_title("exec.run", Some(&args));
        assert_eq!(title, "执行命令");
        assert!(!title.contains("sekret"), "标题不得含命令正文");
        assert!(!title.contains("exec"), "标题不得含工具英文名");
    }

    #[test]
    fn fs_search_title_quotes_pattern() {
        let args = json!({ "pattern": "GatewayClient" });
        assert_eq!(
            tool_title("fs.search", Some(&args)),
            "搜索 \"GatewayClient\""
        );
    }

    #[test]
    fn missing_argument_falls_back_without_placeholder() {
        let t = tool_title("fs.read", None);
        assert_eq!(t, "读取文件");
        assert!(!t.contains('{'), "不得残留占位符：{t}");
        // 参数存在但目标键缺失/空白，同样降级。
        let args = json!({ "cmd": "ls" });
        assert_eq!(tool_title("fs.read", Some(&args)), "读取文件");
        let args = json!({ "path": "   " });
        assert_eq!(tool_title("fs.read", Some(&args)), "读取文件");
    }

    #[test]
    fn unknown_tool_gets_chinese_fallback() {
        assert_eq!(tool_title("xyz.wipe", None), UNKNOWN_TITLE);
        let args = json!({ "path": "secret.key" });
        let title = tool_title("xyz.wipe", Some(&args));
        assert_eq!(title, UNKNOWN_TITLE);
        assert!(
            !title.contains("xyz"),
            "未知工具英文名不得出现在标题里：{title}"
        );
    }

    #[test]
    fn no_title_contains_the_english_tool_name() {
        for t in TEMPLATES {
            let args = json!({
                "path": "p/q.rs",
                "pattern": "needle",
                "url": "https://example.com",
                "command": "ls -la"
            });
            let with = tool_title(t.name, Some(&args));
            let without = tool_title_of(t.name);
            for title in [with, without] {
                let lower = title.to_lowercase();
                assert!(!lower.contains(t.name), "标题外显了英文名：{title}");
                // 名称的两段（域/动作）也不能单独漏出来。
                if let Some((domain, action)) = t.name.split_once('.') {
                    assert!(
                        !lower.contains(&format!("{domain}.")) && !lower.ends_with(action),
                        "标题泄漏了工具名片段：{title}"
                    );
                }
            }
        }
    }

    #[test]
    fn known_table_is_self_consistent() {
        for t in TEMPLATES {
            assert!(t.with_arg.contains("{arg}") || t.kind == ArgKind::None,);
            assert!(!t.fallback.is_empty());
            assert!(!t.fallback.contains('{'));
            assert!(is_known_tool(t.name));
        }
        assert!(!is_known_tool("fs.readx"));
    }
}
