//! 资源级门（权限精简设计 §3）：工具调用 → `AccessRequest[]` → execpolicy 两阶段汇总。
//!
//! 层序（设计 §7：用层序排列消化 execpolicy「首个命中」与 ref-session findLast 的差异）：
//! `[saved…, configured(项目/会话)… , 内置安全基线]`，前层覆盖后层——首个产生命中的层生效。
//!
//! 两阶段（照 ref-session：deny 先查、allow 后汇总）：
//! - phase1 `configured_deny`：只看配置层 + 内置基线（saved 不参与），
//!   任一请求的首个命中为 deny ⇒ 整体 deny（`.ssh/**` 即使用户 saved allow 也拦）。
//! - phase2 `all_allowed`：在完整层序上判，全部请求的首个命中都是 allow ⇒ Allow。
//!
//! 与工具级门底案的关系（对外契约，见卡报告）：phase1 可**收紧**（覆盖 auto 放行），
//! phase2 全 allow 可**放宽**（把工具级 Ask 升为 Allow）；其余情形维持底案，不升级、不退化——
//! 这样既守住「工具级门短路顺序不变」的验收契约，又让规则层双向生效。

use serde_json::Value;

use agent_execpolicy::{assess, AccessKind, AccessRequest, Assessment, Decision, Policy};

use crate::tool::ToolKind;

/// 内置安全基线：`.ssh/**`/`.gnupg/**` deny、包缓存 allow（execpolicy Default）。
fn baseline() -> &'static Policy {
    use std::sync::OnceLock;
    static BASELINE: OnceLock<Policy> = OnceLock::new();
    BASELINE.get_or_init(Policy::security_baseline)
}

/// 某请求在层序上的首个命中（无命中 = None ⇒ 语义上按 fail-closed Ask 处理）。
fn first_match<'p>(
    layers: impl Iterator<Item = &'p Policy>,
    request: &AccessRequest,
) -> Option<Assessment> {
    layers
        .map(|policy| assess(policy, request))
        .find(|assessment| assessment.matched_rule.is_some())
}

/// 一次工具调用派生的访问请求（kind 决定取哪些参数字段；映射表见卡报告）。
pub fn access_requests(kind: ToolKind, args: &Value) -> Vec<AccessRequest> {
    match kind {
        ToolKind::Read | ToolKind::Write => string_field_values(args, PATH_FIELDS)
            .into_iter()
            .map(|target| AccessRequest {
                kind: AccessKind::File,
                target,
            })
            .collect(),
        ToolKind::Exec => {
            let mut reqs = Vec::new();
            for command in string_field_values(args, COMMAND_FIELDS) {
                reqs.push(AccessRequest {
                    kind: AccessKind::Process,
                    target: command,
                });
            }
            // 命令串中的 URL 一并派生 Network 请求（curl https://… 之类）。
            for text in super::string_values(args) {
                reqs.extend(network_requests_for_text(&text));
            }
            reqs
        }
        ToolKind::Network => super::string_values(args)
            .iter()
            .flat_map(|text| network_requests_for_text(text))
            .collect(),
        // Browser 类暂无资源语义（环境 id 不是路径/域名），维持工具级判定。
        ToolKind::Browser => Vec::new(),
    }
}

/// 文件类参数里承担路径语义的键名（对照 tool.rs 与测试/运行时的实际参数面）。
const PATH_FIELDS: &[&str] = &["path", "paths", "file", "files", "dir", "src", "dest"];
/// 命令类参数字段。
const COMMAND_FIELDS: &[&str] = &["command", "cmd", "script"];

/// 取指定键（或其字符串数组值）的全部字符串。
fn string_field_values(args: &Value, fields: &[&str]) -> Vec<String> {
    let Some(map) = args.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for field in fields {
        match map.get(*field) {
            Some(Value::String(text)) => out.push(text.clone()),
            Some(Value::Array(items)) => {
                out.extend(items.iter().filter_map(Value::as_str).map(String::from));
            }
            _ => {}
        }
    }
    out
}

/// 从一段文本里提取 URL 主机名，派生 Network 请求（`scheme://host[:port]/path`）。
fn network_requests_for_text(text: &str) -> Vec<AccessRequest> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(idx) = rest.find("://") {
        let after = &rest[idx + 3..];
        let authority = after
            .split(|c: char| c.is_whitespace() || "?#/<>'\"".contains(c))
            .next()
            .unwrap_or("");
        // 可能带 user:pass@ 前缀取 @ 后，再去端口；无点号裸名（localhost）不作域名。
        let host = authority
            .rsplit('@')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if host.contains('.') {
            out.push(AccessRequest {
                kind: AccessKind::Network,
                target: host,
            });
        }
        rest = after;
    }
    out
}

/// phase1：配置层（+ 内置基线）里任一请求的首个命中为 deny ⇒ deny 理由（不含目标值）。
pub fn configured_deny(configured: &[Policy], requests: &[AccessRequest]) -> Option<String> {
    requests.iter().find_map(|request| {
        let assessment = first_match(
            configured.iter().chain(std::iter::once(baseline())),
            request,
        )?;
        (assessment.decision == Decision::Deny).then(|| {
            // 理由只含规则模式（策略文件内容，非参数值）。
            format!(
                "策略 deny: {} 访问命中规则 {}",
                kind_label(request.kind),
                assessment
                    .matched_rule
                    .map_or_else(|| "?".to_string(), |rule| rule.pattern)
            )
        })
    })
}

/// phase2：saved + 配置层 + 基线的完整层序上，全部请求的首个命中均为 allow ⇒ true。
pub fn all_allowed(saved: &[Policy], configured: &[Policy], requests: &[AccessRequest]) -> bool {
    if requests.is_empty() {
        return false; // 无资源请求：维持工具级门结论，不主动放宽
    }
    let layers = || {
        saved
            .iter()
            .chain(configured.iter())
            .chain(std::iter::once(baseline()))
    };
    requests.iter().all(|request| {
        first_match(layers(), request)
            .is_some_and(|assessment| assessment.decision == Decision::Allow)
    })
}

fn kind_label(kind: AccessKind) -> &'static str {
    match kind {
        AccessKind::File => "文件",
        AccessKind::Process => "进程",
        AccessKind::Network => "网络",
    }
}
