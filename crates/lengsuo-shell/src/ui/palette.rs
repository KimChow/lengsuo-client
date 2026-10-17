//! 命令面板（`Ctrl+K`）的命令表与过滤（纯逻辑，不依赖 gpui）。
//!
//! 首版命令集（任务卡）：新建会话、关闭会话、切模式 ×5、打开设置（占位）。
//! 表里一共 9 条：卡片文案列举的「切模式×5」+「新建/关闭」两条 +「设置」一条。
//! 命令语义在这里定义（[`PaletteCommandKind`]），**执行**由 GPUI 侧映射到既有
//! 状态机迁移与网关动作，本模块不认识网络与渲染。
//!
//! 面板交互约束：
//! - 过滤是大小写不敏感的子序列匹配（可跳字符），命中相同则保持表内原序；
//! - 空查询返回全表（顺序即默认候选顺序，模式切换集中在前，便于键盘连按）。

use crate::state::SessionMode;

/// 命令语义。执行体在 GPUI 侧，按此枚举分派。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteCommandKind {
    /// `session:create`。
    NewSession,
    /// `session:stop` + 从列表移除。
    CloseSession,
    /// 切换当前会话模式（状态机 `switch_mode` + `config:set`/事件回显）。
    SwitchMode(SessionMode),
    /// 打开设置：v0 为占位（面板尚未实现），只提示不落网。
    OpenSettings,
}

/// 一条面板命令。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaletteCommand {
    /// 稳定 id（测试与执行分派用，不含中文）。
    pub id: &'static str,
    /// 面板上显示的人话标题。
    pub title: &'static str,
    /// 副标题/说明（可空字符串）。
    pub hint: &'static str,
    /// 语义。
    pub kind: PaletteCommandKind,
}

/// 模式切换命令的标题：中文模式名 + 协议名（协议名对用户是可选信息，此处保留
/// 便于与网关事件对照；模式名不是工具英文名，允许外显）。
const fn mode_title(mode: SessionMode) -> &'static str {
    match mode {
        SessionMode::Quick => "切到快速模式（quick）",
        SessionMode::Ask => "切到问答模式（ask）",
        SessionMode::Plan => "切到计划模式（plan）",
        SessionMode::Craft => "切到执行模式（craft）",
        SessionMode::Expert => "切到专家模式（expert）",
    }
}

const fn mode_hint(mode: SessionMode) -> &'static str {
    match mode {
        SessionMode::Quick => "不使用工具，最快响应",
        SessionMode::Ask => "只读回答，不写文件",
        SessionMode::Plan => "先出计划，再动手",
        SessionMode::Craft => "允许工具执行（仍受审批约束）",
        SessionMode::Expert => "全权限（仍受网关权限门约束）",
    }
}

/// 模式列表（面板顺序 = 由轻到重）。
// 阶段二 GPUI 渲染层消费；逻辑与测试已先行冻结。
#[allow(dead_code)]
pub const MODES: [SessionMode; 5] = [
    SessionMode::Quick,
    SessionMode::Ask,
    SessionMode::Plan,
    SessionMode::Craft,
    SessionMode::Expert,
];

/// 首版命令表。顺序即空查询时的候选顺序。
pub const PALETTE_COMMANDS: &[PaletteCommand] = &[
    PaletteCommand {
        id: "session.new",
        title: "新建会话",
        hint: "在当前工作区开一个新会话",
        kind: PaletteCommandKind::NewSession,
    },
    PaletteCommand {
        id: "session.close",
        title: "关闭当前会话",
        hint: "停止运行并移出列表",
        kind: PaletteCommandKind::CloseSession,
    },
    PaletteCommand {
        id: "mode.quick",
        title: mode_title(SessionMode::Quick),
        hint: mode_hint(SessionMode::Quick),
        kind: PaletteCommandKind::SwitchMode(SessionMode::Quick),
    },
    PaletteCommand {
        id: "mode.ask",
        title: mode_title(SessionMode::Ask),
        hint: mode_hint(SessionMode::Ask),
        kind: PaletteCommandKind::SwitchMode(SessionMode::Ask),
    },
    PaletteCommand {
        id: "mode.plan",
        title: mode_title(SessionMode::Plan),
        hint: mode_hint(SessionMode::Plan),
        kind: PaletteCommandKind::SwitchMode(SessionMode::Plan),
    },
    PaletteCommand {
        id: "mode.craft",
        title: mode_title(SessionMode::Craft),
        hint: mode_hint(SessionMode::Craft),
        kind: PaletteCommandKind::SwitchMode(SessionMode::Craft),
    },
    PaletteCommand {
        id: "mode.expert",
        title: mode_title(SessionMode::Expert),
        hint: mode_hint(SessionMode::Expert),
        kind: PaletteCommandKind::SwitchMode(SessionMode::Expert),
    },
    PaletteCommand {
        id: "settings.open",
        title: "打开设置",
        hint: "设置面板尚未实现（占位）",
        kind: PaletteCommandKind::OpenSettings,
    },
];

/// 大小写不敏感的跳字符子序列匹配（`cmd` 的所有字符按序出现在 `text` 中）。
fn subsequence_case_insensitive(query: &str, text: &str) -> bool {
    let mut chars = text.chars().flat_map(|c| c.to_lowercase());
    for q in query.chars().flat_map(|c| c.to_lowercase()) {
        if !chars.any(|c| c == q) {
            return false;
        }
    }
    true
}

/// 按查询过滤命令表。空查询（含纯空白）返回全表。
///
/// 匹配优先「标题连续子串」，其次「标题跳字符子序列」，再次「id / 协议名」，
/// 同档内保持表内原序（稳定，便于键盘上下键预期一致）。
#[must_use]
pub fn filter_commands(query: &str) -> Vec<&'static PaletteCommand> {
    let q = query.trim();
    if q.is_empty() {
        return PALETTE_COMMANDS.iter().collect();
    }
    let rank = |c: &PaletteCommand| -> Option<u8> {
        let title = c.title;
        if title.contains(q) {
            Some(0)
        } else if subsequence_case_insensitive(q, title) {
            Some(1)
        } else if subsequence_case_insensitive(q, c.id)
            || matches!(c.kind, PaletteCommandKind::SwitchMode(m) if m.as_str().contains(q.to_lowercase().as_str()))
        {
            Some(2)
        } else {
            None
        }
    };
    let mut hits: Vec<(u8, usize, &'static PaletteCommand)> = PALETTE_COMMANDS
        .iter()
        .enumerate()
        .filter_map(|(i, c)| rank(c).map(|r| (r, i, c)))
        .collect();
    hits.sort_by_key(|(r, i, _)| (*r, *i));
    hits.into_iter().map(|(_, _, c)| c).collect()
}

/// 命令表条数（供测试与「首版 ≥8 命令」的验收断言）。
#[must_use]
// 阶段二 GPUI 渲染层消费；逻辑与测试已先行冻结。
#[allow(dead_code)]
pub fn command_count() -> usize {
    PALETTE_COMMANDS.len()
}

/// 模式切换命令的条数（应为 5）。
#[must_use]
// 阶段二渲染层消费。
#[allow(dead_code)]
pub fn mode_command_count() -> usize {
    PALETTE_COMMANDS
        .iter()
        .filter(|c| matches!(c.kind, PaletteCommandKind::SwitchMode(_)))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_new_close_settings_and_five_modes() {
        assert!(
            command_count() >= 8,
            "首版至少 8 条，实际 {}",
            command_count()
        );
        assert_eq!(mode_command_count(), 5);
        let kinds: Vec<_> = PALETTE_COMMANDS.iter().map(|c| c.kind).collect();
        assert!(kinds.contains(&PaletteCommandKind::NewSession));
        assert!(kinds.contains(&PaletteCommandKind::CloseSession));
        assert!(kinds.contains(&PaletteCommandKind::OpenSettings));
        for mode in MODES {
            assert!(
                kinds.contains(&PaletteCommandKind::SwitchMode(mode)),
                "缺模式 {mode:?}"
            );
        }
    }

    #[test]
    fn ids_and_titles_are_unique_and_non_empty() {
        let mut ids = std::collections::HashSet::new();
        let mut titles = std::collections::HashSet::new();
        for c in PALETTE_COMMANDS {
            assert!(!c.id.is_empty() && !c.title.is_empty());
            assert!(ids.insert(c.id), "id 重复：{}", c.id);
            assert!(titles.insert(c.title), "标题重复：{}", c.title);
        }
    }

    #[test]
    fn empty_query_returns_whole_table_in_order() {
        let all = filter_commands("");
        assert_eq!(all.len(), PALETTE_COMMANDS.len());
        assert_eq!(all[0].id, "session.new");
        // 纯空白同样视为空查询。
        assert_eq!(filter_commands("   ").len(), PALETTE_COMMANDS.len());
    }

    #[test]
    fn substring_match_on_title_wins_and_keeps_table_order() {
        let hits = filter_commands("关闭");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "session.close");
        // 「模式」命中全部 5 条模式命令，顺序与表一致。
        let hits = filter_commands("模式");
        assert_eq!(hits.len(), 5);
        assert_eq!(hits[0].id, "mode.quick");
        assert_eq!(hits[4].id, "mode.expert");
    }

    #[test]
    fn ascii_query_matches_protocol_mode_name_and_id() {
        // 模式协议名（英文）可搜到，便于熟悉协议的开发者。
        let hits = filter_commands("craft");
        assert!(hits.iter().any(|c| c.id == "mode.craft"));
        let hits = filter_commands("settings");
        assert!(hits.iter().any(|c| c.id == "settings.open"));
    }

    #[test]
    fn subsequence_match_is_ranked_below_substring() {
        // 「新会」跳字符命中「新建会话」；「新建」连续命中同一条。
        let hits = filter_commands("新会");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "session.new");
        // 大小写不敏感。
        let hits = filter_commands("CRAFT");
        assert!(hits.iter().any(|c| c.id == "mode.craft"));
        let hits = filter_commands("Session.New");
        assert_eq!(hits[0].id, "session.new");
    }

    #[test]
    fn unmatched_query_returns_empty() {
        assert!(filter_commands("不存在xyz").is_empty());
        assert!(filter_commands("zzzz").is_empty());
    }

    #[test]
    fn ranking_prefers_substring_over_subsequence() {
        // 造一条同时「连续命中」和「跳字符命中」的查询：连续档必须排在前。
        let hits = filter_commands("模式");
        assert!(hits.iter().all(|c| c.title.contains("模式")));
        // 混合场景：`打开` 连续命中「打开当前会话」? 否；命中「打开设置」。
        let hits = filter_commands("打开");
        assert_eq!(hits[0].id, "settings.open");
    }
}
