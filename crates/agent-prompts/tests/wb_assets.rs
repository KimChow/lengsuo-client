//! 参考端 资产加载测试：每项资产可编译期加载、非空、带来源标注、关键章节存在；
//! 目录表 ASSETS 与 asset() 查询一致，标识唯一，正文行数不超红线。

mod common;

use agent_prompts::{asset, PromptAsset, ASSETS};
use common::has_all;

/// 单项资产正文行数上限（任务红线：每个资产文件不超过 400 行）。
const MAX_ASSET_LINES: usize = 400;

/// 每项资产的必备关键章节（与 assets/*.md 的 `## ` 标题一一对应）。
fn required_sections(asset: &PromptAsset) -> &'static [&'static str] {
    match asset.name {
        "system-prompt-quick" => &[
            "## 1. quick 模板全文",
            "## 2. quick 的双保险机制",
            "## 3. quick 模式片段清单",
            "You are 参考客户端 in Quick Answer mode.",
        ],
        "prompt-architecture" => &[
            "## 1. 分层组装模型",
            "## 3. 模板矩阵",
            "## 8. 七种语言风格",
            "## 9. 变量表",
        ],
        "safety-rules" => &[
            "## 1. content_policy 七条",
            "## 2. personal_files_safety 个人目录八条",
            "## 3. windows_command_safety 五条",
            "## 5. tool_use 五规则",
        ],
        "tool-catalog" => &[
            "## 1. 模式矩阵与工具面",
            "## 3. 30 个工具全集：名称与用途",
            "## 4. 工具宇宙 78 项",
            "## 5. 内置 MCP 服务器全表",
        ],
        "tool-descriptions" => &[
            "## 1. Bash 工具 Zod schema",
            "## 2. Agent / TaskOutput 描述原文",
            "## 4. CLI 五模式 appendInstructions 全文",
        ],
        "agent-loop-permissions" => &[
            "## 1. Agent Loop：两版并存",
            "## 2. 8-Phase 权限链",
            "## 3. plan 门禁与工具授权状态机",
        ],
        other => panic!("未知资产标识：{other}"),
    }
}

#[test]
fn all_assets_load_nonempty() {
    assert_eq!(ASSETS.len(), 6, "资产目录应为 6 项");
    for a in ASSETS {
        assert!(!a.content.trim().is_empty(), "{} 正文为空", a.name);
        assert!(!a.title.trim().is_empty(), "{} 标题为空", a.name);
        assert!(
            a.content.starts_with("# 参考端 资产 · "),
            "{} 正文缺少资产标题头",
            a.name
        );
        let lines = a.content.lines().count();
        assert!(
            lines <= MAX_ASSET_LINES,
            "{} 正文 {lines} 行，超过 {MAX_ASSET_LINES} 行上限",
            a.name
        );
    }
}

#[test]
fn every_asset_carries_source_annotation() {
    // 来源标注必须指向 参考端 pc-devguide 册名（《》包裹的书名）以保可追溯。
    for a in ASSETS {
        assert!(
            a.source.starts_with("参考端 pc-devguide ") && a.source.contains('《'),
            "{} 来源标注缺少 参考端 pc-devguide 册名：{}",
            a.name,
            a.source
        );
        assert!(
            a.content.contains("> 来源：参考端 pc-devguide"),
            "{} 正文头部缺少来源行",
            a.name
        );
    }
}

#[test]
fn asset_lookup_matches_catalog() {
    for a in &ASSETS {
        let found = asset(a.name).unwrap_or_else(|| panic!("asset() 查不到 {}", a.name));
        assert_eq!(found, a, "asset() 与目录表不一致：{}", a.name);
    }
    assert!(asset("no-such-asset").is_none());
}

#[test]
fn asset_names_are_unique() {
    for (i, a) in ASSETS.iter().enumerate() {
        for b in &ASSETS[i + 1..] {
            assert_ne!(a.name, b.name, "资产标识重复：{}", a.name);
        }
    }
}

#[test]
fn each_asset_contains_required_sections() {
    for a in &ASSETS {
        has_all(a.content, required_sections(a));
    }
}

#[test]
fn loop_and_permissions_asset_records_both_step_counts() {
    // 9 步 agent loop 与 8-Phase 权限链是本卡的核心交付语义：
    // 两版步数并存（fragment 8 步 / 模板内联 9 步）与 8-Phase 均须在场。
    let a = asset("agent-loop-permissions").expect("资产存在");
    has_all(
        a.content,
        &["fragment 版 8 步", "模板内联版 9 步", "8-Phase 权限链"],
    );
}
